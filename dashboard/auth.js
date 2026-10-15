"use strict";

const { randomBytes, createHash, timingSafeEqual } = require("node:crypto");
const SESSION_COOKIE = "__Host-hotl-session";
const FLOW_COOKIE = "__Host-hotl-flow";
const MUTATIONS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const randomToken = () => randomBytes(32).toString("base64url");
const sha256 = value => createHash("sha256").update(value).digest("base64url");
const equal = (left, right) => typeof left === "string" && typeof right === "string" &&
  Buffer.byteLength(left) === Buffer.byteLength(right) && timingSafeEqual(Buffer.from(left), Buffer.from(right));

class AuthError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}

function cookies(req) {
  const result = {};
  for (const pair of String(req.get("cookie") || "").split(";")) {
    const at = pair.indexOf("=");
    if (at > 0) result[pair.slice(0, at).trim()] = pair.slice(at + 1).trim();
  }
  return result;
}
function setCookie(res, name, value, seconds) {
  res.append("Set-Cookie", `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${seconds}`);
}
function groups(payload, claim) {
  const value = payload[claim];
  return Array.isArray(value) ? value.filter(item => typeof item === "string") : [];
}

function createDynamoSessionStore({ client, tableName, commands }) {
  if (!tableName) return null;
  const { GetCommand, PutCommand, DeleteCommand } = commands;
  return {
    async get(session_id) {
      return (await client.send(new GetCommand({ TableName: tableName, Key: { session_id }, ConsistentRead: true }))).Item || null;
    },
    async put(record) {
      await client.send(new PutCommand({ TableName: tableName, Item: record, ConditionExpression: "attribute_not_exists(session_id)" }));
    },
    async consume(session_id, type, now) {
      try {
        return (await client.send(new DeleteCommand({
          TableName: tableName, Key: { session_id }, ReturnValues: "ALL_OLD",
          ConditionExpression: "#type = :type AND expires_at > :now",
          ExpressionAttributeNames: { "#type": "type" }, ExpressionAttributeValues: { ":type": type, ":now": now },
        }))).Attributes || null;
      } catch (error) {
        if (error.name === "ConditionalCheckFailedException") return null;
        throw error;
      }
    },
    async delete(session_id) { await client.send(new DeleteCommand({ TableName: tableName, Key: { session_id } })); },
  };
}

function createDashboardAuth({ env = process.env, store, fetchImpl = fetch, verifier, jwtKeySet, now = () => Math.floor(Date.now() / 1000) } = {}) {
  let config = null;
  try {
    const origin = new URL(env.PUBLIC_ORIGIN);
    const issuer = new URL(env.OIDC_ISSUER);
    const redirect = new URL(env.OIDC_REDIRECT_URI);
    if (origin.protocol !== "https:" || origin.origin !== env.PUBLIC_ORIGIN || issuer.protocol !== "https:" ||
        issuer.username || issuer.password || issuer.search || issuer.hash || redirect.origin !== origin.origin ||
        redirect.pathname !== "/auth/callback" || redirect.search || redirect.hash || !env.OIDC_CLIENT_ID || !store) throw new Error("Invalid configuration");
    config = {
      origin: origin.origin, issuer: issuer.toString().replace(/\/$/, ""), clientId: env.OIDC_CLIENT_ID,
      redirect: redirect.toString(), admins: new Set(String(env.ADMIN_GROUPS || "security-admins").split(",").map(value => value.trim()).filter(Boolean)),
      readers: new Set(String(env.READER_GROUPS || "security-admins,security-readers").split(",").map(value => value.trim()).filter(Boolean)),
      groupsClaim: env.OIDC_GROUPS_CLAIM || "cognito:groups",
    };
  } catch { /* Deliberately fail closed when production configuration is missing. */ }
  let metadataPromise;
  let jwks;
  async function metadata() {
    if (!config) throw new AuthError(503, "auth_not_configured");
    if (!metadataPromise) metadataPromise = (async () => {
      const response = await fetchImpl(`${config.issuer}/.well-known/openid-configuration`, { signal: AbortSignal.timeout(5000), redirect: "error" });
      if (!response.ok) throw new AuthError(503, "identity_provider_unavailable");
      const value = await response.json();
      if (value.issuer !== config.issuer) throw new AuthError(503, "identity_provider_invalid");
      for (const field of ["authorization_endpoint", "token_endpoint", "jwks_uri"]) {
        const url = new URL(value[field]);
        if (url.protocol !== "https:" || url.username || url.password || url.hash) throw new AuthError(503, "identity_provider_invalid");
      }
      return value;
    })().catch(error => { metadataPromise = null; throw error; });
    return metadataPromise;
  }
  async function verifyJwt(token, kind, nonce) {
    if (!config || typeof token !== "string" || token.length > 20000) throw new AuthError(401, "invalid_token");
    let payload;
    if (verifier) payload = await verifier(token, kind, config);
    else {
      const jose = await import("jose");
      const provider = await metadata();
      if (!jwks) jwks = jwtKeySet || jose.createRemoteJWKSet(new URL(provider.jwks_uri), { timeoutDuration: 5000, cooldownDuration: 30000, cacheMaxAge: 600000 });
      const options = { issuer: config.issuer, algorithms: ["RS256"], requiredClaims: ["sub", "exp", "iat"], clockTolerance: 5 };
      if (kind === "id") options.audience = config.clientId;
      try { payload = (await jose.jwtVerify(token, jwks, options)).payload; }
      catch (error) {
        if (error.code === "ERR_JWKS_TIMEOUT" || error instanceof TypeError) throw new AuthError(503, "identity_provider_unavailable");
        throw new AuthError(401, "invalid_token");
      }
    }
    if (!payload || typeof payload.sub !== "string" || !payload.sub || payload.sub.length > 256 || !Number.isInteger(payload.exp) || payload.exp <= now() ||
        !Number.isInteger(payload.iat) || payload.iat > now() + 5 ||
        payload.iss !== config.issuer || payload.token_use !== kind) throw new AuthError(401, "invalid_token");
    if (kind === "access" && payload.client_id !== config.clientId) throw new AuthError(401, "invalid_token");
    if (kind === "id" && ((!Array.isArray(payload.aud) && payload.aud !== config.clientId) ||
        (Array.isArray(payload.aud) && (!payload.aud.includes(config.clientId) || (payload.aud.length > 1 && payload.azp !== config.clientId))) || !equal(payload.nonce, nonce))) throw new AuthError(401, "invalid_token");
    return payload;
  }
  function principal(payload, csrfToken, expires) {
    const membership = groups(payload, config.groupsClaim);
    const admin = membership.some(group => config.admins.has(group));
    const reader = admin || membership.some(group => config.readers.has(group));
    if (!reader) throw new AuthError(403, "insufficient_role");
    return { sub: payload.sub, issuer: payload.iss, groups: membership, admin, csrfToken, expires_at: expires || payload.exp };
  }
  function originGuard(req) {
    const site = req.get("sec-fetch-site");
    if (site && site !== "same-origin") throw new AuthError(403, "cross_origin");
    if (req.get("origin") !== config.origin) throw new AuthError(403, "cross_origin");
    if (!req.is("application/json")) throw new AuthError(415, "json_required");
  }
  function failure(res, error) {
    const code = error instanceof AuthError ? error.code : "identity_provider_unavailable";
    const status = error instanceof AuthError ? error.status : 503;
    const messages = { auth_not_configured: "관리자 인증 설정이 필요합니다.", insufficient_role: "이 작업에 필요한 관리자 권한이 없습니다.",
      csrf_invalid: "요청 검증이 만료되었습니다. 화면을 새로고침하세요.", cross_origin: "같은 관리자 화면에서 보낸 요청만 허용합니다.",
      invalid_token: "관리자 로그인이 필요합니다.", json_required: "JSON 요청이 필요합니다.", actor_forbidden: "사용자 주체는 서버가 검증합니다." };
    res.status(status).json({ ok: false, code, message: messages[code] || "관리자 인증 서비스를 확인하지 못했습니다." });
  }
  function install(app) {
    app.get("/healthz", (req, res) => res.json({ ok: true }));
    app.get("/auth/logged-out", (req, res) => res.type("html").send('<!doctype html><html lang="ko"><meta charset="utf-8"><title>로그아웃</title><p>로그아웃했습니다. <a href="/auth/login">관리자 로그인</a></p></html>'));
    app.get("/auth/login", async (req, res) => {
      try {
        const provider = await metadata();
        const flowId = randomToken(), state = randomToken(), nonce = randomToken(), verifier = randomToken();
        await store.put({ session_id: `flow#${flowId}`, type: "flow", state, nonce, verifier, expires_at: now() + 300 });
        setCookie(res, FLOW_COOKIE, flowId, 300);
        const url = new URL(provider.authorization_endpoint);
        for (const [name, value] of Object.entries({ response_type: "code", client_id: config.clientId, redirect_uri: config.redirect,
          scope: "openid profile email", state, nonce, code_challenge: sha256(verifier), code_challenge_method: "S256", max_age: "900" })) url.searchParams.set(name, value);
        res.redirect(302, url.toString());
      } catch (error) { failure(res, error); }
    });
    app.get("/auth/callback", async (req, res) => {
      try {
        if (!config) throw new AuthError(503, "auth_not_configured");
        const flowId = cookies(req)[FLOW_COOKIE];
        if (!/^[A-Za-z0-9_-]{43}$/.test(flowId || "") || typeof req.query.state !== "string" || typeof req.query.code !== "string" || req.query.code.length > 4096) throw new AuthError(401, "invalid_token");
        const flow = await store.consume(`flow#${flowId}`, "flow", now());
        setCookie(res, FLOW_COOKIE, "", 0);
        if (!flow || !equal(flow.state, req.query.state)) throw new AuthError(401, "invalid_token");
        const provider = await metadata();
        const response = await fetchImpl(provider.token_endpoint, { method: "POST", redirect: "error", signal: AbortSignal.timeout(5000),
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ grant_type: "authorization_code", client_id: config.clientId, code: req.query.code, redirect_uri: config.redirect, code_verifier: flow.verifier }) });
        if (!response.ok) throw new AuthError(401, "invalid_token");
        const tokens = await response.json();
        const id = await verifyJwt(tokens.id_token, "id", flow.nonce);
        const access = await verifyJwt(tokens.access_token, "access");
        if (id.sub !== access.sub) throw new AuthError(401, "invalid_token");
        const expires = Math.min(id.exp, access.exp, now() + 900);
        const user = principal(access, randomToken(), expires);
        const sessionId = randomToken();
        // Only verified claims are stored. Never persist OAuth bearer/refresh tokens.
        await store.put({ session_id: `session#${sessionId}`, type: "session", user, expires_at: expires });
        setCookie(res, SESSION_COOKIE, sessionId, expires - now());
        res.redirect(303, "/");
      } catch (error) { failure(res, error); }
    });
    app.use(async (req, res, next) => {
      try {
        if (!config) throw new AuthError(503, "auth_not_configured");
        const authorization = req.get("authorization");
        if (authorization) {
          const match = /^Bearer ([A-Za-z0-9_.-]+)$/.exec(authorization);
          if (!match) throw new AuthError(401, "invalid_token");
          const payload = await verifyJwt(match[1], "access");
          req.auth = principal(payload, sha256(match[1]));
        } else {
          const sessionId = cookies(req)[SESSION_COOKIE];
          const record = /^[A-Za-z0-9_-]{43}$/.test(sessionId || "") ? await store.get(`session#${sessionId}`) : null;
          if (!record || record.type !== "session" || !Number.isInteger(record.expires_at) || record.expires_at <= now() || record.user?.issuer !== config.issuer ||
              typeof record.user?.sub !== "string" || !record.user.sub || !/^[A-Za-z0-9_-]{43}$/.test(record.user.csrfToken || "")) {
            if (req.method === "GET" && !req.path.startsWith("/api/")) return res.redirect(302, "/auth/login");
            throw new AuthError(401, "invalid_token");
          }
          req.auth = principal({ sub: record.user.sub, iss: record.user.issuer, exp: record.expires_at,
            [config.groupsClaim]: record.user.groups }, record.user.csrfToken, record.expires_at);
        }
        if (MUTATIONS.has(req.method)) {
          if (!req.auth.admin && req.path !== "/auth/logout") throw new AuthError(403, "insufficient_role");
          originGuard(req);
          if (!equal(req.get("x-csrf-token"), req.auth.csrfToken)) throw new AuthError(403, "csrf_invalid");
        }
        next();
      } catch (error) { failure(res, error); }
    });
    app.get("/api/session", (req, res) => res.json({ ok: true, subject: req.auth.sub, admin: req.auth.admin, csrf_token: req.auth.csrfToken, expires_at: req.auth.expires_at }));
    app.post("/auth/logout", async (req, res) => {
      try {
        const sessionId = cookies(req)[SESSION_COOKIE];
        if (sessionId) await store.delete(`session#${sessionId}`);
        setCookie(res, SESSION_COOKIE, "", 0);
        let redirect = "/auth/logged-out";
        try {
          const provider = await metadata();
          const logout = new URL("/logout", provider.authorization_endpoint);
          logout.searchParams.set("client_id", config.clientId);
          logout.searchParams.set("logout_uri", config.origin + "/auth/logged-out");
          redirect = logout.toString();
        } catch { /* Local session is already revoked even if the IdP is unavailable. */ }
        res.json({ ok: true, redirect });
      } catch (error) { failure(res, error); }
    });
  }
  function rejectClientActor(req, res, next) {
    if (MUTATIONS.has(req.method) && req.body && ["by", "user", "actor", "decided_by", "requested_by"].some(key => Object.hasOwn(req.body, key))) {
      return failure(res, new AuthError(400, "actor_forbidden"));
    }
    next();
  }
  return { install, rejectClientActor, configured: Boolean(config), verifyJwt, originGuard };
}

module.exports = { createDashboardAuth, createDynamoSessionStore, AuthError, SESSION_COOKIE, FLOW_COOKIE };
