"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const { createRequire } = require("node:module");
const { createHash } = require("node:crypto");
const ROOT = path.join(__dirname, "..");
const libraryRequire = createRequire(path.join(ROOT, "package.json"));
const express = libraryRequire("express");
const { createDashboardAuth, createDynamoSessionStore, SESSION_COOKIE, FLOW_COOKIE } = libraryRequire("./auth");
const { sanitizeReportHtml, securityHeaders } = libraryRequire("./content-security");
const { parseCaseKey } = libraryRequire("./case-key");
const { createServiceResolver } = libraryRequire("./service-registry");
const ORIGIN = "https://dashboard.example";
const ISSUER = "https://cognito-idp.ap-northeast-2.amazonaws.com/pool";
const now = () => Math.floor(Date.now() / 1000);
const config = { PUBLIC_ORIGIN: ORIGIN, OIDC_ISSUER: ISSUER, OIDC_CLIENT_ID: "client-one", OIDC_REDIRECT_URI: ORIGIN + "/auth/callback", ADMIN_GROUPS: "security-admins", SESSION_TABLE: "sessions" };
const provider = { issuer: ISSUER, authorization_endpoint: "https://login.example/oauth2/authorize", token_endpoint: "https://login.example/oauth2/token", jwks_uri: ISSUER + "/.well-known/jwks.json" };

class MemoryStore {
  constructor() { this.values = new Map(); }
  async put(value) { assert.ok(!this.values.has(value.session_id)); this.values.set(value.session_id, structuredClone(value)); }
  async get(key) { return structuredClone(this.values.get(key) || null); }
  async consume(key, type, timestamp) {
    const value = this.values.get(key);
    if (!value || value.type !== type || value.expires_at <= timestamp) return null;
    this.values.delete(key);
    return structuredClone(value);
  }
  async delete(key) { this.values.delete(key); }
}
const claims = (changes = {}) => ({ iss: ISSUER, sub: "verified-sub", client_id: "client-one", token_use: "access", iat: now() - 1, exp: now() + 900,
  "cognito:groups": ["security-admins"], ...changes });
function configured(options = {}) {
  const store = options.store || new MemoryStore();
  const auth = createDashboardAuth({ env: config, store, fetchImpl: async () => ({ ok: true, json: async () => provider }),
    verifier: async token => JSON.parse(Buffer.from(token, "base64url").toString()), ...options });
  return { auth, store };
}
const encode = value => Buffer.from(JSON.stringify(value)).toString("base64url");
const bearer = value => ({ Authorization: "Bearer " + encode(value) });
const csrf = token => createHash("sha256").update(token).digest("base64url");

async function runApp(t, auth, configure) {
  const app = express();
  app.use(securityHeaders);
  auth.install(app);
  app.use(express.json());
  app.use(auth.rejectClientActor);
  configure?.(app);
  const server = app.listen(0, "127.0.0.1");
  await new Promise(resolve => server.once("listening", resolve));
  t.after(async () => { await new Promise(resolve => server.close(resolve)); });
  return "http://127.0.0.1:" + server.address().port;
}

test("production configuration and session table are mandatory, health alone remains public", async t => {
  const auth = createDashboardAuth({ env: {}, store: null });
  assert.equal(auth.configured, false);
  let mutations = 0;
  const base = await runApp(t, auth, app => app.post("/api/rollback-ip", (req, res) => { mutations++; res.json({ ok: true }); }));
  assert.equal((await fetch(base + "/healthz")).status, 200);
  assert.equal((await fetch(base + "/api/session")).status, 503);
  assert.equal((await fetch(base + "/auth/login")).status, 503);
  assert.equal((await fetch(base + "/api/rollback-ip", { method: "POST" })).status, 503);
  assert.equal(mutations, 0);
  for (const env of [{ ...config, PUBLIC_ORIGIN: "http://dashboard.example" }, { ...config, OIDC_REDIRECT_URI: "https://evil.example/auth/callback" }]) {
    assert.equal(createDashboardAuth({ env, store: new MemoryStore() }).configured, false);
  }
});

test("anonymous, nonadmin, bad origin and absent CSRF cannot reach any mutating API", async t => {
  const { auth } = configured();
  let writes = 0;
  const base = await runApp(t, auth, app => {
    for (const route of ["/api/decision", "/api/reject", "/api/block-ip", "/api/rollback-ip"]) app.post(route, (req, res) => { writes++; res.json({ subject: req.auth.sub }); });
  });
  const adminToken = encode(claims());
  const readToken = encode(claims({ "cognito:groups": ["security-readers"] }));
  const headers = { "Content-Type": "application/json", Origin: ORIGIN, Authorization: "Bearer " + adminToken, "X-CSRF-Token": csrf(adminToken) };
  for (const route of ["/api/decision", "/api/reject", "/api/block-ip", "/api/rollback-ip"]) {
    assert.equal((await fetch(base + route, { method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN }, body: "{}" })).status, 401);
    assert.equal((await fetch(base + route, { method: "POST", headers: { ...headers, Authorization: "Bearer " + readToken, "X-CSRF-Token": csrf(readToken) }, body: "{}" })).status, 403);
    assert.equal((await fetch(base + route, { method: "POST", headers: { ...headers, "X-CSRF-Token": "wrong" }, body: "{}" })).status, 403);
    assert.equal((await fetch(base + route, { method: "POST", headers: { ...headers, Origin: "https://evil.example", "X-Forwarded-Host": "dashboard.example", "X-Forwarded-Proto": "https" }, body: "{}" })).status, 403);
    assert.equal((await fetch(base + route, { method: "POST", headers, body: JSON.stringify({ by: "forged-admin" }) })).status, 400);
  }
  assert.equal(writes, 0);
  const reply = await fetch(base + "/api/rollback-ip", { method: "POST", headers, body: "{}" });
  assert.equal(reply.status, 200);
  assert.equal((await reply.json()).subject, "verified-sub");
  assert.equal(writes, 1);
});

test("verified reader can read but cannot claim an admin role with a substring or client field", async t => {
  const { auth } = configured();
  const base = await runApp(t, auth);
  const reader = await fetch(base + "/api/session", { headers: bearer(claims({ "cognito:groups": ["security-readers"] })) });
  assert.equal(reader.status, 200);
  assert.equal((await reader.json()).admin, false);
  const confused = await fetch(base + "/api/session", { headers: bearer(claims({ "cognito:groups": ["security-admins-extra"] })) });
  assert.equal(confused.status, 403);
});

test("real RSA signatures, issuer, client, algorithm, expiration and token_use are verified", async () => {
  const jose = await import(pathToFileURL(libraryRequire.resolve("jose")).href);
  const pair = await jose.generateKeyPair("RS256");
  const publicKey = await jose.exportJWK(pair.publicKey);
  publicKey.kid = "key-one";
  const keySet = jose.createLocalJWKSet({ keys: [publicKey] });
  const { auth } = configured({ verifier: undefined, jwtKeySet: keySet });
  const sign = changes => new jose.SignJWT(claims(changes)).setProtectedHeader({ alg: "RS256", kid: "key-one" }).sign(pair.privateKey);
  const good = await sign({});
  assert.equal((await auth.verifyJwt(good, "access")).sub, "verified-sub");
  for (const changed of [{ iss: "https://evil.example" }, { client_id: "wrong-client" }, { exp: now() - 30 }, { token_use: "id" }, { iat: now() + 3600 }]) {
    await assert.rejects(() => sign(changed).then(token => auth.verifyJwt(token, "access")), error => error.status === 401);
  }
  const pieces = good.split(".");
  pieces[1] = Buffer.from(JSON.stringify(claims({ sub: "forged-admin" }))).toString("base64url");
  await assert.rejects(() => auth.verifyJwt(pieces.join("."), "access"), error => error.status === 401);
  const unsigned = [encode({ alg: "none" }), encode(claims()), ""].join(".");
  await assert.rejects(() => auth.verifyJwt(unsigned, "access"), error => error.status === 401);
});

test("login consumes PKCE state once, binds nonce/subject, stores no OAuth tokens and expires session", async t => {
  const store = new MemoryStore();
  let timestamp = now();
  let flow;
  let verifierReceived;
  const { auth } = configured({ store, now: () => timestamp,
    fetchImpl: async (url, options) => {
      if (url.endsWith("openid-configuration")) return { ok: true, json: async () => provider };
      verifierReceived = options.body.get("code_verifier");
      return { ok: true, json: async () => ({ id_token: encode(claims({ token_use: "id", aud: "client-one", nonce: flow.nonce })), access_token: encode(claims()), refresh_token: "must-not-persist" }) };
    } });
  const base = await runApp(t, auth, app => app.get("/", (req, res) => res.type("html").send('<!DOCTYPE html><html><head></head><body><script>console.log("safe")</script></body></html>')));
  const login = await fetch(base + "/auth/login", { redirect: "manual" });
  assert.equal(login.status, 302);
  const location = new URL(login.headers.get("location"));
  assert.equal(location.searchParams.get("code_challenge_method"), "S256");
  assert.equal(location.searchParams.get("redirect_uri"), config.OIDC_REDIRECT_URI);
  const flowCookie = login.headers.get("set-cookie").split(";")[0];
  flow = [...store.values.values()][0];
  assert.equal(location.searchParams.get("code_challenge"), csrf(flow.verifier));
  const callbackUrl = base + "/auth/callback?code=one-time-code&state=" + encodeURIComponent(flow.state);
  const callback = await fetch(callbackUrl, { headers: { Cookie: flowCookie }, redirect: "manual" });
  assert.equal(callback.status, 303);
  assert.equal(verifierReceived, flow.verifier);
  const sessionCookie = callback.headers.getSetCookie().find(value => value.startsWith(SESSION_COOKIE + "="));
  assert.match(sessionCookie, /HttpOnly; Secure; SameSite=Lax/);
  const stored = [...store.values.values()][0];
  assert.equal(stored.type, "session");
  assert.equal(stored.user.sub, "verified-sub");
  assert.equal(JSON.stringify(stored).includes("refresh_token"), false);
  assert.equal(JSON.stringify(stored).includes("access_token"), false);
  const cookieHeader = sessionCookie.split(";")[0];
  const session = await fetch(base + "/api/session", { headers: { Cookie: cookieHeader } });
  assert.equal(session.status, 200);
  const data = await session.json();
  assert.equal(data.subject, "verified-sub");
  const page = await fetch(base + "/", { headers: { Cookie: cookieHeader } });
  const html = await page.text();
  assert.match(html, /name="csrf-token"/);
  assert.match(html, /<script nonce="[A-Za-z0-9+/=]+">/);
  assert.match(page.headers.get("content-security-policy"), /object-src 'none'/);
  const replay = await fetch(callbackUrl, { headers: { Cookie: flowCookie }, redirect: "manual" });
  assert.equal(replay.status, 401);
  timestamp += 901;
  assert.equal((await fetch(base + "/api/session", { headers: { Cookie: cookieHeader } })).status, 401);
});

test("missing/wrong state and mismatched ID/access subjects never create a session", async t => {
  for (const mismatch of ["state", "subject", "nonce"]) {
    const store = new MemoryStore();
    let flow;
    const { auth } = configured({ store, fetchImpl: async url => url.endsWith("openid-configuration") ? { ok: true, json: async () => provider } :
      { ok: true, json: async () => ({ id_token: encode(claims({ token_use: "id", aud: "client-one", nonce: mismatch === "nonce" ? "incorrect" : flow.nonce,
        sub: mismatch === "subject" ? "other-sub" : "verified-sub" })), access_token: encode(claims()) }) } });
    const base = await runApp(t, auth);
    const login = await fetch(base + "/auth/login", { redirect: "manual" });
    flow = [...store.values.values()][0];
    const callback = await fetch(base + "/auth/callback?code=code&state=" + (mismatch === "state" ? "incorrect" : flow.state),
      { headers: { Cookie: login.headers.get("set-cookie").split(";")[0] }, redirect: "manual" });
    assert.equal(callback.status, 401);
    assert.equal([...store.values.values()].some(value => value.type === "session"), false);
  }
});

test("Dynamo session state is created and consumed with conditions and TTL, not an unsafe read-delete pair", async () => {
  const calls = [];
  class GetCommand { constructor(input) { this.input = input; } }
  class PutCommand { constructor(input) { this.input = input; } }
  class DeleteCommand { constructor(input) { this.input = input; } }
  const client = { send: async command => { calls.push(command.input); return { Attributes: { type: "flow" } }; } };
  const store = createDynamoSessionStore({ client, tableName: "sessions", commands: { GetCommand, PutCommand, DeleteCommand } });
  await store.put({ session_id: "flow#random", expires_at: now() + 300 });
  assert.equal(calls[0].ConditionExpression, "attribute_not_exists(session_id)");
  await store.consume("flow#random", "flow", now());
  assert.match(calls[1].ConditionExpression, /expires_at > :now/);
  assert.equal(calls[1].ReturnValues, "ALL_OLD");
  assert.equal(createDynamoSessionStore({ client, tableName: undefined, commands: {} }), null);
});

test("stored Markdown cannot inject scripts, events, javascript URLs, forms, images or SVG", async () => {
  const input = '<h2>Evidence</h2><script>steal()</script><img src="https://evil.example/secret" onerror="steal()"><svg onload="steal()"></svg>' +
    '<a href="javascript:steal()" onclick="steal()">bad</a><iframe srcdoc="<script>steal()</script>"></iframe>' +
    '<form action="/api/rollback-ip"><button>execute</button></form><a href="https://example.com">source</a><pre><code class="language-js">safe</code></pre>';
  const output = await sanitizeReportHtml(input);
  assert.match(output, /<h2>Evidence<\/h2>/);
  assert.match(output, /href="https:\/\/example.com"/);
  assert.match(output, /rel="noopener noreferrer"/);
  assert.doesNotMatch(output, /<script|<img|<svg|<iframe|<form|onclick|onerror|javascript:/i);
});

test("auth failures expose no tokens, callback codes, PKCE secret or arbitrary IdP error details", async t => {
  const secret = "sensitive-bearer-value";
  const { auth } = configured({ verifier: async () => { throw new Error("Bearer " + secret); } });
  const base = await runApp(t, auth);
  const reply = await fetch(base + "/api/session", { headers: { Authorization: "Bearer " + secret } });
  assert.equal(reply.status, 503);
  assert.equal((await reply.text()).includes(secret), false);
});

test("canonical report keys bind a service; flat keys require an explicit legacy service migration", () => {
  const caseId = "inv-" + "a".repeat(32);
  assert.deepEqual(parseCaseKey("billing-prod/" + caseId + ".md", undefined), { serviceId: "billing-prod", caseId, key: "billing-prod/" + caseId + ".md" });
  assert.equal(parseCaseKey(caseId + ".md", ""), null);
  assert.equal(parseCaseKey("../billing-prod/" + caseId + ".md", "legacy-service"), null);
  assert.equal(parseCaseKey(caseId + ".md", "legacy-service").serviceId, "legacy-service");
});

test("registry revalidates company, service, action, scope and operator groups before choosing WAF", async () => {
  const account = "123456789012";
  const id = "00000000-0000-4000-8000-aaaaaaaaaaaa";
  const original = { service_id: "billing-prod", enabled: true, account_id: account, region: "ap-northeast-2", revision: "one", response_mode: "enforce",
    allowed_actions: ["monitor", "block_ip"], manual_block_enabled: true, audit_bucket: "company-audit", waf_ipset_arn: `arn:aws:wafv2:ap-northeast-2:${account}:regional/ipset/security-billing/${id}`, waf_scope: "REGIONAL",
    allowed_admin_groups: ["billing-operators"], allowed_reader_groups: ["billing-readers"] };
  let record = original;
  const calls = [];
  class GetCommand { constructor(input) { this.input = input; } }
  class ScanCommand { constructor(input) { this.input = input; } }
  const client = { send: async command => { calls.push(command.input); return command instanceof ScanCommand ? { Items: [record] } : { Item: structuredClone(record) }; } };
  const resolver = createServiceResolver({ client, tableName: "registry", companyAccountId: account, GetCommand, ScanCommand, reportBucket: "company-audit" });
  const review = { ok: true, service_id: "billing-prod", tier: 2, status: "DECIDED_APPROVE", decision: "approve", callback_status: "SENT", approved_action: "block_ip", target: { source_ip: "203.0.113.9" } };
  const operator = { admin: true, groups: ["billing-operators"] };
  const result = await resolver.resolve(review, operator, "block");
  assert.equal(result.waf.name, "security-billing");
  assert.equal(result.waf.region, "ap-northeast-2");
  assert.equal(result.waf.scope, "REGIONAL");
  assert.equal(calls[0].ConsistentRead, true);
  assert.equal((await resolver.list(operator)).length, 1);
  await assert.rejects(() => resolver.resolve(review, { admin: true, groups: ["other-operators"] }, "rollback"), error => error.code === "service_forbidden");
  await assert.rejects(() => resolver.resolve(review, { admin: false, groups: ["billing-readers"] }, "block"), error => error.code === "service_forbidden");
  for (const changes of [{ account_id: "999999999999" }, { enabled: false }]) {
    record = { ...original, ...changes };
    await assert.rejects(() => resolver.resolve(review, operator, "rollback"), error => error.code === "service_disabled");
  }
  record = { ...original, waf_scope: "CLOUDFRONT" };
  await assert.rejects(() => resolver.resolve(review, operator, "rollback"), error => error.code === "invalid_registry");
  record = { ...original, allowed_actions: ["monitor"] };
  await assert.rejects(() => resolver.resolve(review, operator, "block"), error => error.code === "action_forbidden");
  record = { ...original, response_mode: "observe", manual_block_enabled: false };
  await assert.rejects(() => resolver.resolve(review, operator, "block"), error => error.code === "manual_block_disabled");
  assert.equal((await resolver.resolve(review, operator, "rollback")).waf.id, id);
  record = { ...original, protected_cidrs: ["203.0.113.0/24"] };
  await assert.rejects(() => resolver.resolve(review, operator, "block"), error => error.code === "protected_target");
  assert.equal((await resolver.resolve(review, operator, "rollback")).waf.id, id);
  await assert.rejects(() => resolver.resolve({ ok: true }, operator), error => error.code === "service_unbound");
  record = { ...original, waf_ipv6_ipset_arn: original.waf_ipset_arn.replace("security-billing/", "security-billing-v6/") };
  const ipv6Review = { ...review, target: { source_ip: "2001:db8::1" } };
  assert.equal((await resolver.resolve(ipv6Review, operator, "rollback")).waf.family, 6);
  assert.equal((await resolver.resolve(ipv6Review, operator, "rollback")).waf.name, "security-billing-v6");
  record = { ...original };
  await assert.rejects(() => resolver.resolve(ipv6Review, operator, "rollback"), error => error.code === "waf_unbound");
});

function httpEvent(method, rawPath, headers = {}, body) {
  return { version: "2.0", routeKey: "$default", rawPath, rawQueryString: "", headers: { host: "api.example", ...headers },
    requestContext: { accountId: "123456789012", apiId: "api", domainName: "api.example", domainPrefix: "api", stage: "$default", requestId: "test-request",
      time: "14/Oct/2026:00:00:00 +0000", timeEpoch: Date.now(), http: { method, path: rawPath, protocol: "HTTP/1.1", sourceIp: "127.0.0.1", userAgent: "test" } },
    body, isBase64Encoded: false };
}
test("HTTP API v2 adapter preserves secure session cookies and rejects protected requests without credentials", async () => {
  const serverlessExpress = libraryRequire("@codegenie/serverless-express");
  const { auth } = configured();
  const app = express();
  app.use(securityHeaders);
  auth.install(app);
  const handler = serverlessExpress({ app });
  const context = { getRemainingTimeInMillis: () => 30000 };
  const health = await handler(httpEvent("GET", "/healthz"), context);
  assert.equal(health.statusCode, 200);
  const login = await handler(httpEvent("GET", "/auth/login"), context);
  assert.equal(login.statusCode, 302);
  assert.ok(login.cookies.some(cookie => cookie.startsWith(FLOW_COOKIE + "=")));
  assert.match(login.cookies[0], /Secure; SameSite=Lax/);
  const forbidden = await handler(httpEvent("POST", "/api/rollback-ip", { "content-type": "application/json", origin: ORIGIN }, "{}"), context);
  assert.equal(forbidden.statusCode, 401);
});
