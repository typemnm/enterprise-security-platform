"use strict";

// Called after the dashboard's verified Cognito identity/RBAC/CSRF middleware.
// Additional same-origin checks are browser request protections, not identity.
const { createHash } = require("node:crypto");
const { parseIp, parseNetwork, contains, exactHost } = require("./ip-utils");
const { parseCaseKey } = require("./case-key");
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const FINAL_HOTL = new Set(["AUTO_BLOCKED", "AUTO_BLOCK_PARTIAL", "AUTO_BLOCK_FAILED", "AUTO_BLOCK_UNVERIFIED", "AUTO_ISOLATED", "AUTO_ISOLATION_FAILED"]);
const LIMITATION = "영구 WAF IPSet의 단일 IP 항목만 제거합니다. NACL·임시 WAF·범위 차단은 유지되며 새 탐지 시 재차단될 수 있습니다.";

class RollbackError extends Error {
  constructor(status, code, message, details = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

function requireSameOrigin(req, configuredOrigin) {
  const site = req.get("sec-fetch-site");
  // Some browsers omit Fetch Metadata on public HTTP origins. A present value
  // must still be same-origin; a missing value requires the same Origin checks.
  if (site && site !== "same-origin") {
    throw new RollbackError(403, "cross_origin", "같은 대시보드 화면에서 보낸 요청만 허용합니다.");
  }
  const origin = req.get("origin");
  try {
    const value = new URL(origin);
    if (!["http:", "https:"].includes(value.protocol) || origin !== value.origin) throw new Error("Invalid Origin");
    if (configuredOrigin) {
      const expected = new URL(configuredOrigin);
      if (!["http:", "https:"].includes(expected.protocol) || value.origin !== expected.origin) throw new Error("Origin mismatch");
    } else if (value.host !== req.get("host")) {
      // Keep the existing dashboard proxy behavior: HTTPS may terminate before
      // Express. Set DASHBOARD_ORIGIN for a strict, full public-origin check.
      throw new Error("Origin mismatch");
    }
  } catch {
    throw new RollbackError(403, "cross_origin", "요청 출처가 대시보드와 다릅니다.");
  }
  if (!req.is("application/json")) {
    throw new RollbackError(415, "unsupported_media_type", "JSON 요청이 필요합니다.");
  }
}

function parseCidr(value) {
  const network = parseNetwork(value);
  if (!network) throw new RollbackError(502, "invalid_ipset", "WAF CIDR 응답이 올바르지 않습니다.");
  return network;
}

function canonicalTarget(review, key, serviceId) {
  const identity = parseCaseKey(key);
  if (!identity || !review?.ok || review.case_id !== identity.caseId || review.service_id !== identity.serviceId) {
    throw new RollbackError(404, "case_unavailable", "사건 저장소에서 조치 대상을 확인하지 못했습니다.");
  }
  if (serviceId && review.service_id !== serviceId) throw new RollbackError(403, "service_mismatch", "사건과 등록된 서비스가 일치하지 않습니다.");
  if (!Number.isInteger(review.tier) || ![0, 1].includes(review.tier)) {
    throw new RollbackError(409, "not_hotl", "HOTL 자동 조치 사건에서만 사용자 차단을 롤백할 수 있습니다.");
  }
  if (!FINAL_HOTL.has(review.status)) {
    throw new RollbackError(409, "case_in_progress", "자동 조치가 완료되거나 실패한 사건에서만 롤백할 수 있습니다. 상태를 새로 확인하세요.");
  }
  const ip = review.target?.source_ip;
  if (!parseIp(ip)) {
    throw new RollbackError(409, "target_unavailable", "사건 저장소의 검증된 단일 IP 조치 대상이 없습니다.");
  }
  return parseIp(ip).ip;
}

function validateBody(body) {
  const fields = ["key", "reason", "request_id", "expected_lock_token"];
  if (!body || typeof body !== "object" || Array.isArray(body) ||
      Object.keys(body).length !== fields.length || fields.some(field => !Object.hasOwn(body, field))) {
    throw new RollbackError(400, "invalid_request", "key, reason, request_id, expected_lock_token만 보내세요.");
  }
  if (!parseCaseKey(body.key)) {
    throw new RollbackError(400, "invalid_key", "유효한 사건 보고서 키가 필요합니다.");
  }
  if (typeof body.reason !== "string" || !body.reason.trim() || body.reason.length > 500) {
    throw new RollbackError(400, "invalid_reason", "1~500자의 차단 롤백 사유가 필요합니다.");
  }
  if (typeof body.request_id !== "string" || !UUID_RE.test(body.request_id)) {
    throw new RollbackError(400, "invalid_request_id", "새 UUID v4 요청 식별자가 필요합니다.");
  }
  if (typeof body.expected_lock_token !== "string" || !body.expected_lock_token.trim() || body.expected_lock_token.length > 2048) {
    throw new RollbackError(400, "invalid_lock_token", "화면 조회에서 받은 WAF 변경 잠금 토큰이 필요합니다.");
  }
  return { ...body, reason: body.reason.trim() };
}

function missing(error) {
  return ["NoSuchKey", "NotFound"].includes(error.name) || error.$metadata?.httpStatusCode === 404;
}
function precondition(error) {
  return ["PreconditionFailed", "ConditionalRequestConflict"].includes(error.name) ||
    [409, 412].includes(error.$metadata?.httpStatusCode);
}

function createWafRollback({ waf, s3, bucket, wafArn, wafName, wafId, reviewStatus, commands, logger = console, serviceId, registryRevision, wafFamily = 4 }) {
  const { GetIPSetCommand, UpdateIPSetCommand, GetObjectCommand, PutObjectCommand } = commands;
  const arn = /^arn:(aws|aws-us-gov|aws-cn):wafv2:([a-z0-9-]+):(\d{12}):(global|regional)\/ipset\/([A-Za-z0-9_-]+)\/([A-Za-z0-9-]+)$/.exec(wafArn || "");
  const scope = arn?.[4] === "global" ? "CLOUDFRONT" : "REGIONAL";
  // Endpoint and allowlist stay server-configured; client input cannot choose an IPSet.
  const configured = Boolean(arn && arn[5] === wafName && arn[6] === wafId && bucket && (scope !== "CLOUDFRONT" || arn[2] === "us-east-1"));
  let activeRequest = null; // bounded to one write per permanent IPSet in this process

  function requireConfiguration() {
    if (!configured) throw new RollbackError(503, "invalid_configuration", "영구 WAF IPSet ARN·이름·ID와 감사 버킷 설정을 확인하세요.");
  }
  async function readSet() {
    requireConfiguration();
    const current = await waf.send(new GetIPSetCommand({ Name: wafName, Id: wafId, Scope: scope }));
    if (current.IPSet?.ARN !== wafArn || current.IPSet?.Name !== wafName || current.IPSet?.Id !== wafId ||
        current.IPSet?.IPAddressVersion !== `IPV${wafFamily}` || !Array.isArray(current.IPSet?.Addresses) ||
        typeof current.LockToken !== "string" || !current.LockToken) {
      throw new RollbackError(502, "invalid_ipset", "WAF 응답이 설정된 영구 IPv4 IPSet과 일치하지 않습니다.");
    }
    const networks = current.IPSet.Addresses.map(parseCidr);
    if (networks.some(network => network.family !== wafFamily)) throw new RollbackError(502, "invalid_ipset", "WAF 주소 패밀리가 일치하지 않습니다.");
    return { current, networks };
  }
  function matchingRanges(networks, ip) {
    const parsed = parseIp(ip);
    return networks.filter(network => network.prefix !== parsed.prefix && contains(network, parsed)).map(network => network.cidr);
  }
  function requireFamily(ip) {
    const parsed = parseIp(ip);
    if (!parsed || parsed.family !== wafFamily) throw new RollbackError(409, "target_family_mismatch", "사건 IP와 등록된 WAF IPSet 패밀리가 일치하지 않습니다.");
    return parsed;
  }
  async function getSnapshot(key, trustedReview) {
    if (!parseCaseKey(key)) {
      throw new RollbackError(400, "invalid_key", "유효한 사건 보고서 키가 필요합니다.");
    }
    const review = trustedReview || await reviewStatus(key);
    const ip = canonicalTarget(review, key, serviceId);
    const { current, networks } = await readSet();
    const parsed = requireFamily(ip);
    const blocked = networks.some(network => exactHost(network, parsed));
    return {
      eligible: blocked, blocked, ip, cidr: `${ip}/${parsed.prefix}`, family: parsed.family, tier: review.tier, status: review.status,
      expected_lock_token: current.LockToken, remaining_matching_cidrs: matchingRanges(networks, ip),
      message: blocked ? `${ip}/${parsed.prefix} 영구 차단 항목을 롤백할 수 있습니다.` : `${ip}/${parsed.prefix} 영구 차단 항목이 없습니다.`,
      limitation: LIMITATION,
    };
  }
  function auditKey(body) {
    return `decisions/${body.key}.iprollback.${body.request_id}.json`;
  }
  async function readAudit(key, fingerprint) {
    let reply;
    try {
      reply = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
    } catch (error) {
      if (missing(error)) return null;
      throw error;
    }
    let record;
    try { record = JSON.parse(await reply.Body.transformToString()); }
    catch { throw new RollbackError(503, "invalid_audit", "기존 롤백 감사 기록을 확인하지 못했습니다."); }
    if (record.payload_hash !== fingerprint) {
      throw new RollbackError(409, "request_id_conflict", "이 요청 식별자는 다른 롤백 요청에 이미 사용되었습니다.");
    }
    if (!["attempted", "completed"].includes(record.action) || typeof reply.ETag !== "string") {
      throw new RollbackError(503, "invalid_audit", "기존 롤백 감사 기록 형식이 올바르지 않습니다.");
    }
    return { record, etag: reply.ETag };
  }
  async function pending(body, ip, fingerprint, key, previous, peer, actor, issuer) {
    if (previous) return previous;
    const record = {
      version: 1, action: "attempted", reportKey: body.key, request_id: body.request_id,
      ip, cidr: `${ip}/${parseIp(ip).prefix}`, family: parseIp(ip).family, reason: body.reason, expected_lock_token: body.expected_lock_token,
      ipSetArn: wafArn, payload_hash: fingerprint, attempted_at: new Date().toISOString(),
      service_id: serviceId || null, registry_revision: registryRevision || null,
      requested_by: actor, identity_issuer: issuer, identity_verified: true,
      network_peer: typeof peer === "string" ? peer.slice(0, 128) : null,
    };
    try {
      const reply = await s3.send(new PutObjectCommand({
        Bucket: bucket, Key: key, Body: JSON.stringify(record, null, 2),
        ContentType: "application/json", IfNoneMatch: "*",
      }));
      if (typeof reply.ETag !== "string") {
        throw new RollbackError(503, "audit_unconfirmed", "감사 기록 저장 확인에 실패했습니다. 같은 요청으로 재시도하세요.", { retry_same_request: true });
      }
      return { record, etag: reply.ETag };
    } catch (error) {
      if (!precondition(error)) throw error;
      const existing = await readAudit(key, fingerprint);
      if (!existing) throw error;
      return existing;
    }
  }
  async function complete(audit, key, fingerprint, result) {
    const record = { ...audit.record, action: "completed", result, completed_at: new Date().toISOString() };
    try {
      await s3.send(new PutObjectCommand({
        Bucket: bucket, Key: key, Body: JSON.stringify(record, null, 2),
        ContentType: "application/json", IfMatch: audit.etag,
      }));
      return result;
    } catch (error) {
      if (precondition(error)) {
        try {
          const existing = await readAudit(key, fingerprint);
          if (existing?.record.action === "completed") return { ...existing.record.result, idempotent: true };
        } catch { /* Keep the known WAF outcome visible even if an audit read fails. */ }
      }
      logger.error("WAF_ROLLBACK_AUDIT_GAP", { request_id: result.request_id, error: error.name });
      throw new RollbackError(503, "audit_incomplete", "WAF 결과의 감사 기록 완료에 실패했습니다. 동일 요청으로 재시도하세요.", {
        retry_same_request: true, outcome: result, request_id: result.request_id,
      });
    }
  }
  async function rollback(bodyInput, { peer, actor, issuer } = {}) {
    const body = validateBody(bodyInput);
    requireConfiguration();
    if (typeof actor !== "string" || !actor || typeof issuer !== "string" || !issuer.startsWith("https://")) {
      throw new RollbackError(401, "unauthenticated", "검증된 관리자 주체가 필요합니다.");
    }
    if (activeRequest) throw new RollbackError(409, "busy", "다른 WAF 롤백 요청을 처리 중입니다. 잠시 후 동일 요청으로 재시도하세요.", { retry_same_request: true });
    activeRequest = body.request_id;
    try {
      // The current case record is authoritative, including for retries.
      const review = await reviewStatus(body.key);
      const ip = canonicalTarget(review, body.key, serviceId);
      const payload = { key: body.key, reason: body.reason, ip, expected_lock_token: body.expected_lock_token, ipSetArn: wafArn, actor, issuer,
        service_id: serviceId || null, registry_revision: registryRevision || null };
      const fingerprint = createHash("sha256").update(JSON.stringify(payload)).digest("hex");
      const key = auditKey(body);
      let audit = await readAudit(key, fingerprint);
      if (audit?.record.action === "completed") return { ...audit.record.result, idempotent: true };
      const { current, networks } = await readSet();
      const parsed = requireFamily(ip);
      const cidr = `${ip}/${parsed.prefix}`;
      const exactAddresses = networks.filter(network => exactHost(network, parsed)).map(network => network.original);
      const exactPresent = exactAddresses.length > 0;
      const recovering = Boolean(audit && !exactPresent);
      if (current.LockToken !== body.expected_lock_token && !recovering) {
        throw new RollbackError(409, "conflict", "WAF 목록이 변경됐습니다. 새로고침 후 차단 상태를 확인하고 다시 시도하세요.", { refresh: true });
      }
      audit = await pending(body, ip, fingerprint, key, audit, peer, actor, issuer);
      if (audit.record.action === "completed") return { ...audit.record.result, idempotent: true };
      let status = "already_absent";
      if (exactPresent) {
        const input = {
          Name: wafName, Id: wafId, Scope: scope, LockToken: current.LockToken,
          Addresses: current.IPSet.Addresses.filter(address => !exactAddresses.includes(address)),
        };
        if (current.IPSet.Description) input.Description = current.IPSet.Description;
        try {
          await waf.send(new UpdateIPSetCommand(input));
        } catch (error) {
          if (error.name === "WAFOptimisticLockException") {
            throw new RollbackError(409, "conflict", "WAF 목록이 동시에 변경됐습니다. 새로고침 후 다시 시도하세요.", { refresh: true });
          }
          throw error;
        }
        status = "removed";
      }
      const ranges = matchingRanges(networks, ip);
      const result = {
        ok: true, status, ip, cidr, request_id: body.request_id, audit_key: key,
        remaining_matching_cidrs: ranges, limitation: LIMITATION,
        message: `${cidr} 영구 차단 항목${status === "removed" ? "을 제거했습니다." : "은 이미 없습니다."}` +
          (ranges.length ? ` 해당 IP는 ${ranges.join(", ")} 범위 차단에 계속 포함됩니다.` : "") + ` ${LIMITATION}`,
      };
      if (recovering) result.audit_recovered = true;
      return await complete(audit, key, fingerprint, result);
    } finally {
      activeRequest = null;
    }
  }
  return { getSnapshot, rollback };
}

module.exports = { createWafRollback, requireSameOrigin, RollbackError, LIMITATION };
