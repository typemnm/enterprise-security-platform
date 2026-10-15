"use strict";

// Uses fake SDK clients only. No AWS credentials, network, or mutation.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const {
  createWafRollback, requireSameOrigin, RollbackError,
} = require("../waf-rollback.js");

class GetIPSetCommand { constructor(input) { this.input = input; } }
class UpdateIPSetCommand { constructor(input) { this.input = input; } }
class GetObjectCommand { constructor(input) { this.input = input; } }
class PutObjectCommand { constructor(input) { this.input = input; } }
class ListObjectsV2Command { constructor(input) { this.input = input; } }
class InvokeCommand { constructor(input) { this.input = input; } }
class StartExecutionCommand { constructor(input) { this.input = input; } }
class DescribeExecutionCommand { constructor(input) { this.input = input; } }
const commands = { GetIPSetCommand, UpdateIPSetCommand, GetObjectCommand, PutObjectCommand };
const SERVICE_ID = "sample-service";
const KEY = SERVICE_ID + "/inv-" + "a".repeat(32) + ".md";
const CASE_ID = KEY.split("/").at(-1).slice(0, -3);
const ARN = "arn:aws:wafv2:us-east-1:123456789012:global/ipset/security-example-ipv4/00000000-0000-4000-8000-aaaaaaaaaaaa";
const ID = ARN.split("/").at(-1);
const REQUEST_ID = "12345678-1234-4234-8234-123456789abc";
const body = (changes = {}) => ({ key: KEY, reason: "오탐 확인 후 영구 WAF 차단 해제", request_id: REQUEST_ID, expected_lock_token: "lock-1", ...changes });
const awsError = (name, status) => Object.assign(new Error(name), { name, $metadata: { httpStatusCode: status } });

class FakeS3 {
  constructor() {
    this.objects = new Map();
    this.calls = [];
    this.version = 0;
    this.failPending = false;
    this.failComplete = 0;
    this.failRead = false;
  }
  async send(command) {
    const input = command.input;
    this.calls.push(command);
    if (command instanceof ListObjectsV2Command) return { Contents: [] };
    if (command instanceof GetObjectCommand) {
      if (this.failRead) throw awsError("AccessDenied", 403);
      const found = this.objects.get(input.Key);
      if (!found) throw awsError("NoSuchKey", 404);
      return { ETag: found.etag, Body: { transformToString: async () => found.body } };
    }
    assert.ok(command instanceof PutObjectCommand);
    const previous = this.objects.get(input.Key);
    const record = JSON.parse(input.Body);
    if (record.action === "attempted" && this.failPending) throw awsError("AccessDenied", 403);
    if (record.action === "completed" && this.failComplete) {
      this.failComplete--;
      throw awsError("ServiceUnavailable", 503);
    }
    if ((input.IfNoneMatch === "*" && previous) || (input.IfMatch && input.IfMatch !== previous?.etag)) {
      throw awsError("PreconditionFailed", 412);
    }
    const etag = `"etag-${++this.version}"`;
    this.objects.set(input.Key, { etag, body: input.Body });
    return { ETag: etag };
  }
}

class FakeWaf {
  constructor() {
    this.addresses = ["203.0.113.9/32", "198.51.100.17/32", "203.0.113.0/24"];
    this.token = "lock-1";
    this.version = 1;
    this.calls = [];
    this.arn = ARN;
    this.concurrentIp = null;
    this.beforeUpdate = null;
    this.onRead = null;
    this.scope = "CLOUDFRONT";
    this.family = 4;
  }
  async send(command) {
    this.calls.push(command);
    const input = command.input;
    assert.equal(input.Name, "security-example-ipv4");
    assert.equal(input.Id, ID);
    assert.equal(input.Scope, this.scope);
    if (command instanceof GetIPSetCommand) {
      if (this.onRead) await this.onRead();
      return { IPSet: { Name: input.Name, Id: input.Id, ARN: this.arn, IPAddressVersion: `IPV${this.family}`,
        Addresses: this.addresses.slice(), Description: "Preserve this description" }, LockToken: this.token };
    }
    assert.ok(command instanceof UpdateIPSetCommand);
    if (this.beforeUpdate) this.beforeUpdate();
    if (this.concurrentIp) {
      this.addresses.push(this.concurrentIp);
      this.concurrentIp = null;
      this.token = `lock-${++this.version}`;
    }
    if (input.LockToken !== this.token) throw awsError("WAFOptimisticLockException", 400);
    this.addresses = input.Addresses.slice();
    this.token = `lock-${++this.version}`;
    return { NextLockToken: this.token };
  }
  writes() { return this.calls.filter(command => command instanceof UpdateIPSetCommand); }
}

function fixture() {
  const s3 = new FakeS3();
  const waf = new FakeWaf();
  const logs = [];
  let review = { ok: true, case_id: CASE_ID, service_id: SERVICE_ID, tier: 1, status: "AUTO_BLOCKED", target: { source_ip: "203.0.113.9" } };
  const reviewCalls = [];
  const reviewStatus = async key => { reviewCalls.push(key); return structuredClone(review); };
  const service = createWafRollback({
    waf, s3, bucket: "report-bucket", wafArn: ARN, wafName: "security-example-ipv4", wafId: ID,
    reviewStatus, commands, serviceId: SERVICE_ID, registryRevision: "revision-one", logger: { error: (...args) => logs.push(args) },
  });
  const authenticated = { ...service, rollback: (request, options = {}) => service.rollback(request,
    { actor: "verified-operator-sub", issuer: "https://idp.example/pool", ...options }) };
  return { service: authenticated, waf, s3, logs, reviewStatus, reviewCalls, setReview(value) { review = { service_id: SERVICE_ID, ...value }; } };
}
async function rejected(fn, code, status) {
  await assert.rejects(fn, error => {
    assert.ok(error instanceof RollbackError);
    assert.equal(error.code, code);
    if (status) assert.equal(error.status, status);
    return true;
  });
}

test("authoritative case target only; exact /32 removed with others and description preserved", async () => {
  const { service, waf, s3 } = fixture();
  waf.beforeUpdate = () => {
    const pending = [...s3.objects.values()].map(value => JSON.parse(value.body));
    assert.equal(pending[0].action, "attempted");
    assert.equal(pending[0].identity_verified, true);
    assert.equal(pending[0].requested_by, "verified-operator-sub");
  };
  const reply = await service.rollback(body(), { peer: "10.0.0.7" });
  assert.equal(reply.status, "removed");
  assert.equal(reply.ip, "203.0.113.9");
  assert.deepEqual(waf.addresses, ["198.51.100.17/32", "203.0.113.0/24"]);
  assert.equal(waf.writes()[0].input.Description, "Preserve this description");
  assert.deepEqual(reply.remaining_matching_cidrs, ["203.0.113.0/24"]);
  assert.match(reply.limitation, /NACL/);
  const record = JSON.parse(s3.objects.get(reply.audit_key).body);
  assert.equal(record.action, "completed");
  assert.equal(record.network_peer, "10.0.0.7");
  assert.equal(record.result.status, "removed");
  const puts = s3.calls.filter(command => command instanceof PutObjectCommand);
  assert.equal(puts[0].input.IfNoneMatch, "*");
  assert.equal(puts[1].input.IfMatch, '"etag-1"');
});

test("snapshot reads trusted tier, target, exact membership and current LockToken", async () => {
  const { service, waf } = fixture();
  const reply = await service.getSnapshot(KEY);
  assert.equal(reply.eligible, true);
  assert.equal(reply.ip, "203.0.113.9");
  assert.equal(reply.expected_lock_token, "lock-1");
  waf.addresses = ["203.0.113.0/24"];
  const rangeOnly = await service.getSnapshot(KEY);
  assert.equal(rangeOnly.eligible, false);
  assert.deepEqual(rangeOnly.remaining_matching_cidrs, ["203.0.113.0/24"]);
});

test("AUTO_BLOCK_FAILED and AUTO_ISOLATION_FAILED permit rollback of existing exact WAF entry", async () => {
  for (const status of ["AUTO_BLOCK_FAILED", "AUTO_BLOCK_PARTIAL", "AUTO_ISOLATION_FAILED"]) {
    const f = fixture();
    f.setReview({ ok: true, case_id: CASE_ID, tier: status === "AUTO_BLOCK_FAILED" ? 1 : 0, status, target: { source_ip: "203.0.113.9" } });
    assert.equal((await f.service.getSnapshot(KEY)).eligible, true);
    assert.equal((await f.service.rollback(body())).status, "removed");
  }
});

test("terminal AUTO_BLOCK_UNVERIFIED allows recovery only for the authoritative exact host and fresh LockToken", async () => {
  const f = fixture();
  f.setReview({ ok: true, case_id: CASE_ID, tier: 1, status: "AUTO_BLOCK_UNVERIFIED", target: { source_ip: "203.0.113.9" } });
  const snapshot = await f.service.getSnapshot(KEY);
  assert.equal(snapshot.eligible, true);
  assert.equal(snapshot.status, "AUTO_BLOCK_UNVERIFIED");
  await rejected(() => f.service.rollback(body({ expected_lock_token: "stale-lock" })), "conflict", 409);
  assert.equal(f.waf.writes().length, 0);
  assert.equal(f.s3.objects.size, 0);
  const result = await f.service.rollback(body({ expected_lock_token: snapshot.expected_lock_token }));
  assert.equal(result.status, "removed");
  assert.equal(result.ip, "203.0.113.9");
  assert.deepEqual(f.waf.addresses, ["198.51.100.17/32", "203.0.113.0/24"]);
});

test("HITL, missing target, wrong case, noncanonical and in-progress cases fail closed", async () => {
  for (const [changes, code] of [
    [{ tier: 2 }, "not_hotl"], [{ tier: "1" }, "not_hotl"],
    [{ target: {} }, "target_unavailable"], [{ target: { source_ip: "203.0.113.9/32" } }, "target_unavailable"],
    [{ target: { source_ip: "203.000.113.9" } }, "target_unavailable"],
    [{ status: "TRIAGED" }, "case_in_progress"], [{ status: "UNKNOWN" }, "case_in_progress"],
    [{ status: "AWAITING_APPROVAL" }, "case_in_progress"], [{ status: "WAF_CALL_STARTED" }, "case_in_progress"],
    [{ status: "AUTO_BLOCK_IN_PROGRESS" }, "case_in_progress"],
    [{ case_id: "inv-" + "b".repeat(32) }, "case_unavailable"],
  ]) {
    const f = fixture();
    f.setReview({ ok: true, case_id: CASE_ID, tier: 1, status: "AUTO_BLOCKED", target: { source_ip: "203.0.113.9" }, ...changes });
    await rejected(() => f.service.rollback(body()), code);
    assert.equal(f.waf.writes().length, 0);
    assert.equal(f.s3.objects.size, 0);
  }
});

test("client-supplied IP, ARN or identity and unsafe report keys are rejected before AWS calls", async () => {
  for (const invalid of [body({ ip: "198.51.100.17" }), body({ ipSetArn: ARN }), body({ by: "admin" }),
    body({ key: "../" + KEY }), body({ reason: " " }), body({ request_id: "invalid-id" }), body({ expected_lock_token: "" })]) {
    const f = fixture();
    await assert.rejects(() => f.service.rollback(invalid), RollbackError);
    assert.equal(f.reviewCalls.length, 0);
    assert.equal(f.waf.calls.length, 0);
  }
});

test("stale dashboard LockToken returns 409 without overwriting concurrent changes", async () => {
  const { service, waf, s3 } = fixture();
  waf.addresses.push("192.0.2.22/32");
  waf.token = "lock-2";
  await rejected(() => service.rollback(body()), "conflict", 409);
  assert.equal(waf.writes().length, 0);
  assert.equal(s3.objects.size, 0);
  assert.ok(waf.addresses.includes("192.0.2.22/32"));
});

test("WAF optimistic lock protects a change arriving after the read", async () => {
  const { service, waf, s3 } = fixture();
  waf.concurrentIp = "192.0.2.23/32";
  await rejected(() => service.rollback(body()), "conflict", 409);
  assert.ok(waf.addresses.includes("203.0.113.9/32"));
  assert.ok(waf.addresses.includes("192.0.2.23/32"));
  assert.equal(JSON.parse([...s3.objects.values()][0].body).action, "attempted");
});

test("pending audit write failure or audit read failure prevents WAF mutation", async () => {
  for (const fail of ["failPending", "failRead"]) {
    const { service, waf, s3 } = fixture();
    s3[fail] = true;
    await assert.rejects(() => service.rollback(body()), { name: "AccessDenied" });
    assert.equal(waf.writes().length, 0);
  }
});

test("WAF success and audit failure is reported and same-request retry recovers without second removal", async () => {
  const { service, waf, s3, logs } = fixture();
  s3.failComplete = 1;
  await assert.rejects(() => service.rollback(body()), error => {
    assert.equal(error.code, "audit_incomplete");
    assert.equal(error.details.outcome.status, "removed");
    assert.equal(error.details.retry_same_request, true);
    return true;
  });
  assert.equal(waf.writes().length, 1);
  assert.equal(logs[0][0], "WAF_ROLLBACK_AUDIT_GAP");
  const result = await service.rollback(body());
  assert.equal(result.status, "already_absent");
  assert.equal(result.audit_recovered, true);
  assert.equal(waf.writes().length, 1);
  assert.equal(JSON.parse(s3.objects.get(result.audit_key).body).action, "completed");
});

test("same UUID binds reason, lock and current authoritative target; completed replay does not delete a new block", async () => {
  const f = fixture();
  await f.service.rollback(body());
  f.waf.addresses.push("203.0.113.9/32");
  f.waf.token = "lock-3";
  const replay = await f.service.rollback(body());
  assert.equal(replay.idempotent, true);
  assert.ok(f.waf.addresses.includes("203.0.113.9/32"));
  assert.equal(f.waf.writes().length, 1);
  for (const change of [{ reason: "다른 사유" }, { expected_lock_token: "lock-3" }]) {
    await rejected(() => f.service.rollback(body(change)), "request_id_conflict", 409);
  }
  f.setReview({ ok: true, case_id: CASE_ID, tier: 1, status: "AUTO_BLOCKED", target: { source_ip: "198.51.100.17" } });
  await rejected(() => f.service.rollback(body()), "request_id_conflict", 409);
});

test("a new block after incomplete audit is preserved and requires a fresh user decision", async () => {
  const { service, waf, s3 } = fixture();
  s3.failComplete = 1;
  await rejected(() => service.rollback(body()), "audit_incomplete", 503);
  waf.addresses.push("203.0.113.9/32");
  waf.token = "lock-3";
  await rejected(() => service.rollback(body()), "conflict", 409);
  assert.ok(waf.addresses.includes("203.0.113.9/32"));
  assert.equal(waf.writes().length, 1);
});

test("already absent host is audited without deleting a matching broad subnet", async () => {
  const { service, waf } = fixture();
  waf.addresses = ["203.0.113.0/24", "198.51.100.17/32"];
  const result = await service.rollback(body());
  assert.equal(result.status, "already_absent");
  assert.deepEqual(result.remaining_matching_cidrs, ["203.0.113.0/24"]);
  assert.equal(waf.writes().length, 0);
});

test("wrong WAF identity and mismatched fixed ARN configuration fail closed", async () => {
  const f = fixture();
  f.waf.arn = ARN.replace("123456789012", "999999999999");
  await rejected(() => f.service.rollback(body()), "invalid_ipset", 502);
  assert.equal(f.waf.writes().length, 0);
  const bad = createWafRollback({ waf: f.waf, s3: f.s3, bucket: "reports", wafArn: ARN.replace("us-east-1", "ap-northeast-2"),
    wafName: "security-example-ipv4", wafId: ID, reviewStatus: f.reviewStatus, commands });
  await rejected(() => bad.rollback(body()), "invalid_configuration", 503);
});

test("single-process concurrency is bounded and released after a failed attempt", async () => {
  const { service, waf } = fixture();
  let release;
  waf.onRead = () => new Promise(resolve => { release = resolve; });
  const pending = service.rollback(body());
  while (!release) await new Promise(resolve => setImmediate(resolve));
  await rejected(() => service.rollback(body({ request_id: "abcdef12-1234-4234-8234-123456789abc" })), "busy", 409);
  waf.onRead = null;
  release();
  await pending;
  assert.equal((await service.rollback(body())).idempotent, true);
});

function browserRequest(headers = {}, contentType = "application/json") {
  const values = { "sec-fetch-site": "same-origin", origin: "http://dashboard:3000", host: "dashboard:3000", ...headers };
  return { protocol: "http", get: name => values[name], is: type => type === contentType };
}
test("browser protection requires Origin and JSON, validates available metadata, and supports HTTPS proxy termination", () => {
  requireSameOrigin(browserRequest());
  requireSameOrigin(browserRequest({ "sec-fetch-site": undefined }));
  requireSameOrigin(browserRequest({ origin: "https://dashboard:3000" }));
  requireSameOrigin(browserRequest({ origin: "https://dashboard.example" }), "https://dashboard.example");
  for (const headers of [{ "sec-fetch-site": "cross-site" }, { "sec-fetch-site": "same-site" }, { "sec-fetch-site": "none" },
    { origin: undefined }, { origin: "http://evil.example" }, { origin: "http://dashboard:3000/" }]) {
    assert.throws(() => requireSameOrigin(browserRequest(headers)), error => error.status === 403);
  }
  assert.throws(() => requireSameOrigin(browserRequest({ origin: "http://dashboard.example" }), "https://dashboard.example"), error => error.status === 403);
  assert.throws(() => requireSameOrigin(browserRequest({ origin: "http://dashboard:3000", "sec-fetch-site": undefined }), "https://dashboard:3000"), error => error.status === 403);
  assert.throws(() => requireSameOrigin(browserRequest({}, "text/plain")), error => error.status === 415);
});

function loadServer(f, env = {}) {
  const service = { service_id: SERVICE_ID, revision: "revision-one", audit_bucket: "report-bucket", reportBucket: "report-bucket", allowed_actions: ["monitor", "block_ip"], response_mode: "enforce", manual_block_enabled: true, can_admin: true,
    waf: { arn: ARN, name: "security-example-ipv4", id: ID, region: "us-east-1", scope: "CLOUDFRONT", family: 4 } };
  const routes = new Map();
  const middleware = [];
  const app = {
    disable() {},
    use(fn) { middleware.push(fn); },
    get(route, fn) { routes.set("GET " + route, fn); },
    post(route, fn) { routes.set("POST " + route, fn); },
    listen() {},
  };
  function express() { return app; }
  express.static = () => (req, res, next) => next();
  express.json = () => Object.assign((req, res, next) => next(), { jsonParser: true });
  const lambda = { send: async command => {
    const request = JSON.parse(Buffer.from(command.input.Payload).toString());
    const reply = f.invokeApproval ? await f.invokeApproval(request) : await f.reviewStatus(request.key);
    return { StatusCode: 200, Payload: Buffer.from(JSON.stringify(reply)) };
  } };
  const requireMock = name => {
    if (name === "express") return express;
    if (name === "path") return path;
    if (name.startsWith("node:")) return require(name);
    if (name === "./markdown") return { renderMarkdown: async value => value };
    if (name === "@aws-sdk/client-s3") return { S3Client: function () { return f.s3; }, GetObjectCommand, PutObjectCommand, ListObjectsV2Command };
    if (name === "@aws-sdk/client-wafv2") return { WAFV2Client: function () { return f.waf; }, GetIPSetCommand, UpdateIPSetCommand };
    if (name === "@aws-sdk/client-sfn") return { SFNClient: function () { return { send: async () => ({}) }; }, StartExecutionCommand, DescribeExecutionCommand };
    if (name === "@aws-sdk/client-lambda") return { LambdaClient: function () { return lambda; }, InvokeCommand };
    if (name === "./waf-rollback") return { createWafRollback, requireSameOrigin, RollbackError };
    if (name === "./auth") return {
      createDynamoSessionStore: () => null,
      createDashboardAuth: () => ({ configured: true, install() {}, rejectClientActor: (req, res, next) => next() }),
    };
    if (name === "./content-security") return { sanitizeReportHtml: value => value, securityHeaders: (req, res, next) => next() };
    if (name === "./case-key") return require("../case-key.js");
    if (name === "./ip-utils") return require("../ip-utils.js");
    if (name === "./request-errors") return require("../request-errors.js");
    if (name === "./service-registry") return { createServiceResolver: () => ({ resolve: async () => service, list: async () => [service] }) };
    if (name === "@aws-sdk/client-dynamodb") return { DynamoDBClient: function () {} };
    if (name === "@aws-sdk/lib-dynamodb") return { DynamoDBDocumentClient: { from() { return {}; } }, GetCommand: function () {}, PutCommand: function () {}, DeleteCommand: function () {} };
    throw new Error("Unexpected dependency " + name);
  };
  const serverPath = path.join(__dirname, "../server.js");
  vm.runInNewContext(fs.readFileSync(serverPath, "utf8"), {
    require: requireMock, module: { exports: {} }, process: { env: { REPORT_BUCKET: "report-bucket", WAF_IPSET_ARN: ARN, WAF_IPSET_NAME: "security-example-ipv4", WAF_IPSET_ID: ID, APPROVE_FUNCTION_NAME: "approval", ...env } }, __dirname: path.dirname(serverPath),
    console: { log() {}, error() {} }, Buffer, URL, setTimeout,
  }, { filename: serverPath });
  return { routes, middleware, service };
}
function response() {
  return { statusCode: 200, headers: {}, status(value) { this.statusCode = value; return this; },
    set(name, value) { this.headers[name] = value; return this; }, json(value) { this.body = value; },
    send(value) { this.body = value; }, redirect(value) { this.redirected = value; } };
}

test("actual POST route uses the authoritative case even when report Markdown names another IP", async () => {
  const f = fixture();
  f.s3.objects.set(KEY, { etag: '"report"', body: "---\ntier: 1\nattackerIp: 198.51.100.17\n---\n- **대상 IP**: `198.51.100.17`" });
  const { routes, service } = loadServer(f);
  const res = response();
  await routes.get("POST /api/rollback-ip")({ body: body(), socket: { remoteAddress: "10.0.0.7" }, service, auth: { sub: "verified-operator-sub", issuer: "https://idp.example/pool", admin: true } }, res);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.ip, "203.0.113.9");
  assert.ok(f.waf.addresses.includes("198.51.100.17/32"));
});

test("actual HOTL page has enabled rollback, mandatory reason, safe inline state and syntactically valid script", async () => {
  const f = fixture();
  f.s3.objects.set(KEY, { etag: '"report"', body: "---\ntier: 1\n---\n# Report" });
  const { routes, service } = loadServer(f);
  const res = response();
  await routes.get("GET /report")({ query: { key: KEY }, service, caseReview: await f.reviewStatus(KEY), auth: { admin: true } }, res);
  assert.equal(res.statusCode, 200);
  assert.match(res.body, /id="rollback-btn" >사용자 차단 롤백/);
  assert.match(res.body, /차단 롤백 사유 \(필수\)/);
  assert.match(res.body, /롤백 대상 IP \(사건 저장소\)/);
  assert.match(res.body, /203\.0\.113\.9/);
  assert.match(res.body, /NACL·임시 WAF·범위 차단/);
  const scripts = [...res.body.matchAll(/<script>([\s\S]*?)<\/script>/g)];
  assert.equal(scripts.length, 3);
  scripts.forEach(script => new vm.Script(script[1]));
  assert.equal(res.headers["Cache-Control"], "no-store");
});

test("actual page disables rollback when authoritative target or WAF membership is absent", async () => {
  for (const unknown of [true, false]) {
    const f = fixture();
    f.s3.objects.set(KEY, { etag: '"report"', body: "---\ntier: 1\n---\n# Report" });
    if (unknown) f.setReview({ ok: true, case_id: CASE_ID, tier: 1, status: "AUTO_BLOCKED", target: {} });
    else f.waf.addresses = [];
    const { routes, service } = loadServer(f);
    const res = response();
    await routes.get("GET /report")({ query: { key: KEY }, service, caseReview: await f.reviewStatus(KEY), auth: { admin: true } }, res);
    assert.match(res.body, /id="rollback-btn" disabled/);
  }
});

test("actual new route is guarded before JSON parser for cross-origin or missing metadata requests", async () => {
  const { middleware } = loadServer(fixture());
  const guard = middleware[2];
  const bad = { ...browserRequest({ "sec-fetch-site": "cross-site" }), method: "POST", path: "/api/rollback-ip" };
  const res = response();
  let nextCalled = false;
  guard(bad, res, () => { nextCalled = true; });
  assert.equal(res.statusCode, 403);
  assert.equal(nextCalled, false);
});

test("rollback audit UUID binds the verified actor and cannot be replayed by another administrator", async () => {
  const { service } = fixture();
  await service.rollback(body());
  await rejected(() => service.rollback(body(), { actor: "different-operator" }), "request_id_conflict", 409);
});

test("regional WAF uses the parsed scope and still removes only the exact host", async () => {
  const f = fixture();
  const regional = ARN.replace("us-east-1", "ap-northeast-2").replace(":global/", ":regional/");
  f.waf.arn = regional;
  f.waf.scope = "REGIONAL";
  const core = createWafRollback({ waf: f.waf, s3: f.s3, bucket: "report-bucket", wafArn: regional, wafName: "security-example-ipv4", wafId: ID,
    reviewStatus: f.reviewStatus, serviceId: SERVICE_ID, registryRevision: "one", commands });
  const result = await core.rollback(body(), { actor: "verified-sub", issuer: "https://idp.example/pool" });
  assert.equal(result.status, "removed");
  assert.equal(f.waf.writes()[0].input.Scope, "REGIONAL");
  assert.ok(f.waf.addresses.includes("198.51.100.17/32"));
});

test("manual HITL block uses authoritative service target and writes a verified pending audit before WAF", async () => {
  const f = fixture();
  f.setReview({ ok: true, case_id: CASE_ID, tier: 2, status: "DECIDED_APPROVE", decision: "approve", callback_status: "SENT", approved_action: "block_ip", target: { source_ip: "192.0.2.18" } });
  const { routes, service } = loadServer(f, { MANUAL_IP_BLOCK_ENDPOINT_ENABLED: "true" });
  f.waf.beforeUpdate = () => {
    const audit = [...f.s3.objects.values()].map(value => JSON.parse(value.body))[0];
    assert.equal(audit.action, "attempted");
    assert.equal(audit.by, "verified-sub");
    assert.equal(audit.ip, "192.0.2.18");
    assert.equal(audit.service_id, SERVICE_ID);
  };
  const req = { body: { key: KEY, reason: "증거 확인 완료", request_id: REQUEST_ID }, service, caseReview: await f.reviewStatus(KEY),
    auth: { sub: "verified-sub", issuer: "https://idp.example/pool", admin: true } };
  const res = response();
  await routes.get("POST /api/block-ip")(req, res);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.status, "blocked");
  assert.ok(f.waf.addresses.includes("192.0.2.18/32"));
  assert.ok(f.waf.addresses.includes("203.0.113.9/32"));
  assert.equal(f.waf.writes()[0].input.Description, "Preserve this description");
});

test("manual block retries an audit gap without another WAF write", async () => {
  const f = fixture();
  f.setReview({ ok: true, case_id: CASE_ID, tier: 2, status: "DECIDED_APPROVE", decision: "approve", callback_status: "SENT", approved_action: "block_ip", target: { source_ip: "192.0.2.19" } });
  const { routes, service } = loadServer(f, { MANUAL_IP_BLOCK_ENDPOINT_ENABLED: "true" });
  const req = { body: { key: KEY, reason: "증거 확인", request_id: REQUEST_ID }, service, caseReview: await f.reviewStatus(KEY),
    auth: { sub: "verified-sub", issuer: "https://idp.example/pool", admin: true } };
  f.s3.failComplete = 1;
  const first = response();
  await routes.get("POST /api/block-ip")(req, first);
  assert.equal(first.statusCode, 503);
  assert.equal(first.body.code, "audit_incomplete");
  assert.equal(first.body.retry_same_request, true);
  const second = response();
  await routes.get("POST /api/block-ip")(req, second);
  assert.equal(second.statusCode, 200);
  assert.equal(second.body.status, "already_present");
  assert.equal(f.waf.writes().length, 1);
});

test("generic deployment denies direct manual block before any AWS read or write", async () => {
  const f = fixture();
  const { routes, service, middleware } = loadServer(f);
  const req = { method: "POST", path: "/api/block-ip", body: {}, service, auth: { sub: "verified-sub", admin: true } };
  const res = response();
  await routes.get("POST /api/block-ip")(req, res);
  assert.equal(res.statusCode, 405);
  assert.equal(res.body.code, "workflow_approval_required");
  assert.equal(f.waf.writes().length, 0);
  assert.equal(f.s3.objects.size, 0);
  // The middleware also rejects before case reads and registry resolution.
  const guarded = response();
  const gate = middleware.find(fn => String(fn).includes("workflow_approval_required"));
  assert.ok(gate);
  assert.ok(middleware.indexOf(gate) < middleware.findIndex(fn => fn.jsonParser));
  gate(req, guarded, () => { throw new Error("Disabled endpoint must not continue"); });
  assert.equal(guarded.statusCode, 405);
});

test("generic profile and nonlegacy opt-in have no forensic S3 reads or PDF links", async () => {
  for (const env of [{}, { FORENSIC_REPORTS_ENABLED: "true", DEFAULT_SERVICE_ID: SERVICE_ID }]) {
    const f = fixture();
    f.s3.objects.set(KEY, { etag: '"report"', body: "---\ntier: 1\n---\n# Report" });
    const { routes, service } = loadServer(f, env);
    const page = response();
    await routes.get("GET /report")({ query: { key: KEY }, service, caseReview: await f.reviewStatus(KEY), auth: { admin: true } }, page);
    assert.match(page.body, /현재 설치에서는 포렌식 보고서를 지원하지 않습니다/);
    assert.doesNotMatch(page.body, /href="\/forensic|PDF 원본 보기/);
    for (const route of ["GET /forensic", "GET /forensic.pdf"]) {
      const res = response();
      await routes.get(route)({ query: { case: CASE_ID, isolation: "a".repeat(64) }, service, auth: { admin: true } }, res);
      assert.equal(res.statusCode, 404);
      assert.equal(res.body.code, "forensic_reports_not_supported");
    }
    assert.equal(f.s3.calls.some(command => String(command.input.Prefix || command.input.Key || "").startsWith("forensic/")), false);
  }
});

test("HITL approve resumes the existing callback with verified sub and never reads model prose or starts a new SFN", async () => {
  const f = fixture();
  const calls = [];
  const review = { ok: true, case_id: CASE_ID, service_id: SERVICE_ID, tier: 2, status: "AWAITING_APPROVAL", pending: true, target: { source_ip: "203.0.113.9" } };
  f.invokeApproval = async request => { calls.push(request); return { ok: true, decision: "approve" }; };
  const { routes, service } = loadServer(f);
  const req = { body: { key: KEY, action: "approve", note: "검토 완료" }, service, caseReview: review,
    auth: { sub: "verified-sub", issuer: "https://idp.example/pool", admin: true } };
  const res = response();
  await routes.get("POST /api/decision")(req, res);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.decision, "approve");
  assert.deepEqual(calls, [{ key: KEY, decision: "approve", user: "verified-sub", reason: "검토 완료" }]);
  assert.equal(f.s3.calls.some(command => command instanceof GetObjectCommand && command.input.Key === KEY), false);
});

test("case service prefix cannot be swapped to operate on the same case under another registered service", async () => {
  const f = fixture();
  const { middleware } = loadServer(f);
  const guard = middleware.find(fn => fn.toString().includes("CASE_SERVICE_BINDING_FAILED"));
  const res = response();
  let next = false;
  await guard({ method: "POST", path: "/api/rollback-ip", body: body({ key: "other-service/" + CASE_ID + ".md" }), auth: { admin: true, groups: ["security-admins"] } }, res, () => { next = true; });
  assert.equal(res.statusCode, 404);
  assert.equal(next, false);
  assert.equal(f.waf.writes().length, 0);
});

test("IPv6 rollback removes the exact /128 while keeping other hosts and the matching /64", async () => {
  const f = fixture();
  f.setReview({ ok: true, case_id: CASE_ID, tier: 1, status: "AUTO_BLOCK_PARTIAL", target: { source_ip: "2001:db8::1" } });
  f.waf.family = 6;
  f.waf.addresses = ["2001:0db8:0000:0000:0000:0000:0000:0001/128", "2001:db8::2/128", "2001:db8::/64"];
  const core = createWafRollback({ waf: f.waf, s3: f.s3, bucket: "report-bucket", wafArn: ARN, wafName: "security-example-ipv4", wafId: ID,
    reviewStatus: f.reviewStatus, serviceId: SERVICE_ID, registryRevision: "one", wafFamily: 6, commands });
  const result = await core.rollback(body(), { actor: "verified-sub", issuer: "https://idp.example/pool" });
  assert.equal(result.cidr, "2001:db8::1/128");
  assert.equal(result.status, "removed");
  assert.deepEqual(f.waf.addresses, ["2001:db8::2/128", "2001:db8::/64"]);
  assert.deepEqual(result.remaining_matching_cidrs, ["2001:db8::/64"]);
});
