const express = require("express");
const path = require("path");
const { createHash } = require("node:crypto");
const { renderMarkdown } = require("./markdown");
const {
  S3Client,
  GetObjectCommand,
  PutObjectCommand,
  ListObjectsV2Command,
} = require("@aws-sdk/client-s3");
const {
  SFNClient,
  StartExecutionCommand,
  DescribeExecutionCommand,
} = require("@aws-sdk/client-sfn");
const { WAFV2Client, GetIPSetCommand, UpdateIPSetCommand } = require("@aws-sdk/client-wafv2");
const { LambdaClient, InvokeCommand } = require("@aws-sdk/client-lambda");
const { createWafRollback, requireSameOrigin, RollbackError } = require("./waf-rollback");
const { createDashboardAuth, createDynamoSessionStore } = require("./auth");
const { sanitizeReportHtml, securityHeaders } = require("./content-security");
const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const { DynamoDBDocumentClient, GetCommand, PutCommand, DeleteCommand, ScanCommand } = require("@aws-sdk/lib-dynamodb");
const { createServiceResolver } = require("./service-registry");
const { parseCaseKey } = require("./case-key");
const { parseIp, parseNetwork, exactHost } = require("./ip-utils");
const { createRequestErrorHandler } = require("./request-errors");

const app = express();
const PORT = process.env.PORT || 3000;
const REGION = process.env.AWS_REGION || "ap-northeast-2";

const REPORT_BUCKET = process.env.REPORT_BUCKET;
// 기태 격리 Step Functions (WHS-CredentialExfiltration)
const STATE_MACHINE_ARN = process.env.STATE_MACHINE_ARN;
// 대시보드 자기 자신은 절대 격리하면 안 됨
const DASHBOARD_INSTANCE_ID = process.env.DASHBOARD_INSTANCE_ID;
const DECISION_PREFIX = "decisions/";
const APPROVE_FUNCTION_NAME = process.env.APPROVE_FUNCTION_NAME;
// New installations execute approved blocks through the committed SFN path.
// A legacy deployment may explicitly retain its separate direct-block route.
const MANUAL_IP_BLOCK_ENDPOINT_ENABLED = process.env.MANUAL_IP_BLOCK_ENDPOINT_ENABLED === "true";
const FORENSIC_REPORTS_ENABLED = process.env.FORENSIC_REPORTS_ENABLED === "true" && process.env.DEFAULT_SERVICE_ID === "legacy-whs";
const forensicEnabledFor = service => FORENSIC_REPORTS_ENABLED && service?.service_id === "legacy-whs";
const REVIEW_KEY_RE = /^(?:[a-z][a-z0-9-]{2,47}\/)?inv-[0-9a-f]{32}\.md$/;
const CASE_ID_RE = /^inv-[0-9a-f]{32}$/;
const ISOLATION_ID_RE = /^[0-9a-f]{64}$/;
const FORENSIC_KEY_RE = /^forensic\/(inv-[0-9a-f]{32})\/([0-9a-f]{64})\/report\.json$/;
const MAX_DASHBOARD_REPORTS = 100;
const rejectRequests = new Set();
const isolateRequests = new Set();

// Permanent WAF resources are resolved from the trusted service registry.

const s3 = new S3Client({ region: REGION });
const sfn = new SFNClient({ region: REGION });
const approvalLambda = new LambdaClient({ region: REGION });
const documentClient = DynamoDBDocumentClient.from(new DynamoDBClient({ region: REGION }));
const sessionStore = createDynamoSessionStore({
  client: documentClient, tableName: process.env.SESSION_TABLE,
  commands: { GetCommand, PutCommand, DeleteCommand },
});
const dashboardAuth = createDashboardAuth({ store: sessionStore });
const serviceResolver = createServiceResolver({
  client: documentClient, tableName: process.env.SERVICE_REGISTRY_TABLE, companyAccountId: process.env.COMPANY_ACCOUNT_ID,
  GetCommand, ScanCommand, reportBucket: REPORT_BUCKET,
});
const wafClients = new Map();
const rollbackServices = new Map();
function serviceWaf(service) {
  if (!service?.waf) throw new RollbackError(409, "waf_unbound", "사건 서비스에 등록된 WAF IPSet이 없습니다.");
  if (!wafClients.has(service.waf.region)) wafClients.set(service.waf.region, new WAFV2Client({ region: service.waf.region }));
  return wafClients.get(service.waf.region);
}
function rollbackFor(service) {
  const cacheKey = JSON.stringify([service.service_id, service.revision, service.waf?.arn, service.audit_bucket]);
  if (!rollbackServices.has(cacheKey)) {
    if (rollbackServices.size >= 128) rollbackServices.delete(rollbackServices.keys().next().value);
    rollbackServices.set(cacheKey, createWafRollback({
      waf: serviceWaf(service), s3, bucket: service.audit_bucket, wafArn: service.waf.arn, wafName: service.waf.name,
      wafId: service.waf.id, serviceId: service.service_id, registryRevision: service.revision, wafFamily: service.waf.family || 4, reviewStatus,
      commands: { GetIPSetCommand, UpdateIPSetCommand, GetObjectCommand, PutObjectCommand },
    }));
  }
  return rollbackServices.get(cacheKey);
}

app.disable("x-powered-by");
// PUBLIC_ORIGIN is explicit; forwarded headers are never trusted for identity,
// scheme, issuer, or CSRF decisions. TLS can terminate at the approved proxy.
app.use(securityHeaders);
dashboardAuth.install(app);
app.use(express.static(path.join(__dirname, "public")));
// Browser request protection is not operator authentication. Keep the existing
// network boundary until application login/role checks are deployed.
app.use((req, res, next) => {
  if (req.method !== "POST" || req.path !== "/api/rollback-ip") return next();
  try {
    requireSameOrigin(req, process.env.PUBLIC_ORIGIN || process.env.DASHBOARD_ORIGIN);
    next();
  } catch (error) {
    res.status(error.status || 403).json({ ok: false, code: error.code || "cross_origin", message: error.message });
  }
});
app.use((req, res, next) => {
  if (req.method === "POST" && req.path === "/api/block-ip" && !MANUAL_IP_BLOCK_ENDPOINT_ENABLED) {
    return res.status(405).json({ ok: false, code: "workflow_approval_required",
      message: "대응 승인을 통해 IP 차단을 실행합니다." });
  }
  next();
});
app.use(express.json());
app.use(dashboardAuth.rejectClientActor);
app.use(async (req, res, next) => {
  const cases = new Set(["/report", "/forensic", "/forensic.pdf", "/api/decision", "/api/reject", "/api/block-ip", "/api/rollback-ip", "/api/review-status", "/api/execution-status"]);
  if (!cases.has(req.path)) return next();
  const key = req.method === "POST" ? req.body?.key : ["/forensic", "/forensic.pdf"].includes(req.path) ? req.query.key || `${req.query.service}/${req.query.case}.md` : req.query.key;
  const identity = parseCaseKey(key);
  if (!identity) return res.status(400).json({ ok: false, message: "서비스에 연결된 유효한 사건 보고서 키가 필요합니다." });
  try {
    const review = await reviewStatus(key);
    if (!review.ok || review.case_id !== identity.caseId || review.service_id !== identity.serviceId) return res.status(404).json({ ok: false, message: "사건과 서비스 연결을 확인하지 못했습니다." });
    const action = req.method !== "POST" ? "read" : req.path === "/api/block-ip" ? "block" : req.path === "/api/rollback-ip" ? "rollback" : req.body.action === "approve" ? "approve" : "decide";
    req.service = await serviceResolver.resolve(review, req.auth, action);
    req.caseReview = review;
    req.caseKey = key;
    if (["/forensic", "/forensic.pdf"].includes(req.path) && (req.query.case !== identity.caseId || req.query.service !== identity.serviceId)) {
      return res.status(403).json({ ok: false, message: "포렌식 보고서와 사건 서비스가 일치하지 않습니다." });
    }
    next();
  } catch (error) {
    if (error instanceof RollbackError) return res.status(error.status).json({ ok: false, code: error.code, message: error.message });
    console.error("CASE_SERVICE_BINDING_FAILED", error.name);
    res.status(503).json({ ok: false, message: "사건 서비스 등록부를 확인하지 못했습니다." });
  }
});
// Apply browser request protections to the new API and cached legacy reject requests.
app.use((req, res, next) => {
  if (req.method !== "POST" || !(req.path === "/api/reject" ||
      (req.path === "/api/decision" && req.body?.action === "reject"))) return next();
  const site = req.get("sec-fetch-site");
  if (site && !["same-origin", "none"].includes(site)) {
    return res.status(403).json({ ok: false, message: "같은 대시보드에서 보낸 요청만 허용합니다." });
  }
  const origin = req.get("origin");
  if (origin) {
    try {
      const value = new URL(origin);
      if (!["http:", "https:"].includes(value.protocol) || value.host !== req.get("host")) {
        return res.status(403).json({ ok: false, message: "요청 출처가 대시보드와 다릅니다." });
      }
    } catch {
      return res.status(403).json({ ok: false, message: "요청 출처를 확인할 수 없습니다." });
    }
  }
  if (!req.is("application/json")) {
    return res.status(415).json({ ok: false, message: "JSON 요청이 필요합니다." });
  }
  next();
});

// ---------------------------------------------------------------- 유틸
const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const inlineJson = (value) => JSON.stringify(value).replace(/[<>&\u2028\u2029]/g,
  (character) => "\\u" + character.charCodeAt(0).toString(16).padStart(4, "0"));

const INSTANCE_RE = /^i-[0-9a-f]{8,17}$/;
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

// 리포트 맨 위 --- ... --- 부분(frontmatter)을 읽어서 { meta, body }로 나눔
function parseReport(markdown) {
  const meta = {};
  let body = markdown;
  const m = markdown.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/);
  if (m) {
    body = markdown.slice(m[0].length);
    for (const line of m[1].split(/\r?\n/)) {
      const kv = line.replace(/\s+#.*$/, "").match(/^\s*([A-Za-z_]+)\s*:\s*(.*?)\s*$/);
      if (kv) meta[kv[1]] = kv[2].replace(/^["']|["']$/g, "");
    }
  }
  // frontmatter가 없을 때 본문에서 최대한 찾아보기
  if (!meta.tier) {
    const t = markdown.match(/Tier\s*([123])/i);
    if (t) meta.tier = t[1];
  }
  if (!meta.instanceId) {
    const i = markdown.match(/\bi-[0-9a-f]{8,17}\b/);
    if (i) meta.instanceId = i[0];
  }
  // Older AI reports omit attackerIp in frontmatter. Show their explicitly named
  // target IP as context only; never use model-written prose for response actions.
  if (!meta.attackerIp) {
    const lines = [...body.matchAll(/^- \*\*대상 IP\*\*:\s*`?(\d{1,3}(?:\.\d{1,3}){3})`?\s*$/gm)];
    if (lines.length === 1 && IPV4_RE.test(lines[0][1])) meta.reportedIp = lines[0][1];
  }
  return { meta, body };
}

async function listReports(services) {
  const reports = [];
  for (const service of services) {
    const prefixes = [service.service_id + "/"];
    if (process.env.DEFAULT_SERVICE_ID === service.service_id) prefixes.push("inv-");
    for (const prefix of prefixes) {
      let continuationToken;
      do {
        const response = await s3.send(new ListObjectsV2Command({ Bucket: service.reportBucket, Prefix: prefix, ContinuationToken: continuationToken }));
        for (const object of response.Contents || []) {
          const identity = parseCaseKey(object.Key);
          if (identity?.serviceId === service.service_id) reports.push({ ...object, service });
        }
        continuationToken = response.IsTruncated ? response.NextContinuationToken : undefined;
        if (response.IsTruncated && !continuationToken) throw new Error("S3PaginationTokenMissing");
      } while (continuationToken);
    }
  }
  return reports.sort((left, right) => new Date(right.LastModified) - new Date(left.LastModified)).slice(0, MAX_DASHBOARD_REPORTS);
}

async function getText(key, bucket = REPORT_BUCKET) {
  const resp = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
  return await resp.Body.transformToString();
}

// Only a published report under this exact case is eligible for the dashboard.
// The forensic workflow writes the JSON and PDF as sibling objects.
async function forensicReports(caseId, bucket = REPORT_BUCKET) {
  if (!CASE_ID_RE.test(caseId || "")) return [];
  const prefix = `forensic/${caseId}/`;
  const reports = [];
  let continuationToken;
  do {
    const response = await s3.send(new ListObjectsV2Command({
      Bucket: bucket, Prefix: prefix, ContinuationToken: continuationToken,
    }));
    for (const object of response.Contents || []) {
      const match = FORENSIC_KEY_RE.exec(object.Key || "");
      if (match && match[1] === caseId) reports.push({
        key: object.Key, isolationId: match[2], modified: object.LastModified,
      });
    }
    continuationToken = response.IsTruncated ? response.NextContinuationToken : undefined;
    if (response.IsTruncated && !continuationToken) throw new Error("S3 forensic pagination token missing");
  } while (continuationToken);
  return reports.sort((a, b) => new Date(b.modified) - new Date(a.modified));
}

function forensicUrl(caseId, isolationId, pdf = false, serviceId, reportKey) {
  return `${pdf ? "/forensic.pdf" : "/forensic"}?case=${encodeURIComponent(caseId)}&isolation=${encodeURIComponent(isolationId)}&service=${encodeURIComponent(serviceId)}&key=${encodeURIComponent(reportKey || serviceId + "/" + caseId + ".md")}`;
}

function forensicList(items, field, emptyText = "기록 없음") {
  if (!Array.isArray(items) || items.length === 0) return `<p class="muted">${esc(emptyText)}</p>`;
  return `<ul>${items.map((item) => {
    const value = typeof item === "string" ? item : item && typeof item === "object" ? item[field] : "";
    return `<li>${esc(value || "기록 없음")}</li>`;
  }).join("")}</ul>`;
}

async function invokeApproval(payload) {
  const reply = await approvalLambda.send(new InvokeCommand({
    FunctionName: APPROVE_FUNCTION_NAME,
    InvocationType: "RequestResponse",
    Payload: Buffer.from(JSON.stringify(payload)),
  }));
  if (reply.FunctionError || reply.StatusCode !== 200) throw new Error("ApprovalUnavailable");
  const value = JSON.parse(Buffer.from(reply.Payload || []).toString("utf8"));
  if (!value || typeof value.ok !== "boolean") throw new Error("InvalidApprovalResponse");
  return value;
}

async function reviewStatus(key) {
  return invokeApproval({ operation: "status", key });
}

const rejectComplete = (review) => review?.decision === "reject" &&
  (review.callback_status === "SENT" || review.status === "REJECTED");

async function getStoredDecision(key, strict = false, bucket = REPORT_BUCKET) {
  try {
    return JSON.parse(await getText(DECISION_PREFIX + key + ".json", bucket));
  } catch (err) {
    if (strict && err.name !== "NoSuchKey" && err.name !== "NotFound" && err.$metadata?.httpStatusCode !== 404) throw err;
    return null; // 아직 결정 없음
  }
}

async function getDecision(key, bucket = REPORT_BUCKET) {
  // The list keeps its existing S3 reads; mutation and detail status use the live case.
  return getStoredDecision(key, false, bucket);
}

// 사용자 차단 기록: decisions/<리포트키>.ipblock.json
async function getIpBlock(key, bucket = REPORT_BUCKET) {
  try {
    return JSON.parse(await getText(DECISION_PREFIX + key + ".ipblock.json", bucket));
  } catch {
    return null;
  }
}

async function saveIpBlock(key, record, bucket = REPORT_BUCKET) {
  await s3.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: DECISION_PREFIX + key + ".ipblock.json",
      Body: JSON.stringify(record, null, 2),
      ContentType: "application/json",
    })
  );
}

function assertPermanentSet(current, service, family) {
  if (!service?.waf || current.IPSet?.ARN !== service.waf.arn || current.IPSet?.Name !== service.waf.name ||
      current.IPSet?.Id !== service.waf.id || current.IPSet?.IPAddressVersion !== `IPV${family}` ||
      !Array.isArray(current.IPSet?.Addresses) || typeof current.LockToken !== "string" || !current.LockToken) {
    throw new Error("InvalidPermanentIPSet");
  }
  if (current.IPSet.Addresses.some(value => !parseNetwork(value) || parseNetwork(value).family !== family)) throw new Error("InvalidPermanentIPSet");
}

// WAF IP 세트에 이미 들어 있는지 확인 (조회 실패 시 null)
async function isIpInWafSet(ip, service) {
  try {
    const cur = await serviceWaf(service).send(new GetIPSetCommand({ Name: service.waf.name, Id: service.waf.id, Scope: service.waf.scope }));
    const parsed = parseIp(ip);
    assertPermanentSet(cur, service, parsed.family);
    return cur.IPSet.Addresses.some(value => exactHost(parseNetwork(value), parsed));
  } catch (err) {
    console.error("WAF 목록 조회 실패:", err.name);
    return null;
  }
}

// WAF IP 세트에 IP 추가 (이미 있으면 그대로 둠)
async function addIpToWafSet(ip, service) {
  const parsed = parseIp(ip);
  const cidr = parsed.ip + "/" + parsed.prefix;
  for (let attempt = 0; attempt < 3; attempt++) {
    const cur = await serviceWaf(service).send(new GetIPSetCommand({ Name: service.waf.name, Id: service.waf.id, Scope: service.waf.scope }));
    assertPermanentSet(cur, service, parsed.family);
    const addresses = cur.IPSet.Addresses || [];
    if (addresses.some(value => exactHost(parseNetwork(value), parsed))) return { already: true };
    try {
      await serviceWaf(service).send(
        new UpdateIPSetCommand({
          Name: service.waf.name,
          Id: service.waf.id,
          Scope: service.waf.scope,
          Addresses: [...addresses, cidr],
          LockToken: cur.LockToken,
          ...(cur.IPSet.Description ? { Description: cur.IPSet.Description } : {}),
        })
      );
      return { already: false };
    } catch (err) {
      // 다른 사람이 동시에 수정했으면 다시 읽어서 재시도
      if (err.name !== "WAFOptimisticLockException") throw err;
    }
  }
  throw new Error("WAF IP 세트 수정 충돌이 계속 발생했습니다.");
}

async function saveDecision(key, decision, bucket = REPORT_BUCKET) {
  await s3.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: DECISION_PREFIX + key + ".json",
      Body: JSON.stringify(decision, null, 2),
      ContentType: "application/json",
    })
  );
}

const STATUS = {
  pending: { label: "검토 대기", cls: "pending" },
  approve: { label: "대응 승인", cls: "approve" },
  reject: { label: "반려", cls: "reject" },
  hold: { label: "보류", cls: "hold" },
};
const statusOf = (d) => d?.action === "reject" && d?.source !== "hitl-callback"
  ? { label: "거부(기록)", cls: "reject" } : STATUS[d?.action] || STATUS.pending;

const TIER_TEXT = { 0: "T0 자동 대응", 1: "T1 자동 IP 대응", 2: "T2 AI 추천 후 승인", 3: "T3 사람 판단" };

// 티어 0, 1은 자동 조치(HOTL), 티어 2, 3과 티어 없는 사건은 사람 검토(HITL)
const isHotl = (meta) => ["0", "1"].includes(String(meta?.tier ?? ""));
const AUTO_STATUS = {
  0: { label: "자동 대응", cls: "auto-iso" },
  1: { label: "자동 대응", cls: "auto-block" },
};
function autoStatus(review) {
  const labels = { AUTO_BLOCKED: "차단 완료", AUTO_BLOCK_PARTIAL: "부분 차단 · 확인 필요", AUTO_BLOCK_FAILED: "차단 실패", AUTO_ISOLATED: "격리 완료",
    AUTO_ISOLATION_FAILED: "격리 실패", AUTO_MONITORED: "관찰", MONITORED: "관찰", AUTO_DRY_RUN: "검증 모드", AUTO_RESPONSE_EXEMPT: "조치 제외" };
  return { label: labels[review?.status] || "자동 대응 상태 확인", cls: "auto-block" };
}

function page(title, inner) {
  return `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${esc(title)}</title>
  <link rel="stylesheet" href="/style.css" />
  <script>
    function dashboardFetch(url, options = {}) {
      const target = new URL(url, location.origin);
      if (target.origin !== location.origin) return Promise.reject(new Error("관리 API 요청 출처가 다릅니다."));
      const headers = new Headers(options.headers || {});
      if (["POST", "PUT", "PATCH", "DELETE"].includes(String(options.method || "GET").toUpperCase())) {
        headers.set("X-CSRF-Token", document.querySelector('meta[name="csrf-token"]').content);
      }
      return fetch(target, { ...options, headers, credentials: "same-origin" });
    }
  </script>
</head>
<body>
  <header class="topbar">
    <a href="/" class="brand">침해대응 대시보드</a>
    <button class="btn ghost" id="logout-btn">로그아웃</button>
  </header>
  <script>
    document.getElementById("logout-btn").addEventListener("click", async () => {
      const response = await dashboardFetch("/auth/logout", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
      const result = await response.json();
      if (response.ok && result.ok) location.assign(result.redirect);
    });
  </script>
  ${inner}
</body>
</html>`;
}

// ---------------------------------------------------------------- 목록 페이지
app.get("/", async (req, res) => {
  let rows = [];
  let error = null;
  try {
    const reports = await listReports(await serviceResolver.list(req.auth));
    rows = await Promise.all(
      reports.map(async (r) => {
        let service, review;
        try {
          review = await reviewStatus(r.Key);
          if (review.service_id !== parseCaseKey(r.Key)?.serviceId) return null;
          service = await serviceResolver.resolve(review, req.auth, "read");
        } catch { return null; }
        let meta = {};
        try {
          meta = parseReport(await getText(r.Key, service.reportBucket)).meta;
          if (Number.isInteger(review.tier)) meta.tier = String(review.tier);
        } catch {}
        return { key: r.Key, at: r.LastModified, meta, review, decision: await getDecision(r.Key, service.reportBucket) };
      })
    );
    rows = rows.filter(Boolean);
  } catch (err) {
    console.error("리포트 목록 불러오기 실패:", err.name);
    error = "리포트 목록을 불러오지 못했습니다. (S3 연결 확인 필요)";
  }

  // HOTL 사건은 사람 결정이 없으므로 "auto" 상태로 따로 취급
  const actionOf = (r) => (isHotl(r.meta) ? "auto" : r.decision?.action || "pending");
  const count = (a) => rows.filter((r) => actionOf(r) === a).length;

  // 통계 카드 클릭 시 ?filter= 로 목록 필터링
  const FILTERS = {
    pending: (r) => actionOf(r) === "pending",
    approve: (r) => actionOf(r) === "approve",
    reject: (r) => ["reject", "hold"].includes(actionOf(r)),
  };
  const filter = FILTERS[req.query.filter] ? req.query.filter : "";
  const shown = filter ? rows.filter(FILTERS[filter]) : rows;

  const stats = [
    ["최근 사건", rows.length, "", ""],
    ["검토 대기", count("pending"), "pending", "pending"],
    ["격리 승인", count("approve"), "approve", "approve"],
    ["반려/보류", count("reject") + count("hold"), "reject", "reject"],
  ]
    .map(
      ([l, n, c, f]) =>
        `<a href="/${f ? "?filter=" + f : ""}" class="stat ${c} ${filter === f ? "selected" : ""}"><div class="stat-num">${n}</div><div class="stat-label">${l}</div></a>`
    )
    .join("");

  const rowHtml = (r) => {
    const tier = r.meta.tier;
    const tierKnown = ["0", "1", "2", "3"].includes(String(tier));
    const st = isHotl(r.meta) ? autoStatus(r.review) : statusOf(r.decision);
    return `<a class="incident-row" href="/report?key=${encodeURIComponent(r.key)}">
            <span class="tier-pill t${esc(tier || "x")}">${tierKnown ? "T" + esc(tier) : "T?"}</span>
            <span class="row-main">
              <span class="row-title">${esc(r.meta.title || r.key)}</span>
              <span class="row-sub">${esc(r.meta.instanceId || "대상 미지정")}${r.meta.attackerIp ? " / 공격자 " + esc(r.meta.attackerIp) : ""}</span>
            </span>
            <span class="row-date">${new Date(r.at).toLocaleString("ko-KR", { timeZone: "Asia/Seoul" })}</span>
            <span class="status-pill ${st.cls}">${st.label}</span>
          </a>`;
  };

  const block = (title, items) => {
    const body = error
      ? `<p class="empty">${esc(error)}</p>`
      : items.length === 0
      ? `<p class="empty">해당하는 사건이 없습니다.</p>`
      : items.map(rowHtml).join("");
    return `<section class="panel">
          <div class="block-head"><h2>${title}</h2><span class="block-count">${items.length}건</span></div>
          <div class="block-list">${body}</div>
        </section>`;
  };

  const hotlRows = shown.filter((r) => isHotl(r.meta));
  const hitlRows = shown.filter((r) => !isHotl(r.meta));

  res.send(
    page(
      "침해대응 대시보드",
      `<main class="wrap">
        <h1 class="page-title">침해 사고 목록</h1>
        <div class="stats">${stats}</div>
        ${block("HOTL 대시보드", hotlRows)}
        ${block("HITL 대시보드", hitlRows)}
      </main>`
    )
  );
});

// ---------------------------------------------------------------- 상세 페이지
app.get("/report", async (req, res) => {
  const key = req.query.key;
  if (!key) return res.redirect("/");
  if (typeof key !== "string" || !REVIEW_KEY_RE.test(key)) {
    return res.status(400).send("유효한 사건 보고서 키가 필요합니다.");
  }
  res.set("Cache-Control", "no-store");

  let meta = {}, reportHtml, decision = null, ipBlock = null, liveReview = null;
  const caseId = parseCaseKey(key)?.caseId || null;
  let forensic = [], forensicError = false;
  try {
    const parsed = parseReport(await getText(key, req.service.reportBucket));
    meta = parsed.meta;
    reportHtml = await sanitizeReportHtml(await renderMarkdown(parsed.body));
    decision = await getDecision(key, req.service.reportBucket);
    ipBlock = await getIpBlock(key, req.service.reportBucket);
    if (REVIEW_KEY_RE.test(key)) {
      try {
        const review = req.caseReview;
        liveReview = review;
        // Tier and rollback target come from the case store, never AI prose.
        if (review.ok && Number.isInteger(review.tier) && [0, 1, 2, 3].includes(review.tier)) meta.tier = String(review.tier);
        if (!isHotl(meta) && review.ok && rejectComplete(review)) decision = {
          action: "reject", source: "hitl-callback", callback_status: "SENT",
          by: review.decided_by || "dashboard", at: review.decided_at || review.updated_at,
          note: review.decision_reason || "",
        };
        else if (!isHotl(meta) && review.ok && review.decision === "approve" && review.callback_status === "SENT") decision = {
          action: "approve", source: "hitl-callback", callback_status: "SENT",
          by: review.decided_by || "dashboard", at: review.decided_at || review.updated_at,
          note: review.decision_reason || "",
        };
        else if (!isHotl(meta) && review.ok && review.pending && decision?.action === "reject") decision = null;
      } catch (err) {
        console.error("승인 상태 조회 실패:", err.name);
      }
    }
  } catch (err) {
    console.error("리포트 읽기 실패:", err.name);
    reportHtml = "<p>리포트를 불러오지 못했습니다.</p>";
  }
  if (caseId && forensicEnabledFor(req.service)) {
    try { forensic = await forensicReports(caseId, req.service.reportBucket); }
    catch (err) { console.error("포렌식 보고서 목록 조회 실패:", err.name); forensicError = true; }
  }

  const hotl = isHotl(meta);
  let rollbackState = { eligible: false, message: "사건 저장소 또는 WAF 차단 상태를 확인하지 못했습니다. 새로고침해 주세요." };
  if (hotl && liveReview?.ok) {
    try {
      rollbackState = await rollbackFor(req.service).getSnapshot(key, liveReview);
      if (!req.service.can_admin || !req.service.allowed_actions.includes("block_ip")) { rollbackState.eligible = false; rollbackState.message = "이 서비스의 IP 차단 변경 권한이 필요합니다."; }
    }
    catch (error) {
      rollbackState.message = error instanceof RollbackError ? error.message : "WAF 차단 상태를 확인하지 못했습니다. 새로고침해 주세요.";
      console.error("HOTL 롤백 상태 조회 실패:", error.code || error.name);
    }
  }
  const st = hotl ? autoStatus(liveReview) : statusOf(decision);
  const tierRow = [0, 1, 2, 3]
    .map((t) => `<span class="tier-badge t${t} ${String(meta.tier) === String(t) ? "active" : ""}">${TIER_TEXT[t]}</span>`)
    .join("");
  const forensicPanel = !caseId ? "" : !forensicEnabledFor(req.service) ? '<section class="panel"><h2>포렌식 보고서</h2><p class="muted">현재 설치에서는 포렌식 보고서를 지원하지 않습니다.</p></section>' : `<section class="panel">
    <h2>격리 후 포렌식 보고서</h2>
    ${forensicError ? '<p class="warn">포렌식 보고서 저장소를 확인하지 못했습니다.</p>' :
      forensic.length ? `<p>격리가 끝난 인스턴스의 침해 분석 결과가 준비됐습니다.</p>
        <ul>${forensic.map((entry) => `<li><a href="${forensicUrl(caseId, entry.isolationId, false, req.service.service_id, key)}">포렌식 보고서 보기</a>
        <span class="muted mono">격리 실행 ${esc(entry.isolationId.slice(0, 12))}</span></li>`).join("")}</ul>` :
      '<p class="muted">포렌식 보고서가 아직 저장되지 않았습니다. 격리와 조사 완료 후 새로고침해 주세요.</p>'}
  </section>`;

  const fact = (label, value, mono = true) =>
    `<div class="fact"><div class="fact-label">${label}</div><div class="fact-value ${mono ? "mono" : ""}">${value ? esc(value) : '<span class="muted">없음</span>'}</div></div>`;

  const canIsolate = req.service.can_admin && liveReview?.pending && [2, 3].includes(liveReview.tier);

  const caseIp = parseIp(liveReview?.target?.source_ip);
  if (caseIp) meta.attackerIp = caseIp.ip;
  const canBlock = MANUAL_IP_BLOCK_ENDPOINT_ENABLED && req.service.can_admin && req.service.manual_block_enabled === true && req.service.allowed_actions.includes("block_ip") &&
    [2, 3].includes(liveReview?.tier) && liveReview.status === "DECIDED_APPROVE" && liveReview.decision === "approve" &&
    liveReview.callback_status === "SENT" && liveReview.approved_action === "block_ip" && Boolean(caseIp);
  // 대시보드에서 차단한 기록이 없으면 WAF 목록에 이미 있는지 직접 확인
  const inWaf = !hotl && !ipBlock && canBlock ? await isIpInWafSet(meta.attackerIp, req.service) : null;
  const ipBlockInfo = inWaf
    ? `<div class="decided"><b>이미 WAF 차단 목록에 있음</b> | ${esc(meta.attackerIp)}/${caseIp.prefix}</div>`
    : ipBlock
    ? `<div class="decided"><b>차단됨</b> | ${esc(ipBlock.cidr || ipBlock.ip + "/32")} | ${esc(ipBlock.by || "이전 기록")} | ${new Date(ipBlock.at).toLocaleString("ko-KR", { timeZone: "Asia/Seoul" })}</div>`
    : "";

  const decisionInfo = decision
    ? `<div class="decided">
         <b>${st.label}</b> | ${esc(decision.by || "익명")} | ${new Date(decision.at).toLocaleString("ko-KR", { timeZone: "Asia/Seoul" })}
         ${decision.note ? `<div class="muted">메모: ${esc(decision.note)}</div>` : ""}
         ${decision.executionArn ? `<div class="muted mono small">${esc(decision.executionArn.split(":").pop())}</div>` : ""}
       </div>`
    : "";

  res.send(
    page(
      "침해대응 대시보드 - " + key,
      `<main class="wrap">
        <a href="/" class="back">← 침해 사고 목록</a>

        <div class="incident-bar">
          <div>
            <div class="incident-title">${esc(meta.title || key)}</div>
          </div>
          <span class="status-pill big ${st.cls}" id="status-pill">${st.label}</span>
        </div>

        <div class="incident-grid">
          <aside class="evidence-col">
            <div class="panel">
              <h2>조치 대상</h2>
              ${fact("인스턴스 ID", meta.instanceId)}
              ${fact(meta.reportedIp ? "공격자 IP (AI 보고서 표기)" : "공격자 IP", meta.attackerIp || meta.reportedIp)}
              ${hotl ? fact("롤백 대상 IP (사건 저장소)", rollbackState.ip) : ""}
              ${fact("GuardDuty Finding", meta.findingId)}
              ${fact("리포트 파일", key)}
            </div>
          </aside>

          <section class="decision-col">
            <div class="tier-row">${tierRow}</div>

            <article class="panel report">${reportHtml}</article>

${hotl ? `
            <div class="panel action-panel">
              <h2>자동 조치</h2>
              <div class="decided"><b>${st.label}</b> | 티어 ${esc(meta.tier)} 기준으로 자동 판단된 사건입니다.</div>
              <div class="buttons">
                <button class="btn ghost" id="rollback-btn" ${rollbackState.eligible ? "" : "disabled"}>사용자 차단 롤백</button>
              </div>
              <div class="inputs"><input id="rollback-reason" placeholder="차단 롤백 사유 (필수)" aria-label="차단 롤백 사유" maxlength="500" ${rollbackState.eligible ? "" : "disabled"} /></div>
              <p class="warn small">영구 WAF IPSet의 단일 IP 항목만 제거합니다. NACL·임시 WAF·범위 차단은 유지되며 새 탐지 시 재차단될 수 있습니다. 격리된 인스턴스는 복구하지 않습니다.</p>
              <div class="status" id="rollback-status" role="status" aria-live="polite">${esc(rollbackState.message)}</div>
            </div>
` : `
            <div class="panel action-panel">
              <h2>대응 결정</h2>
              ${decisionInfo}
              <div class="action-form" ${decision ? 'style="display:none"' : ""}>
                <div class="inputs">
                  <input id="note" placeholder="메모 (선택)" maxlength="200" />
                </div>
                <div class="buttons">
                  <button class="btn approve" data-action="approve" ${canIsolate ? "" : "disabled"}>대응 승인</button>
                  <button class="btn hold" data-action="hold">보류</button>
                </div>
                ${canIsolate ? "" : '<p class="warn small">승인 대기 중인 사건이 없거나 관리자 권한이 없습니다.</p>'}
                <div class="confirm" id="confirm" hidden>
                  <p>이 사건의 검증된 저장소 대상에 대해 승인 대기 중인 워크플로를 진행합니다.<br/>
                  <b>승인할 대응: ${esc(({ monitor: "관찰", block_ip: "IP 차단", isolate_instance: "인스턴스 격리", none: "수동 검토" })[liveReview?.recommended_action] || "저장된 대응")}</b></p>
                  <button class="btn approve" id="confirm-yes">확인, 실행</button>
                  <button class="btn ghost" id="confirm-no">취소</button>
                </div>
              </div>
              <div class="status" id="status-text"></div>
            </div>

            <div class="panel action-panel" id="reject-panel">
              <h2>요청 반려</h2>
              <p class="muted small">승인 대기 요청을 종료합니다.</p>
              <div class="inputs">
                <input id="reject-reason" placeholder="반려 사유 (선택)" aria-label="반려 사유 (선택)" maxlength="500" />
              </div>
              <div class="buttons">
                <button class="btn reject" id="reject-btn" disabled>반려</button>
              </div>
              <div class="status" id="reject-status" role="status" aria-live="polite">승인 대기 상태 확인 중...</div>
              <div class="decided" id="reject-history" hidden></div>
            </div>

            <div class="panel action-panel">
              <h2>사용자 차단 (WAF)</h2>
              ${ipBlockInfo}
              <div class="inputs"><input id="block-reason" placeholder="사용자 차단 사유 (필수)" aria-label="사용자 차단 사유" maxlength="500" /></div>
              <div ${ipBlock || inWaf ? 'style="display:none"' : ""}>
                <div class="buttons">
                  <button class="btn reject" id="block-btn" ${canBlock ? "" : "disabled"}>사용자 차단</button>
                </div>
                ${canBlock ? "" : MANUAL_IP_BLOCK_ENDPOINT_ENABLED ? '<p class="warn small">수동 차단 정책과 이 사건의 확정된 IP 차단 승인이 필요합니다.</p>' : '<p class="warn small">대응 승인을 통해 IP 차단을 실행합니다.</p>'}
                <div class="confirm" id="block-confirm" hidden>
                  <p><b class="mono">${esc(caseIp ? caseIp.ip + "/" + caseIp.prefix : "대상 미확인")}</b> 를 이 사건의 등록된 영구 WAF IPSet에 추가합니다.</p>
                  <button class="btn reject" id="block-yes">확인, 차단</button>
                  <button class="btn ghost" id="block-no">취소</button>
                </div>
              </div>
              <div class="status" id="block-status"></div>
            </div>
`}
          </section>
        </div>
        ${forensicPanel}
      </main>

      <script>
        const KEY = ${inlineJson(key)};
        const EXEC_ARN = ${inlineJson(decision?.executionArn || null)};
        const statusText = document.getElementById("status-text");
        const confirmBox = document.getElementById("confirm");
        const buttons = document.querySelectorAll(".buttons .btn[data-action]");

        function setStatus(msg, cls) { statusText.textContent = msg; statusText.className = "status " + (cls || ""); }

        async function send(action) {
          buttons.forEach(b => b.disabled = true);
          setStatus("처리 중...");
          try {
            const res = await dashboardFetch("/api/decision", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                key: KEY, action,
                note: document.getElementById("note").value.trim()
              })
            });
            const data = await res.json();
            if (!data.ok) { setStatus(data.message, "err"); buttons.forEach(b => b.disabled = false); return; }
            setStatus(data.message, "ok");
            setTimeout(() => location.reload(), 1200);
          } catch (e) {
            setStatus("요청 실패: 서버에 연결할 수 없음", "err");
            buttons.forEach(b => b.disabled = false);
          }
        }

        buttons.forEach(b => b.addEventListener("click", () => {
          const a = b.dataset.action;
          if (a === "approve") { confirmBox.hidden = false; return; }
          send(a);
        }));
        document.getElementById("confirm-yes")?.addEventListener("click", () => { confirmBox.hidden = true; send("approve"); });
        document.getElementById("confirm-no")?.addEventListener("click", () => { confirmBox.hidden = true; });

        // A reject closes the actual waiting HITL callback through the server.
        const rejectBtn = document.getElementById("reject-btn");
        const rejectReason = document.getElementById("reject-reason");
        const rejectStatus = document.getElementById("reject-status");
        const rejectHistory = document.getElementById("reject-history");
        let rejectBusy = false;
        let rejectAllowed = false;
        const existingIsolation = ${JSON.stringify(decision?.action === "approve" || Boolean(decision?.executionArn))};
        function setRejectStatus(message, cls) {
          rejectStatus.textContent = message;
          rejectStatus.className = "status " + (cls || "");
        }
        function finishReject(message, history) {
          rejectAllowed = false;
          rejectBtn.disabled = true;
          rejectReason.disabled = true;
          setRejectStatus(message || "반려 완료: 승인 대기 요청을 종료했습니다.", "ok");
          if (history && rejectHistory) {
            const details = [];
            if (history.decided_by) details.push("담당자: " + history.decided_by);
            if (history.decided_at) details.push(new Date(history.decided_at).toLocaleString("ko-KR", { timeZone: "Asia/Seoul" }));
            if (history.decision_reason) details.push("사유: " + history.decision_reason);
            rejectHistory.textContent = details.join(" | ");
            rejectHistory.hidden = !details.length;
          }
          const pill = document.getElementById("status-pill");
          pill.textContent = "반려";
          pill.className = "status-pill big reject";
          buttons.forEach(b => b.disabled = true);
          const actionForm = document.querySelector(".action-form");
          if (actionForm) actionForm.style.display = "none";
          if (confirmBox) confirmBox.hidden = true;
        }
        async function loadReviewStatus() {
          if (!rejectBtn) return;
          rejectBtn.disabled = true;
          try {
            const response = await dashboardFetch("/api/review-status?key=" + encodeURIComponent(KEY), { cache: "no-store" });
            const data = await response.json();
            if (!response.ok || !data.ok) {
              rejectAllowed = false;
              return setRejectStatus(data.message || "승인 대기 상태를 확인하지 못했습니다. 새로고침 후 다시 확인해 주세요.", "err");
            }
            if (data.completed) return finishReject(undefined, data);
            rejectAllowed = !existingIsolation && (data.can_reject === true || data.can_retry_reject === true);
            rejectBtn.disabled = rejectBusy || !rejectAllowed;
            rejectReason.disabled = !rejectAllowed;
            setRejectStatus(existingIsolation ? "이미 격리 승인된 사건입니다." :
              rejectAllowed ? (data.can_retry_reject ? "반려 전달을 다시 시도할 수 있습니다." : "승인 대기 중: 반려할 수 있습니다.") :
              data.message || "승인 대기 중인 요청이 없어 반려할 수 없습니다.", data.uncertain ? "err" : "");
          } catch {
            rejectAllowed = false;
            setRejectStatus("승인 대기 상태를 확인하지 못했습니다. 새로고침 후 다시 확인해 주세요.", "err");
          }
        }
        rejectBtn?.addEventListener("click", async () => {
          if (rejectBusy || !rejectAllowed) return;
          const reason = rejectReason.value.trim();
          if (reason.length > 500) return setRejectStatus("반려 사유는 500자 이내로 입력해 주세요.", "err");
          rejectBusy = true;
          rejectBtn.disabled = true;
          rejectReason.disabled = true;
          setRejectStatus("반려 요청 중...");
          try {
            const response = await dashboardFetch("/api/reject", {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ key: KEY, reason }),
            });
            const data = await response.json();
            if (response.ok && data.ok && data.decision === "reject") {
              finishReject(data.message, data);
            } else {
              rejectAllowed = data.retryable === true;
              setRejectStatus(data.message || "반려를 완료하지 못했습니다. 상태를 다시 확인해 주세요.", "err");
            }
          } catch {
            rejectAllowed = false;
            setRejectStatus("응답을 확인하지 못했습니다. 새로고침하여 반려 처리 상태를 확인해 주세요.", "err");
          } finally {
            rejectBusy = false;
            rejectBtn.disabled = !rejectAllowed;
            rejectReason.disabled = !rejectAllowed;
          }
        });
        if (rejectBtn) loadReviewStatus();

        // HOTL rollback always resolves the IP again from the server's case store.
        const ROLLBACK_STATE = ${inlineJson(rollbackState)};
        const rollbackBtn = document.getElementById("rollback-btn");
        const rollbackReason = document.getElementById("rollback-reason");
        const rollbackStatus = document.getElementById("rollback-status");
        let rollbackBusy = false;
        let rollbackRequest = null;
        function setRollbackStatus(message, cls) {
          rollbackStatus.textContent = message;
          rollbackStatus.className = "status " + (cls || "");
        }
        function newRollbackId() {
          if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
          // The existing dashboard can run on HTTP; still use a cryptographic UUID.
          if (!globalThis.crypto?.getRandomValues) throw new Error("이 브라우저는 안전한 요청 식별자 생성을 지원하지 않습니다.");
          const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
          bytes[6] = (bytes[6] & 15) | 64;
          bytes[8] = (bytes[8] & 63) | 128;
          const hex = Array.from(bytes, value => value.toString(16).padStart(2, "0")).join("");
          return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)].join("-");
        }
        rollbackBtn?.addEventListener("click", async () => {
          if (rollbackBusy || !ROLLBACK_STATE.eligible) return;
          if (!rollbackRequest) {
            const reason = rollbackReason.value.trim();
            if (!reason || reason.length > 500) return setRollbackStatus("1~500자의 차단 롤백 사유를 입력하세요.", "err");
            if (!window.confirm(ROLLBACK_STATE.cidr + "를 영구 WAF 차단 IPSet에서 제거할까요?\\n사유: " + reason + "\\nNACL·임시 WAF·범위 차단은 유지되며 새 탐지 시 재차단될 수 있습니다.")) return;
            try {
              rollbackRequest = { key: KEY, reason, request_id: newRollbackId(), expected_lock_token: ROLLBACK_STATE.expected_lock_token };
            } catch (error) { return setRollbackStatus(error.message, "err"); }
          }
          rollbackBusy = true;
          rollbackBtn.disabled = true;
          rollbackReason.disabled = true;
          setRollbackStatus("WAF 차단 롤백 요청 중...");
          try {
            const response = await dashboardFetch("/api/rollback-ip", {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify(rollbackRequest), credentials: "same-origin", cache: "no-store",
            });
            const data = await response.json();
            if (response.ok && data.ok) {
              setRollbackStatus((data.idempotent ? "이전 요청 결과: " : "") + data.message, "ok");
              setTimeout(() => location.reload(), 1500);
              return;
            }
            if (response.status === 409 && data.refresh) {
              rollbackRequest = null;
              setRollbackStatus(data.message + " 화면을 새로고침합니다.", "err");
              setTimeout(() => location.reload(), 1500);
              return;
            }
            if (data.retry_same_request || response.status >= 500) {
              setRollbackStatus((data.outcome?.message ? data.outcome.message + " " : "") + data.message + " 요청 식별자: " + rollbackRequest.request_id, "err");
              rollbackBtn.textContent = data.code === "audit_incomplete" ? "감사 기록 재시도" : "동일 요청 재시도";
            } else {
              rollbackRequest = null;
              setRollbackStatus(data.message || "롤백 요청을 완료하지 못했습니다.", "err");
            }
            rollbackBtn.disabled = false;
            rollbackReason.disabled = Boolean(rollbackRequest);
          } catch {
            setRollbackStatus("응답을 확인하지 못했습니다. 같은 요청으로 재시도하세요. 요청 식별자: " + rollbackRequest.request_id, "err");
            rollbackBtn.textContent = "동일 요청 재시도";
            rollbackBtn.disabled = false;
          } finally {
            rollbackBusy = false;
          }
        });

        // 사용자 차단 (WAF)
        const blockBtn = document.getElementById("block-btn");
        const blockConfirm = document.getElementById("block-confirm");
        const blockStatus = document.getElementById("block-status");
        let blockRequest = null;
        blockBtn?.addEventListener("click", () => { blockConfirm.hidden = false; });
        document.getElementById("block-no")?.addEventListener("click", () => { blockConfirm.hidden = true; });
        document.getElementById("block-yes")?.addEventListener("click", async () => {
          const reason = document.getElementById("block-reason")?.value.trim() || "";
          if (!reason || reason.length > 500) { blockStatus.textContent = "1~500자의 사용자 차단 사유를 입력하세요."; return; }
          if (!blockRequest) blockRequest = { key: KEY, reason, request_id: newRollbackId() };
          blockConfirm.hidden = true;
          blockBtn.disabled = true;
          blockStatus.textContent = "차단 요청 중...";
          blockStatus.className = "status";
          try {
            const res = await dashboardFetch("/api/block-ip", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(blockRequest)
            });
            const data = await res.json();
            blockStatus.textContent = data.message;
            blockStatus.className = "status " + (data.ok ? "ok" : "err");
            if (data.ok) setTimeout(() => location.reload(), 1200);
            else blockBtn.disabled = false;
          } catch (e) {
            blockStatus.textContent = "요청 실패: 서버에 연결할 수 없음";
            blockStatus.className = "status err";
            blockBtn.disabled = false;
          }
        });

        // 승인된 사건이면 Step Functions 진행 상태를 5초마다 확인
        const LABEL = { RUNNING: "격리 진행 중...", SUCCEEDED: "격리 완료", FAILED: "격리 실패", TIMED_OUT: "시간 초과", ABORTED: "중단됨" };
        async function poll() {
          try {
            const r = await dashboardFetch("/api/execution-status?key=" + encodeURIComponent(KEY) + "&arn=" + encodeURIComponent(EXEC_ARN));
            const d = await r.json();
            if (!d.ok) return setStatus(d.message, "err");
            setStatus("Step Functions: " + (LABEL[d.status] || d.status), d.status === "SUCCEEDED" ? "ok" : d.status === "RUNNING" ? "" : "err");
            if (d.status === "RUNNING") setTimeout(poll, 5000);
          } catch { setTimeout(poll, 5000); }
        }
        if (EXEC_ARN) poll();
      </script>`
    )
  );
});

// Post-isolation report is a separate artifact from the AI1/AI2 triage Markdown.
// Resolve it by an exact case + isolation ID; never accept an arbitrary S3 key.
app.get("/forensic", async (req, res) => {
  if (!forensicEnabledFor(req.service)) return res.status(404).json({ ok: false, code: "forensic_reports_not_supported" });
  const caseId = req.query.case;
  const isolationId = req.query.isolation;
  if (!CASE_ID_RE.test(caseId || "") || !ISOLATION_ID_RE.test(isolationId || "")) {
    return res.status(400).send("잘못된 사건 또는 격리 실행 식별자입니다.");
  }
  try {
    const entry = (await forensicReports(caseId, req.service.reportBucket)).find((item) => item.isolationId === isolationId);
    if (!entry) return res.status(404).send("포렌식 보고서가 아직 없습니다.");
    const report = JSON.parse(await getText(entry.key, req.service.reportBucket));
    if (!report || report.incident_id !== caseId || !Array.isArray(report.summary)) {
      return res.status(502).send("포렌식 보고서 형식이나 사건 ID가 일치하지 않습니다.");
    }
    const rootCause = report.root_cause && typeof report.root_cause === "object" ? report.root_cause : {};
    const timeline = Array.isArray(report.timeline) ? report.timeline : [];
    res.set("Cache-Control", "no-store");
    res.send(page("격리 후 포렌식 보고서 - " + caseId, `<main class="wrap">
      <a href="/report?key=${encodeURIComponent(req.caseKey)}" class="back">← 사건 화면</a>
      <div class="incident-bar"><div><h1>격리 후 포렌식 보고서</h1>
      <p class="mono">사건 ${esc(caseId)} · 격리 실행 ${esc(isolationId.slice(0, 12))}</p></div></div>
      <section class="panel report"><h2>사건 요약</h2>${forensicList(report.summary, "text")}
      <h2>원인 판단</h2><p>판정: <b>${esc(rootCause.status || "미확인")}</b></p>
      <p>${esc(rootCause.description || "원인 설명 없음")}</p>
      <h2>관측 흐름</h2>${timeline.length ? `<ol>${timeline.map((item) =>
        `<li><time>${esc(item?.timestamp || "시각 없음")}</time> · ${esc(item?.event || "사건 설명 없음")}</li>`).join("")}</ol>` :
        '<p class="muted">관측 흐름 없음</p>'}
      <h2>확인되지 않은 부분</h2>${forensicList(report.unresolved_items, "description", "미해결 항목 없음")}
      <h2>권고 조치</h2>${forensicList(report.recommendations, "recommendation", "권고 조치 없음")}
      <p><b>사람 검토 필요:</b> ${report.requires_human_review === true ? "예" : "아니요"}</p>
      <p><a href="${forensicUrl(caseId, isolationId, true, req.service.service_id, req.caseKey)}" target="_blank" rel="noopener">PDF 원본 보기</a></p>
      </section></main>`));
  } catch (err) {
    console.error("포렌식 보고서 읽기 실패:", err.name);
    res.status(503).send("포렌식 보고서를 읽지 못했습니다.");
  }
});

app.get("/forensic.pdf", async (req, res) => {
  if (!forensicEnabledFor(req.service)) return res.status(404).json({ ok: false, code: "forensic_reports_not_supported" });
  const caseId = req.query.case;
  const isolationId = req.query.isolation;
  if (!CASE_ID_RE.test(caseId || "") || !ISOLATION_ID_RE.test(isolationId || "")) {
    return res.status(400).send("잘못된 사건 또는 격리 실행 식별자입니다.");
  }
  try {
    const entry = (await forensicReports(caseId, req.service.reportBucket)).find((item) => item.isolationId === isolationId);
    if (!entry) return res.status(404).send("포렌식 보고서가 아직 없습니다.");
    const pdfKey = entry.key.replace(/report\.json$/, "report.pdf");
    const object = await s3.send(new GetObjectCommand({ Bucket: req.service.reportBucket, Key: pdfKey }));
    if (object.ContentLength > 20 * 1024 * 1024) return res.status(413).send("PDF가 너무 큽니다.");
    const bytes = await object.Body.transformToByteArray();
    res.set("Content-Type", "application/pdf");
    res.set("Content-Disposition", `inline; filename="${caseId}.pdf"`);
    res.set("Cache-Control", "no-store");
    res.send(Buffer.from(bytes));
  } catch (err) {
    if (["NoSuchKey", "NotFound"].includes(err.name)) return res.status(404).send("PDF가 아직 없습니다.");
    console.error("포렌식 PDF 읽기 실패:", err.name);
    res.status(503).send("포렌식 PDF를 읽지 못했습니다.");
  }
});

// ---------------------------------------------------------------- 결정 API
app.post("/api/decision", async (req, res) => {
  const { key, action, note = "" } = req.body || {};
  if (action === "reject") return canonicalReject(req, res);
  if (!req.auth?.sub) return res.status(401).json({ ok: false, message: "관리자 로그인이 필요합니다." });
  if (typeof key !== "string" || !REVIEW_KEY_RE.test(key) || !["approve", "hold"].includes(action) ||
      typeof note !== "string" || note.length > 500 || Object.keys(req.body).some(field => !["key", "action", "note"].includes(field))) {
    return res.status(400).json({ ok: false, message: "유효한 사건과 결정·메모가 필요합니다." });
  }
  if (rejectRequests.has(key) || isolateRequests.has(key)) return res.status(409).json({ ok: false, message: "이 사건의 대응 요청을 처리 중입니다." });
  isolateRequests.add(key);
  try {
    const review = req.caseReview;
    if (!review.ok || review.case_id !== parseCaseKey(key)?.caseId) return res.status(404).json({ ok: false, message: "검증된 사건을 찾지 못했습니다." });
    if (![2, 3].includes(review.tier)) return res.status(409).json({ ok: false, message: "HITL 검토 사건만 승인·보류할 수 있습니다." });
    const awaiting = review.status === "AWAITING_APPROVAL" && review.pending === true && !review.decision;
    const retry = action === "approve" && review.status === "DECIDED_APPROVE" && review.decision === "approve" && review.callback_status === "PENDING";
    if (!awaiting && !retry) return res.status(409).json({ ok: false, message: "승인 대기 중인 사건이 없습니다." });
    const actor = req.auth.sub;
    const display = { reportKey: key, action, by: actor, identity_issuer: req.auth.issuer, identity_verified: true,
      note: note.trim(), at: new Date().toISOString(), tier: review.tier, attackerIp: review.target?.source_ip || null };
    if (action === "approve") {
      // Only consume this case's existing callback. Never start a workflow from
      // model-authored report metadata or a client-provided instance/IP.
      const result = await invokeApproval({ key, decision: "approve", user: actor, reason: note.trim() });
      if (!result.ok || result.decision !== "approve") return res.status(result.retryable ? 503 : 409).json({ ok: false,
        message: result.message || "승인 대기 요청을 처리하지 못했습니다.", retryable: result.retryable === true });
      display.source = "hitl-callback";
      display.callback_status = "SENT";
      if (result.idempotent) { display.by = review.decided_by || actor; display.at = review.decided_at || display.at; display.note = review.decision_reason || ""; }
      let synced = true;
      try { await saveDecision(key, display, req.service.reportBucket); } catch (error) { synced = false; console.error("APPROVAL_AUDIT_SYNC_FAILED", error.name); }
      return res.json({ ok: true, decision: "approve", synced, message: "승인 완료: 사건의 승인 대기 워크플로에 전달했습니다." });
    }
    await saveDecision(key, display, req.service.reportBucket);
    res.json({ ok: true, message: "검증된 운영자의 보류 결정으로 기록했습니다." });
  } catch (error) {
    console.error("DECISION_REQUEST_FAILED", error.name);
    res.status(503).json({ ok: false, message: "결정 상태를 확인하지 못했습니다. 새로고침하세요." });
  } finally { isolateRequests.delete(key); }
});

// ---------------------------------------------------------------- 승인 대기 조회 / 반려
app.get("/api/review-status", async (req, res) => {
  res.set("Cache-Control", "no-store");
  const key = req.query.key;
  if (typeof key !== "string" || !REVIEW_KEY_RE.test(key)) {
    return res.status(400).json({ ok: false, message: "이 리포트는 승인 대기 요청이 아닙니다." });
  }
  try {
    const review = req.caseReview;
    if (!review.ok) return res.status(404).json({ ok: false, message: "승인 대기 요청을 찾을 수 없습니다." });
    const uncertain = review.decision === "reject" && !rejectComplete(review) && review.callback_status === "UNKNOWN";
    res.json({
      ok: true, status: review.status, decision: review.decision,
      can_reject: req.service.can_admin && review.can_reject === true, can_retry_reject: req.service.can_admin && review.can_retry_reject === true,
      completed: rejectComplete(review), uncertain,
      decided_by: review.decided_by, decided_at: review.decided_at,
      decision_reason: review.decision_reason, callback_status: review.callback_status,
      message: uncertain ? "반려 전달 여부를 확인할 수 없습니다. 담당자에게 처리 상태를 확인해 주세요." : undefined,
    });
  } catch (err) {
    console.error("승인 대기 조회 실패:", err.name);
    res.status(503).json({ ok: false, message: "승인 대기 상태를 확인하지 못했습니다. 잠시 후 다시 확인해 주세요." });
  }
});

async function canonicalReject(req, res) {
  const { key, reason = "", note } = req.body || {};
  const rawReason = note === undefined ? reason : note;
  if (!req.auth?.sub) return res.status(401).json({ ok: false, message: "관리자 로그인이 필요합니다." });
  if (typeof key !== "string" || !REVIEW_KEY_RE.test(key) || typeof rawReason !== "string" || rawReason.length > 500 ||
      Object.keys(req.body).some(field => !["key", "reason", "note", "action"].includes(field))) {
    return res.status(400).json({ ok: false, message: "유효한 사건과 500자 이내의 사유가 필요합니다." });
  }
  if (rejectRequests.has(key) || isolateRequests.has(key)) return res.status(409).json({ ok: false, message: "이 사건의 결정을 처리 중입니다." });
  rejectRequests.add(key);
  try {
    const current = req.caseReview;
    if (!current.ok || current.case_id !== parseCaseKey(key)?.caseId) return res.status(404).json({ ok: false, message: "검증된 사건을 찾지 못했습니다." });
    if (![2, 3].includes(current.tier)) return res.status(409).json({ ok: false, message: "HITL 승인 대기 사건만 반려할 수 있습니다." });
    if (!current.can_reject && !current.can_retry_reject && !rejectComplete(current)) return res.status(409).json({ ok: false, message: "반려할 승인 대기 요청이 없습니다." });
    const user = req.auth.sub;
    const result = await invokeApproval({ key, decision: "reject", reason: rawReason.trim(), user });
    if (!result.ok || result.decision !== "reject") return res.status(result.retryable ? 503 : 409).json({ ok: false,
      message: result.message || "사건의 승인 대기 요청을 반려하지 못했습니다.", retryable: result.retryable === true });
    const display = { reportKey: key, action: "reject", source: "hitl-callback", callback_status: "SENT",
      by: result.idempotent ? current.decided_by || user : user, identity_issuer: req.auth.issuer, identity_verified: true,
      at: result.idempotent ? current.decided_at || current.updated_at || new Date().toISOString() : new Date().toISOString(),
      note: result.idempotent ? current.decision_reason || "" : rawReason.trim(), tier: current.tier,
      attackerIp: current.target?.source_ip || null };
    let synced = true;
    try { await saveDecision(key, display, req.service.reportBucket); } catch (error) { synced = false; console.error("REJECT_AUDIT_SYNC_FAILED", error.name); }
    res.json({ ok: true, decision: "reject", idempotent: result.idempotent === true, callback_status: "SENT", synced,
      decided_by: display.by, decided_at: display.at, decision_reason: display.note, message: "반려 완료: 사건의 승인 대기 요청을 종료했습니다." });
  } catch (error) {
    console.error("REJECT_REQUEST_FAILED", error.name);
    res.status(503).json({ ok: false, message: "반려 상태를 확인하지 못했습니다. 새로고침하세요." });
  } finally { rejectRequests.delete(key); }
}

app.post("/api/reject", canonicalReject);

// ---------------------------------------------------------------- 실행 상태 조회
// ---------------------------------------------------------------- 사용자 차단 API (WAF IP 세트)
app.post("/api/rollback-ip", async (req, res) => {
  res.set("Cache-Control", "no-store");
  try {
    if (isolateRequests.has(req.body?.key)) {
      return res.status(409).json({ ok: false, code: "busy", message: "이 사건의 격리 요청을 처리 중입니다. 상태를 다시 확인하세요.", refresh: true });
    }
    const result = await rollbackFor(req.service).rollback(req.body, { peer: req.socket.remoteAddress, actor: req.auth.sub, issuer: req.auth.issuer });
    res.json(result);
  } catch (error) {
    if (error instanceof RollbackError) {
      return res.status(error.status).json({ ok: false, code: error.code, message: error.message, ...error.details });
    }
    console.error("WAF 롤백 요청 실패:", error.name);
    res.status(503).json({ ok: false, code: "service_unavailable", retry_same_request: true,
      message: "WAF 또는 감사 저장소 요청에 실패했습니다. 동일 요청으로 재시도하세요." });
  }
});

const blockRequests = new Set();
app.post("/api/block-ip", async (req, res) => {
  const { key, reason, request_id } = req.body || {};
  if (!req.auth?.sub) return res.status(401).json({ ok: false, message: "관리자 로그인이 필요합니다." });
  if (!MANUAL_IP_BLOCK_ENDPOINT_ENABLED) return res.status(405).json({ ok: false, code: "workflow_approval_required",
    message: "대응 승인을 통해 IP 차단을 실행합니다." });
  if (typeof key !== "string" || !REVIEW_KEY_RE.test(key) || typeof reason !== "string" || !reason.trim() || reason.length > 500 ||
      typeof request_id !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(request_id) ||
      Object.keys(req.body).some(field => !["key", "reason", "request_id"].includes(field))) {
    return res.status(400).json({ ok: false, message: "유효한 사건·차단 사유·UUID 요청 식별자가 필요합니다." });
  }
  if (blockRequests.has(key) || blockRequests.size >= 128) return res.status(409).json({ ok: false, retry_same_request: true, message: "WAF 차단 요청을 처리 중입니다." });
  blockRequests.add(key);
  try {
    const review = req.caseReview;
    if (!review.ok || review.case_id !== parseCaseKey(key)?.caseId || ![2, 3].includes(review.tier) || !parseIp(review.target?.source_ip) ||
        req.service.manual_block_enabled !== true || review.status !== "DECIDED_APPROVE" || review.decision !== "approve" || review.callback_status !== "SENT" || review.approved_action !== "block_ip") {
      return res.status(409).json({ ok: false, message: "수동 차단 정책과 검증된 사건의 확정된 IP 차단 승인이 필요합니다." });
    }
    const parsedIp = parseIp(review.target.source_ip);
    const ip = parsedIp.ip;
    const actor = req.auth.sub;
    const fingerprint = createHash("sha256").update(JSON.stringify({ key, ip, actor, issuer: req.auth.issuer, reason: reason.trim(),
      ipSetArn: req.service.waf.arn, service_id: req.service.service_id, registry_revision: req.service.revision })).digest("hex");
    const auditKey = DECISION_PREFIX + key + ".ipblock." + request_id + ".json";
    async function existingAudit() {
      try {
        const reply = await s3.send(new GetObjectCommand({ Bucket: req.service.audit_bucket, Key: auditKey }));
        const record = JSON.parse(await reply.Body.transformToString());
        if (record.payload_hash !== fingerprint) throw new RollbackError(409, "request_id_conflict", "이 요청 식별자는 다른 차단 요청에 사용됐습니다.");
        if (!["attempted", "completed"].includes(record.action) || typeof reply.ETag !== "string") throw new Error("InvalidBlockAudit");
        return { record, etag: reply.ETag };
      } catch (error) {
        if (["NoSuchKey", "NotFound"].includes(error.name) || error.$metadata?.httpStatusCode === 404) return null;
        throw error;
      }
    }
    let audit = await existingAudit();
    if (audit?.record.action === "completed") return res.json({ ...audit.record.result, idempotent: true });
    if (!audit) {
      const record = { action: "attempted", reportKey: key, ip, reason: reason.trim(), request_id, payload_hash: fingerprint,
        by: actor, identity_issuer: req.auth.issuer, identity_verified: true, ipSetArn: req.service.waf.arn,
        service_id: req.service.service_id, registry_revision: req.service.revision, attempted_at: new Date().toISOString() };
      try {
        const reply = await s3.send(new PutObjectCommand({ Bucket: req.service.audit_bucket, Key: auditKey, Body: JSON.stringify(record), ContentType: "application/json", IfNoneMatch: "*" }));
        if (typeof reply.ETag !== "string") throw new Error("AuditUnconfirmed");
        audit = { record, etag: reply.ETag };
      } catch (error) {
        if (error.name !== "PreconditionFailed" && error.$metadata?.httpStatusCode !== 412) throw error;
        audit = await existingAudit();
        if (!audit) throw error;
        if (audit.record.action === "completed") return res.json({ ...audit.record.result, idempotent: true });
      }
    }
    const result = await addIpToWafSet(ip, req.service);
    const outcome = { ok: true, status: result.already ? "already_present" : "blocked", request_id,
      message: `${ip}/${parsedIp.prefix} 영구 WAF 차단 항목${result.already ? "은 이미 있습니다." : "을 추가했습니다."}` };
    const completed = { ...audit.record, action: "completed", result: outcome, completed_at: new Date().toISOString() };
    try {
      await s3.send(new PutObjectCommand({ Bucket: req.service.audit_bucket, Key: auditKey, Body: JSON.stringify(completed), ContentType: "application/json", IfMatch: audit.etag }));
    } catch (error) {
      console.error("WAF_BLOCK_AUDIT_GAP", { request_id, error: error.name });
      return res.status(503).json({ ok: false, code: "audit_incomplete", outcome, retry_same_request: true, message: "WAF 결과 감사 기록 완료에 실패했습니다. 동일 요청으로 재시도하세요." });
    }
    let synced = true;
    try { await saveIpBlock(key, { reportKey: key, ip, cidr: `${ip}/${parsedIp.prefix}`, family: parsedIp.family, by: actor, at: completed.completed_at, ipSet: req.service.waf.name, identity_verified: true, request_id }, req.service.reportBucket); }
    catch (error) { synced = false; console.error("WAF_BLOCK_DISPLAY_SYNC_FAILED", error.name); }
    res.json({ ...outcome, synced });
  } catch (error) {
    if (error instanceof RollbackError) return res.status(error.status).json({ ok: false, code: error.code, message: error.message });
    console.error("WAF_BLOCK_REQUEST_FAILED", error.name);
    res.status(503).json({ ok: false, retry_same_request: true, message: "차단 요청 결과를 확인하지 못했습니다. 동일 요청으로 재시도하세요." });
  } finally { blockRequests.delete(key); }
});

app.get("/api/execution-status", async (req, res) => {
  const { arn, key } = req.query;
  if (typeof key !== "string" || !REVIEW_KEY_RE.test(key) || typeof arn !== "string" || !STATE_MACHINE_ARN ||
      !arn.startsWith(STATE_MACHINE_ARN.replace(":stateMachine:", ":execution:") + ":")) {
    return res.status(400).json({ ok: false, message: "유효한 사건에 연결된 실행 식별자가 필요합니다." });
  }
  try {
    const decision = await getStoredDecision(key, true, req.service.reportBucket);
    if (decision?.executionArn !== arn) return res.status(403).json({ ok: false, message: "이 사건에 연결된 실행이 아닙니다." });
    const result = await sfn.send(new DescribeExecutionCommand({ executionArn: arn }));
    res.json({ ok: true, status: result.status, startDate: result.startDate, stopDate: result.stopDate });
  } catch (error) {
    console.error("EXECUTION_STATUS_FAILED", error.name);
    res.status(503).json({ ok: false, message: "실행 상태를 확인하지 못했습니다." });
  }
});

// Final boundary also protects unknown routes and logout in development mode.
app.use(createRequestErrorHandler());

if (require.main === module) app.listen(PORT, "0.0.0.0", () => {
  console.log("Dashboard started", { port: PORT, authenticationConfigured: dashboardAuth.configured });
});
module.exports = { app };
