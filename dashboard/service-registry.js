"use strict";

const { RollbackError } = require("./waf-rollback");
const { parseIp, parseNetwork, contains } = require("./ip-utils");
const SERVICE_ID = /^[a-z][a-z0-9-]{2,47}$/;
const IPSET_ARN = /^arn:(aws|aws-us-gov|aws-cn):wafv2:([a-z0-9-]+):(\d{12}):(global|regional)\/ipset\/([A-Za-z0-9_-]{1,128})\/([0-9a-f-]{36})$/;

function createServiceResolver({ client, tableName, companyAccountId, GetCommand, ScanCommand, reportBucket, globalAdminGroup = "security-admins", globalReaderGroup = "security-readers" }) {
  async function resolve(review, actor, action = "read") {
    if (!tableName || !/^\d{12}$/.test(companyAccountId || "")) throw new RollbackError(503, "registry_not_configured", "회사 서비스 등록부 설정이 필요합니다.");
    if (!review?.ok || !SERVICE_ID.test(review.service_id || "")) throw new RollbackError(409, "service_unbound", "사건의 검증된 서비스 연결이 없습니다.");
    const service = (await client.send(new GetCommand({ TableName: tableName, Key: { service_id: review.service_id }, ConsistentRead: true }))).Item;
    if (!service || service.service_id !== review.service_id || service.enabled !== true || service.account_id !== companyAccountId ||
        !Array.isArray(service.allowed_actions) || !service.allowed_actions.length || service.allowed_actions.some(value => !["monitor", "block_ip", "isolate_instance"].includes(value)) ||
        typeof service.revision !== "string" || !service.revision || typeof service.audit_bucket !== "string") {
      throw new RollbackError(403, "service_disabled", "이 회사 계정의 활성 서비스로 확인되지 않았습니다.");
    }
    const memberships = Array.isArray(actor?.groups) ? actor.groups : [];
    const globalAdmin = memberships.includes(globalAdminGroup);
    const serviceAdmin = actor?.admin && Array.isArray(service.allowed_admin_groups) && service.allowed_admin_groups.some(group => memberships.includes(group));
    const reader = globalAdmin || serviceAdmin || memberships.includes(globalReaderGroup) ||
      (Array.isArray(service.allowed_reader_groups) && service.allowed_reader_groups.some(group => memberships.includes(group)));
    if (!(action === "read" ? reader : actor?.admin && (globalAdmin || serviceAdmin))) throw new RollbackError(403, "service_forbidden", "이 서비스에 대한 운영자 권한이 없습니다.");
    if (["block", "rollback"].includes(action) && !service.allowed_actions.includes("block_ip")) throw new RollbackError(403, "action_forbidden", "이 서비스에서 IP 차단 변경을 허용하지 않습니다.");
    if (action === "block" && service.manual_block_enabled !== true) throw new RollbackError(403, "manual_block_disabled", "이 서비스의 수동 IP 차단이 활성화되지 않았습니다.");
    if (action === "block" && (!([2, 3].includes(review.tier)) || review.status !== "DECIDED_APPROVE" || review.decision !== "approve" ||
        review.callback_status !== "SENT" || review.approved_action !== "block_ip")) throw new RollbackError(409, "block_not_approved", "이 사건의 IP 차단 승인이 워크플로에 확정되어야 합니다.");
    if (action === "approve" && review.recommended_action && review.recommended_action !== "none" && !service.allowed_actions.includes(review.recommended_action)) throw new RollbackError(403, "action_forbidden", "사건의 조치가 서비스 허용 범위에 없습니다.");
    let waf = null;
    const target = parseIp(review.target?.source_ip);
    const family = target?.family || 4;
    const chosenArn = family === 6 ? service.waf_ipv6_ipset_arn : service.waf_ipset_arn;
    if (chosenArn) {
      const match = IPSET_ARN.exec(chosenArn);
      const scope = match?.[4] === "global" ? "CLOUDFRONT" : "REGIONAL";
      if (!match || match[3] !== companyAccountId || service.waf_scope !== scope ||
          (scope === "CLOUDFRONT" && match[2] !== "us-east-1") || (scope === "REGIONAL" && match[2] !== service.region)) {
        throw new RollbackError(503, "invalid_registry", "등록된 WAF IPSet의 계정·리전·범위가 일치하지 않습니다.");
      }
      waf = { arn: chosenArn, name: match[5], id: match[6], region: match[2], scope, family };
    }
    if (["block", "rollback"].includes(action) && !waf) throw new RollbackError(409, "waf_unbound", "이 서비스에 등록된 영구 WAF IPSet이 없습니다.");
    if (action === "block") {
      const ip = review.target?.source_ip;
      if (!target) throw new RollbackError(409, "target_unavailable", "검증된 단일 IP 조치 대상이 없습니다.");
      for (const cidr of service.protected_cidrs || []) {
        const network = parseNetwork(cidr);
        if (!network) throw new RollbackError(503, "invalid_registry", "서비스 보호 CIDR 설정을 확인하세요.");
        if (contains(network, target)) throw new RollbackError(403, "protected_target", "보호 대상 IP는 차단할 수 없습니다.");
      }
    }
    return { ...service, waf, family, target_ip: target?.ip, can_admin: Boolean(actor?.admin && (globalAdmin || serviceAdmin)), reportBucket: service.report_bucket || reportBucket };
  }
  async function list(actor) {
    if (!tableName || !/^\d{12}$/.test(companyAccountId || "")) throw new RollbackError(503, "registry_not_configured", "회사 서비스 등록부 설정이 필요합니다.");
    let cursor;
    const services = [];
    do {
      const result = await client.send(new ScanCommand({ TableName: tableName, ExclusiveStartKey: cursor, ConsistentRead: true }));
      for (const item of result.Items || []) {
        try { services.push(await resolve({ ok: true, service_id: item.service_id }, actor, "read")); }
        catch (error) { if (!(error instanceof RollbackError) || ![403, 409].includes(error.status)) throw error; }
        if (services.length > 1000) throw new RollbackError(503, "registry_capacity", "서비스 목록을 페이지별로 조회하도록 설정해야 합니다.");
      }
      cursor = result.LastEvaluatedKey;
    } while (cursor);
    return services;
  }
  return { resolve, list };
}

module.exports = { createServiceResolver };
