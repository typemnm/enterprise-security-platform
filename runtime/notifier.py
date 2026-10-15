"""Notification-only Slack delivery. No approval, response, AI or raw-log access.

Only publication metadata and a sanitized summary are accepted. A permanent event receipt plus a leased claim
protects normal duplicates. Ambiguous first-post failures are held for review rather
than retried blindly; Slack does not provide an atomic transaction with DynamoDB.
"""
from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from .notification_content import ACTION_LABELS, ACTION_STATUS_LABELS, selected_content
from .outcome_metadata import SLACK_STATUS_LABELS, publication_metadata
from .expected_activity import wrap
from .outbox_delivery import project

LOG = logging.getLogger(__name__)
LOG.setLevel(logging.INFO)
CASE = re.compile(r"inv-[0-9a-f]{32}\Z")
SERVICE = re.compile(r"[a-z][a-z0-9-]{2,47}\Z")
DIGEST = re.compile(r"[a-f0-9]{64}\Z")
INSTANCE = re.compile(r"i-[0-9a-f]{8,17}\Z")
CHANNEL = re.compile(r"[CG][A-Z0-9]{8,}\Z")
TS = re.compile(r"\d{9,12}\.\d{1,8}\Z")
KINDS = {"HOTL", "HITL"}
INITIAL_STATUSES = {"TRIAGED", "REPORT_READY", "AI1_READY", "AWAITING_APPROVAL"}
STATUSES = {
    "TRIAGED": "1차 판단 보고서 도착",
    "REPORT_READY": "보고서 도착", "AI1_READY": "1차 판단 보고서 도착",
    "AWAITING_APPROVAL": "관리자 검토 필요", "DECIDED_APPROVE": "승인 기록됨",
    "DECIDED_REJECT": "반려 기록됨", "REJECTED": "반려 · 조치 없음",
    "MANUAL_ACTION_REQUIRED": "수동 분석 필요", "ISOLATED": "격리 완료",
    "IP_BLOCKED": "IP 차단 완료", "BLOCKED": "IP 차단 완료",
    "COMPLETED": "처리 완료", "MONITORED": "관찰", "NO_ACTION": "조치 없음",
    "RESPONSE_EXEMPT": "자동 대응 제외", "FAILED": "처리 실패",
    "TIMED_OUT": "검토 시간 만료", "IR_READY": "침해대응 보고서 도착",
    "DRY_RUN": "모의 실행 완료", "AUTO_ACTION_COMPLETED": "자동 대응 완료",
    "ISOLATION_FAILED": "격리 실패 · 확인 필요", "MANUAL_ANALYSIS": "수동 분석 필요",
    "AUTO_ISOLATED": "자동 격리 완료", "AUTO_ISOLATION_FAILED": "자동 격리 실패 · 확인 필요",
    "AUTO_BLOCKED": "자동 IP 차단 완료", "AUTO_BLOCK_FAILED": "자동 IP 차단 실패 · 확인 필요",
    "AUTO_MONITORED": "자동 판단 · 관찰", "AUTO_DRY_RUN": "자동 대응 모의 실행 완료",
    "AUTO_RESPONSE_EXEMPT": "자동 대응 제외", "AUTO_RESPONSE_GUARD_FAILED": "자동 대응 검증 실패 · 확인 필요",
}
STATUSES.update(SLACK_STATUS_LABELS)
COMPONENT_LABELS = {"APPLIED": "적용 완료", "ALREADY_PRESENT": "기존 적용 확인", "FAILED": "실패",
                    "SKIPPED": "건너뜀", "NOT_REQUIRED": "필요 없음", "UNKNOWN": "결과 미확인"}
RESPONSE_LABELS = {"APPLIED": "적용 완료", "PARTIAL": "일부 적용 · 확인 필요", "FAILED": "실패",
                   "DRY_RUN": "모의 실행 · 실제 조치 없음", "SKIPPED": "조치 제외", "UNVERIFIED": "결과 미확인"}


class NoticeError(Exception):
    def __init__(self, code, *, ambiguous=False, retry_after=0):
        super().__init__(code)
        self.code, self.ambiguous, self.retry_after = code, ambiguous, retry_after


@dataclass(frozen=True)
class Config:
    account: str
    region: str
    channel: str
    secret_arn: str
    dashboard_bucket: str
    lease_seconds: int = 150
    secret_field: str = "bot_token"
    notify_after_utc: str = ""
    # Flat keys are accepted only by an explicitly installed legacy profile.
    default_service_id: str = ""


def utc_epoch(value):
    if not isinstance(value, str) or len(value) > 50:
        raise NoticeError("INVALID_PUBLISHED_TIME")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError()
        return int(parsed.timestamp() * 1_000_000)
    except ValueError:
        raise NoticeError("INVALID_PUBLISHED_TIME") from None


def registered_service(registry, service_id, config):
    """Strong registry binding, independent of the event producer's assertions."""
    if registry is None:
        raise NoticeError("SERVICE_REGISTRY_REQUIRED")
    item = registry.get_item(Key={"service_id": service_id}, ConsistentRead=True).get("Item")
    if (not isinstance(item, dict) or item.get("service_id") != service_id
            or item.get("enabled") is not True or item.get("account_id") != config.account):
        raise NoticeError("SERVICE_NOT_REGISTERED")
    if (item.get("audit_bucket") != config.dashboard_bucket
            or item.get("report_bucket", item.get("audit_bucket")) != config.dashboard_bucket):
        raise NoticeError("SERVICE_REPORT_BUCKET_MISMATCH")
    return item


def normalize(event, config, registry):
    """Accept only service-scoped committed publication metadata; no report body."""
    if not isinstance(event, dict):
        raise NoticeError("INVALID_EVENT_SCHEMA")
    if event.get("account") != config.account or event.get("region") != config.region:
        raise NoticeError("UNTRUSTED_EVENT_ORIGIN")
    source, event_type, detail = event.get("source"), event.get("detail-type"), event.get("detail")
    if not isinstance(detail, dict) or detail.get("schema_version") != "1.0":
        raise NoticeError("INVALID_EVENT_SCHEMA")
    if source != "whs.hitl.dashboard" or event_type != "DashboardReportPublished.v1":
        raise NoticeError("UNTRUSTED_EVENT_TYPE")
    case_id, kind, service_id = detail.get("case_id"), detail.get("report_kind"), detail.get("service_id")
    status, revision, published_at = detail.get("status"), detail.get("event_id"), detail.get("published_at")
    location, target, phase = detail.get("result"), detail.get("target") or {}, detail.get("publication_type")
    if not isinstance(service_id, str) or not SERVICE.fullmatch(service_id):
        raise NoticeError("INVALID_SERVICE_ID")
    if not isinstance(case_id, str) or not CASE.fullmatch(case_id) or not isinstance(kind, str) or kind not in KINDS:
        raise NoticeError("INVALID_CASE_OR_KIND")
    if not isinstance(revision, str) or not DIGEST.fullmatch(revision) or detail.get("revision") != revision:
        raise NoticeError("INVALID_REVISION")
    if not isinstance(status, str) or status not in STATUSES:
        raise NoticeError("INVALID_STATUS")
    if not isinstance(phase, str) or phase not in {"INITIAL", "OUTCOME"}:
        raise NoticeError("INVALID_PUBLICATION_PHASE")
    expected_key = service_id + "/" + case_id + ".md"
    legacy_key = (service_id == "legacy-whs" and config.default_service_id == service_id
                  and isinstance(location, dict) and location.get("key") == case_id + ".md")
    if (not isinstance(location, dict) or set(location) != {"bucket", "key"}
            or location.get("bucket") != config.dashboard_bucket
            or location.get("key") != expected_key and not legacy_key):
        raise NoticeError("UNTRUSTED_REPORT_LOCATION")
    registered_service(registry, service_id, config)
    stamp = utc_epoch(published_at)
    tier = detail.get("tier")
    tier = tier if isinstance(tier, int) and not isinstance(tier, bool) and 0 <= tier <= 3 else None
    if not isinstance(target, dict):
        target = {}
    instance = target.get("instance_id")
    instance = instance if isinstance(instance, str) and INSTANCE.fullmatch(instance) else None
    address = target.get("source_ip")
    try:
        address = str(ipaddress.ip_address(address)) if isinstance(address, str) else None
    except ValueError:
        address = None
    content = selected_content(detail.get("report_summary"), detail.get("recommended_action"), detail.get("decision"),
                               phase=phase, status=status)
    facts = publication_metadata(service_id, {"components": detail.get("actual_outcomes"),
                                "response_status": detail.get("response_status"), "error_code": detail.get("response_error_code")},
                                {name: {"Error": code} for name, code in (detail.get("failure_codes") or {}).items()}
                                if isinstance(detail.get("failure_codes"), dict) else None)
    safe_target = {name: value for name, value in (("instance_id", instance), ("source_ip", address)) if value}
    # The producer hashes only these selected visible facts. Projection drops
    # empty targets and inferred outcome fields; reconstruct those canonically.
    # A modified summary, recipient service, action, pointer or component result
    # cannot reuse a previously committed event identity.
    material = {"service_id": service_id, "case_id": case_id, "kind": kind, "phase": phase, "status": status,
                **{name: facts.get(name) for name in ("response_status", "actual_outcomes", "failure_codes", "response_error_code")},
                **{name: content.get(name) for name in ("report_summary", "recommended_action", "decision", "decided_action", "action_status")},
                "tier": tier, "target": safe_target, "result": location}
    expected_revision = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if revision != expected_revision:
        raise NoticeError("PUBLICATION_REVISION_MISMATCH")
    for name in ("decided_action", "action_status"):
        if name in detail and detail[name] != content.get(name):
            raise NoticeError("PUBLICATION_ACTION_MISMATCH")
    # Recipient, account and service are part of every delivery identity.
    event_key = hashlib.sha256(f"{config.account}:{source}:{service_id}:{case_id}:{kind}:{revision}:{config.channel}".encode()).hexdigest()
    return {**content, **facts, "case_id": case_id, "kind": kind, "status": status, "revision": revision,
            "phase": phase,
            "published_at": published_at, "stamp": stamp, "tier": tier,
            "instance_id": instance, "source_ip": address, "event_key": "event#" + event_key,
            "message_key": f"message#{config.account}#{service_id}#{case_id}#{kind}#{config.channel}",
            "case_key": f"case#{config.account}#{service_id}#{case_id}#{config.channel}",
            "bucket": location["bucket"], "key": location["key"]}


def message_payload(notice, channel):
    """Plain text only: no mentions, raw report, action buttons or task token."""
    label = notice["kind"]
    heading, action_status = STATUSES[notice["status"]], notice.get("action_status", "UNKNOWN")
    if notice.get("decided_action") == "block_ip" and action_status == "APPLIED":
        components = notice.get("actual_outcomes", {})
        applied = {"APPLIED", "ALREADY_PRESENT"}
        # A status name or a successful Lambda invocation alone does not prove
        # WAF applied the block. Missing/conflicting evidence is displayed honestly.
        if notice.get("response_status") != "APPLIED" or components.get("waf", {}).get("status") not in applied:
            action_status, heading = "UNKNOWN", "IP 차단 적용 결과 미확인 · 수동 확인 필요"
        elif any(value.get("status") == "FAILED" for value in components.values()):
            action_status, heading = "PARTIAL", "IP 차단 일부 적용 · 확인 필요"
    lines = [f"[{label}] {heading}", f"서비스: {notice['service_id']}", f"사건: {notice['case_id']}"]
    if notice["tier"] is not None:
        lines.append(f"위험도: Tier {notice['tier']}")
    if notice["instance_id"]:
        lines.append(f"인스턴스: {notice['instance_id']}")
    if notice["source_ip"]:
        lines.append(f"IP: {notice['source_ip']}")
    lines.append("리포트 요약: " + notice.get("report_summary", "요약이 제공되지 않았습니다. 대시보드 보고서를 확인하세요."))
    recommended = notice.get("recommended_action")
    if recommended in ACTION_LABELS:
        lines.append(f"권장 행동: {ACTION_LABELS[recommended]} ({recommended})")
    if notice["phase"] == "INITIAL":
        lines.append("실행 상태: 관리자 승인 대기" if notice["status"] == "AWAITING_APPROVAL" else "실행 상태: 최종 조치 결과 대기")
    else:
        decided = notice.get("decided_action")
        if decided in ACTION_LABELS:
            lines.append(f"결정·실행 행동: {ACTION_LABELS[decided]} ({decided})")
        if notice.get("decision") in {"approve", "reject"}:
            lines.append("관리자 결정: " + ("승인" if notice["decision"] == "approve" else "반려"))
        lines.append("실행 결과: " + ACTION_STATUS_LABELS.get(action_status, ACTION_STATUS_LABELS["UNKNOWN"]))
        if notice.get("response_status") in RESPONSE_LABELS:
            lines.append("대응 상태: " + RESPONSE_LABELS[notice["response_status"]])
        for name in ("waf", "nacl"):
            component = notice.get("actual_outcomes", {}).get(name)
            if component:
                line = name.upper() + ": " + COMPONENT_LABELS[component["status"]]
                if component.get("error_code"):
                    line += " (" + component["error_code"] + ")"
                lines.append(line)
        for name, code in notice.get("failure_codes", {}).items():
            lines.append("확인 코드: " + name + " / " + code)
        if notice.get("response_error_code"):
            lines.append("대응 확인 코드: " + notice["response_error_code"])
    # UTC rendering is stable regardless of executor timezone.
    moment = datetime.fromtimestamp(notice["stamp"] / 1_000_000, timezone.utc)
    lines.append(f"게시 시각: {moment.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    return {"channel": channel, "text": html.escape("\n".join(lines), quote=False), "mrkdwn": False,
            "blocks": [{"type": "section", "text": {"type": "plain_text", "text": line, "emoji": False}}
                       for line in lines],
            "unfurl_links": False, "unfurl_media": False, "parse": "none"}


class Store:
    def __init__(self, table):
        self.table = table

    def get(self, key):
        return self.table.get_item(Key={"notification_id": key}, ConsistentRead=True).get("Item") or {}

    def claim(self, key, owner, now, lease):
        try:
            self.table.update_item(Key={"notification_id": key},
                UpdateExpression="SET #s = :pending, lease_owner = :owner, lease_until = :lease, updated_at = :now",
                ConditionExpression="attribute_not_exists(notification_id) OR (#s = :retry AND (attribute_not_exists(retry_at) OR retry_at <= :now)) OR (#s = :pending AND lease_until < :now)",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":pending": "PENDING", ":retry": "RETRY", ":owner": owner, ":lease": now + lease, ":now": now})
            return True
        except Exception as exc:
            if getattr(exc, "response", {}).get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return False
            raise

    def receipt(self, key, owner, status, *, now, code=None, retry_at=0):
        values = {":owner": owner, ":status": status, ":now": now, ":retry": retry_at, ":code": code or "NONE"}
        self.table.update_item(Key={"notification_id": key},
            UpdateExpression="SET #s = :status, updated_at = :now, retry_at = :retry, last_code = :code REMOVE lease_owner, lease_until",
            ConditionExpression="lease_owner = :owner",
            ExpressionAttributeNames={"#s": "status"}, ExpressionAttributeValues=values)

    def begin_send(self, key, owner, method, now):
        # Journal before an external side effect. A killed Lambda cannot silently
        # reclaim an expired first-post lease and post a second copy.
        self.table.update_item(Key={"notification_id": key},
            UpdateExpression="SET send_started = :yes, last_method = :method, send_started_at = :now",
            ConditionExpression="lease_owner = :owner",
            ExpressionAttributeValues={":yes": True, ":method": method, ":now": now, ":owner": owner})

    def hold_expired_post(self, key, now):
        self.table.update_item(Key={"notification_id": key},
            UpdateExpression="SET #s = :unknown, updated_at = :now, last_code = :code REMOVE lease_owner, lease_until",
            ConditionExpression="#s = :pending AND lease_until < :now AND send_started = :yes AND last_method = :post",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":unknown": "UNKNOWN", ":pending": "PENDING", ":now": now,
                ":code": "EXPIRED_POST_LEASE_UNCERTAIN", ":yes": True, ":post": "chat.postMessage"})

    def put_message(self, key, value):
        self.table.put_item(Item={"notification_id": key, **value})

    def begin_update(self, key, owner, previous, now, lease):
        # Different revisions have different event receipts. Serialize updates
        # of their shared message and compare the observed version atomically.
        try:
            self.table.update_item(Key={"notification_id": key},
                UpdateExpression="SET update_owner = :owner, update_until = :lease",
                ConditionExpression="revision = :revision AND ts = :ts AND channel = :channel AND (attribute_not_exists(update_owner) OR update_until < :now)",
                ExpressionAttributeValues={":revision": previous["revision"], ":ts": previous["ts"],
                    ":channel": previous["channel"], ":owner": owner, ":lease": now + lease, ":now": now})
        except Exception as exc:
            if getattr(exc, "response", {}).get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                raise NoticeError("MESSAGE_UPDATE_BUSY_OR_CHANGED", retry_after=15) from None
            raise

    def commit_update(self, key, owner, value):
        self.table.put_item(Item={"notification_id": key, **value},
                            ConditionExpression="update_owner = :owner", ExpressionAttributeValues={":owner": owner})

    def release_update(self, key, owner):
        self.table.update_item(Key={"notification_id": key}, UpdateExpression="REMOVE update_owner, update_until",
                               ConditionExpression="update_owner = :owner", ExpressionAttributeValues={":owner": owner})

    def begin_first_post(self, key, owner, now, lease):
        try:
            self.table.update_item(Key={"notification_id": key},
                UpdateExpression="SET delivery_state = :posting, gate_owner = :owner, gate_until = :lease",
                ConditionExpression="attribute_not_exists(ts) AND (attribute_not_exists(delivery_state) OR delivery_state = :retry)",
                ExpressionAttributeValues={":posting": "POSTING", ":retry": "RETRY", ":owner": owner, ":lease": now + lease})
        except Exception as exc:
            if getattr(exc, "response", {}).get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                raise NoticeError("FIRST_POST_GATE_BUSY") from None
            raise

    def first_post_gate_state(self, key, owner, state, code):
        self.table.update_item(Key={"notification_id": key},
            UpdateExpression="SET delivery_state = :state, last_delivery_code = :code REMOVE gate_owner, gate_until",
            ConditionExpression="gate_owner = :owner",
            ExpressionAttributeValues={":state": state, ":code": code, ":owner": owner})

    def hold_expired_gate(self, key, now):
        self.table.update_item(Key={"notification_id": key},
            UpdateExpression="SET delivery_state = :unknown, last_delivery_code = :code REMOVE gate_owner, gate_until",
            ConditionExpression="delivery_state = :posting AND gate_until < :now AND attribute_not_exists(ts)",
            ExpressionAttributeValues={":unknown": "UNKNOWN", ":posting": "POSTING", ":now": now,
                ":code": "EXPIRED_FIRST_POST_GATE_UNCERTAIN"})


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


class Slack:
    def __init__(self, token, opener=None):
        if not isinstance(token, str) or not re.fullmatch(r"xoxb-[A-Za-z0-9-]{15,2043}", token):
            raise NoticeError("INVALID_BOT_TOKEN")
        self.token = token
        self.opener = urllib.request.build_opener(_NoRedirect()).open if opener is None else opener

    def call(self, method, payload):
        if method not in {"chat.postMessage", "chat.update"}:
            raise NoticeError("UNSUPPORTED_SLACK_METHOD")
        request = urllib.request.Request("https://slack.com/api/" + method,
            data=json.dumps(payload, ensure_ascii=False).encode(), method="POST",
            headers={"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + self.token})
        try:
            with self.opener(request, timeout=10) as response:
                data = response.read(65537)
                if len(data) > 65536:
                    raise NoticeError("SLACK_RESPONSE_TOO_LARGE", ambiguous=method == "chat.postMessage")
                result = json.loads(data)
        except urllib.error.HTTPError as exc:
            exc.close()
            if exc.code == 429:
                try:
                    delay = max(1, min(3600, int(exc.headers.get("Retry-After", "60"))))
                except (TypeError, ValueError):
                    delay = 60
                raise NoticeError("SLACK_RATE_LIMITED", retry_after=delay) from None
            raise NoticeError("SLACK_HTTP_" + str(exc.code), ambiguous=exc.code >= 500 and method == "chat.postMessage") from None
        except NoticeError:
            raise
        except (ValueError, OSError, TimeoutError):
            raise NoticeError("SLACK_DELIVERY_UNCERTAIN", ambiguous=method == "chat.postMessage") from None
        if not isinstance(result, dict) or result.get("ok") is not True:
            code = result.get("error") if isinstance(result, dict) else None
            # Only Slack's explicit, well-formed rejection establishes definite
            # non-delivery. Parseable but unexpected JSON is still uncertain.
            definite_rejection = (isinstance(result, dict) and result.get("ok") is False
                and isinstance(code, str) and re.fullmatch(r"[a-z_]{1,70}", code))
            if not definite_rejection:
                raise NoticeError("SLACK_DELIVERY_UNCERTAIN", ambiguous=method == "chat.postMessage")
            raise NoticeError("SLACK_API_" + code, retry_after=60 if code == "ratelimited" else 0)
        channel, stamp = result.get("channel"), result.get("ts")
        if (not isinstance(channel, str) or not CHANNEL.fullmatch(channel) or channel != payload.get("channel")
                or not isinstance(stamp, str) or not TS.fullmatch(stamp)):
            raise NoticeError("SLACK_DELIVERY_UNCERTAIN", ambiguous=method == "chat.postMessage")
        return {"channel": channel, "ts": stamp}


def committed_notice(event, notice, *, config, registry, cases, s3, now):
    """Read only selected journal metadata before receipts, secrets or Slack."""
    if cases is None:
        raise NoticeError("CASE_PUBLICATION_JOURNAL_REQUIRED")
    if notice["stamp"] > int(now * 1_000_000):
        raise NoticeError("PUBLICATION_TIME_IN_FUTURE")
    # Never request task_token, report_md, private reasoning or the pending body.
    fields = ["case_id", "service_id", "dashboard_bucket", "dashboard_key", "publication_state", "publication_revision",
              "dashboard_publication.state", "dashboard_publication.revision", "dashboard_publication.phase",
              "dashboard_publication.bucket", "dashboard_publication.key", "dashboard_publication.body_sha256",
              "dashboard_publication.outbox_attribute", "dashboard_publication.outbox.event_id"]
    visible = ("schema_version", "case_id", "service_id", "report_kind", "publication_type", "status", "published_at",
               "result", "target", "tier", "report_summary", "recommended_action", "decision", "event_id", "revision",
               "response_status", "actual_outcomes", "failure_codes", "response_error_code", "decided_action", "action_status")
    for name in ("dashboard_notification_hotl", "dashboard_notification_hitl", "dashboard_notification_outcome"):
        fields.extend((name + ".status", name + ".event_id"))
        fields.extend(name + ".detail." + field for field in visible)
    aliases, paths = {}, []
    for path in fields:
        parts = []
        for name in path.split("."):
            alias = "#f" + str(len(aliases))
            aliases[alias] = name
            parts.append(alias)
        paths.append(".".join(parts))
    case = cases.get_item(Key={"case_id": notice["case_id"]}, ConsistentRead=True,
                          ProjectionExpression=",".join(paths), ExpressionAttributeNames=aliases).get("Item") or {}
    if (case.get("case_id") != notice["case_id"] or case.get("service_id") != notice["service_id"]
            or case.get("dashboard_bucket") != notice["bucket"] or case.get("dashboard_key") != notice["key"]):
        raise NoticeError("CASE_PUBLICATION_SCOPE_MISMATCH")
    attribute = "dashboard_notification_outcome" if notice["phase"] == "OUTCOME" else "dashboard_notification_" + notice["kind"].lower()
    outbox, job = case.get(attribute), case.get("dashboard_publication") or {}
    if (case.get("publication_state") == "PENDING" and isinstance(job.get("outbox"), dict)
            and job["outbox"].get("event_id") == notice["revision"]):
        raise NoticeError("PUBLICATION_NOT_COMMITTED", retry_after=60)
    if not isinstance(outbox, dict):
        raise NoticeError("CASE_OUTBOX_IDENTITY_MISMATCH")
    try:
        authoritative = project(dict(outbox, status="PENDING"), expected_case=notice["case_id"], expected_service=notice["service_id"])
        expected = normalize({"account": config.account, "region": config.region, "source": "whs.hitl.dashboard",
                              "detail-type": "DashboardReportPublished.v1", "detail": authoritative}, config, registry)
    except (ValueError, TypeError, KeyError):
        raise NoticeError("CASE_OUTBOX_IDENTITY_MISMATCH") from None
    if notice != expected:
        raise NoticeError("CASE_OUTBOX_CONTENT_MISMATCH")
    # A legitimate initial outbox remains in the journal after a terminal
    # publication. Its old S3 version must never replace the outcome message.
    if notice["phase"] == "INITIAL" and job.get("phase") == "OUTCOME":
        return "STALE"
    if case.get("publication_state") != "PUBLISHED" or job.get("state") != "PUBLISHED":
        raise NoticeError("PUBLICATION_NOT_COMMITTED", retry_after=60)
    if (job.get("phase") != notice["phase"] or job.get("outbox_attribute") != attribute
            or job.get("bucket") != notice["bucket"] or job.get("key") != notice["key"]
            or job.get("outbox", {}).get("event_id") != notice["revision"]
            or not DIGEST.fullmatch(str(job.get("body_sha256")))
            or not DIGEST.fullmatch(str(job.get("revision")))
            or case.get("publication_revision") != job.get("revision")):
        raise NoticeError("PRIVATE_PUBLICATION_IDENTITY_MISMATCH")
    revision = hashlib.sha256(json.dumps([notice["service_id"], notice["case_id"], notice["phase"], notice["revision"],
                                         job["body_sha256"]], separators=(",", ":")).encode()).hexdigest()
    if revision != job["revision"]:
        raise NoticeError("PRIVATE_PUBLICATION_IDENTITY_MISMATCH")
    # S3 can be ahead of the journal during another publication commit. Treat
    # its version mismatch as retryable without reading any report text.
    try:
        head = s3.head_object(Bucket=notice["bucket"], Key=notice["key"])
    except Exception:
        raise NoticeError("PUBLICATION_OBJECT_LOOKUP_UNAVAILABLE", retry_after=60) from None
    metadata = head.get("Metadata", {})
    if metadata.get("publication-revision") != revision or metadata.get("service-id") != notice["service_id"]:
        raise NoticeError("PUBLICATION_OBJECT_VERSION_NOT_COMMITTED", retry_after=60)
    return "COMMITTED"


def deliver(event, *, config, registry, store, s3, slack, cases=None, clock=time.time):
    if not CHANNEL.fullmatch(config.channel):
        raise NoticeError("INVALID_CHANNEL")
    notice = normalize(event, config, registry)
    if config.notify_after_utc and notice["stamp"] < utc_epoch(config.notify_after_utc):
        return "BEFORE_ACTIVATION_SKIPPED"
    now, owner = int(clock()), uuid.uuid4().hex
    if committed_notice(event, notice, config=config, registry=registry, cases=cases, s3=s3, now=clock()) == "STALE":
        return "STALE"
    existing = store.get(notice["event_key"])
    if existing.get("status") == "SENT":
        return "DUPLICATE"
    if existing.get("status") == "UNKNOWN":
        raise NoticeError("DELIVERY_UNKNOWN_REQUIRES_REVIEW")
    if (existing.get("status") == "PENDING" and existing.get("lease_until", now + 1) < now
            and existing.get("send_started") and existing.get("last_method") == "chat.postMessage"):
        previous = store.get(notice["message_key"])
        if previous.get("revision") != notice["revision"]:
            store.hold_expired_post(notice["event_key"], now)
            raise NoticeError("DELIVERY_UNKNOWN_REQUIRES_REVIEW")
    if not store.claim(notice["event_key"], owner, now, config.lease_seconds):
        raise NoticeError("CLAIM_BUSY_OR_RETRY_DELAY")
    method, called, first_gate, update_gate = None, False, False, False
    try:
        previous = store.get(notice["message_key"])
        if not previous.get("ts") and previous.get("delivery_state") == "UNKNOWN":
            raise NoticeError("CASE_DELIVERY_UNKNOWN_REQUIRES_REVIEW")
        if not previous.get("ts") and previous.get("delivery_state") == "POSTING":
            if previous.get("gate_until", now + 1) < now:
                store.hold_expired_gate(notice["message_key"], now)
                raise NoticeError("CASE_DELIVERY_UNKNOWN_REQUIRES_REVIEW")
            raise NoticeError("FIRST_POST_GATE_BUSY")
        if previous.get("revision") == notice["revision"]:
            store.receipt(notice["event_key"], owner, "SENT", now=now)
            return "DUPLICATE"
        previous_phase = previous.get("phase") or ("INITIAL" if previous.get("status") in INITIAL_STATUSES else "OUTCOME")
        # Standard SQS can deliver an outcome before its initial publication,
        # even with equal timestamps or a later replay timestamp on INITIAL.
        # Business phase wins over wall-clock ordering; initial never rewinds a
        # recorded outcome, and an outcome may advance an initial publication.
        phase_rewinds = previous.get("ts") and previous_phase == "OUTCOME" and notice["phase"] == "INITIAL"
        outcome_advances = previous.get("ts") and previous_phase == "INITIAL" and notice["phase"] == "OUTCOME"
        time_rewinds = previous.get("stamp", 0) > notice["stamp"] and not outcome_advances
        if phase_rewinds or time_rewinds:
            store.receipt(notice["event_key"], owner, "SENT", now=now, code="STALE_SKIPPED")
            return "STALE"
        payload = message_payload(notice, config.channel)
        method = "chat.update" if previous.get("ts") and previous.get("channel") == config.channel else "chat.postMessage"
        if method == "chat.update":
            payload["ts"] = previous["ts"]
            store.begin_update(notice["message_key"], owner, previous, now, config.lease_seconds)
            update_gate = True
        # Credential retrieval happens only for an eligible external delivery.
        # A failed Secrets call occurs before the first-post side-effect journal.
        if hasattr(slack, "prepare"):
            slack.prepare()
        if method == "chat.postMessage":
            store.begin_first_post(notice["message_key"], owner, now, config.lease_seconds)
            first_gate = True
        store.begin_send(notice["event_key"], owner, method, now)
        called = True
        result = slack.call(method, payload)
        value = {**result, "revision": notice["revision"], "stamp": notice["stamp"],
                 "status": notice["status"], "kind": notice["kind"], "phase": notice["phase"], "updated_at": now,
                 "delivery_state": "SENT"}
        if update_gate:
            store.commit_update(notice["message_key"], owner, value)
            update_gate = False
        else:
            store.put_message(notice["message_key"], value)
        if not store.get(notice["case_key"]).get("ts"):
            store.put_message(notice["case_key"], value)
        store.receipt(notice["event_key"], owner, "SENT", now=now)
        return "UPDATED" if method == "chat.update" else "POSTED"
    except NoticeError as exc:
        if update_gate:
            store.release_update(notice["message_key"], owner)
        if first_gate:
            store.first_post_gate_state(notice["message_key"], owner, "UNKNOWN" if exc.ambiguous else "RETRY", exc.code)
        store.receipt(notice["event_key"], owner, "UNKNOWN" if exc.ambiguous else "RETRY", now=now,
                      code=exc.code, retry_at=now + exc.retry_after)
        raise
    except Exception:
        # A successful first post followed by a database failure may have delivered.
        try:
            if update_gate:
                store.release_update(notice["message_key"], owner)
            if first_gate:
                store.first_post_gate_state(notice["message_key"], owner,
                    "UNKNOWN" if called else "RETRY", "POST_COMMIT_UNCERTAIN" if called else "DEPENDENCY_FAILED")
            store.receipt(notice["event_key"], owner, "UNKNOWN" if called and method == "chat.postMessage" else "RETRY",
                          now=now, code="POST_COMMIT_UNCERTAIN" if called else "DEPENDENCY_FAILED")
        except Exception:
            pass
        raise NoticeError("DEPENDENCY_FAILED") from None


_TOKEN_CACHE = {}


def get_token(secrets, config, clock=time.time):
    if not re.fullmatch(r"arn:aws(?:-us-gov|-cn)?:secretsmanager:" + re.escape(config.region) + ":" + re.escape(config.account) + r":secret:[A-Za-z0-9/_+=.@-]+", config.secret_arn):
        raise NoticeError("UNTRUSTED_SLACK_SECRET")
    cache_key = (config.account, config.region, config.secret_arn, config.secret_field)
    cached = _TOKEN_CACHE.get(cache_key, {})
    if cached.get("expires", 0) <= clock():
        result = secrets.get_secret_value(SecretId=config.secret_arn)
        if result.get("ARN", config.secret_arn) != config.secret_arn:
            raise NoticeError("UNTRUSTED_SLACK_SECRET")
        raw = result.get("SecretString")
        if not isinstance(raw, str) or len(raw) > 16384:
            raise NoticeError("INVALID_SLACK_SECRET")
        try:
            body = json.loads(raw)
            token = body[config.secret_field]
        except (ValueError, TypeError, KeyError):
            raise NoticeError("INVALID_SLACK_SECRET") from None
        Slack(token)  # Validate without making a request.
        # Lambda owns a fixed small set of secrets; bound the process cache.
        if len(_TOKEN_CACHE) >= 8:
            _TOKEN_CACHE.clear()
        cached = {"token": token, "expires": clock() + 300}
        _TOKEN_CACHE[cache_key] = cached
    return cached["token"]


class CredentialSlack:
    """Defer secret access until a validated, non-duplicate message can be sent."""
    def __init__(self, secrets, config):
        self.secrets, self.config, self.sender = secrets, config, None

    def prepare(self):
        if self.sender is None:
            self.sender = Slack(get_token(self.secrets, self.config))

    def call(self, method, payload):
        self.prepare()
        return self.sender.call(method, payload)


def handle_batch(event, *, dispatch, delay_retry=None):
    failures = []
    for record in event.get("Records", []):
        item_id = record.get("messageId")
        # SQS assigns this transport ID. Do not log an arbitrary supplied value.
        logged_id = item_id if isinstance(item_id, str) and re.fullmatch(r"[a-f0-9-]{36}", item_id) else "INVALID_TRANSPORT_ID"
        try:
            body = json.loads(record["body"])
            outcome = dispatch(body)
            LOG.info(json.dumps({"notification": outcome, "message_id": logged_id}))
        except Exception as exc:
            code = exc.code if isinstance(exc, NoticeError) else "UNEXPECTED_ERROR"
            LOG.warning(json.dumps({"notification": "FAILED", "code": code, "message_id": logged_id}))
            if delay_retry is not None and isinstance(exc, NoticeError) and exc.retry_after:
                try:
                    delay_retry(record, exc.retry_after)
                except Exception:
                    LOG.warning(json.dumps({"notification": "RETRY_DELAY_FAILED", "message_id": logged_id}))
            failures.append({"itemIdentifier": item_id})
    return {"batchItemFailures": failures}


def handler(event, context):
    if os.environ.get("NOTIFICATIONS_ENABLED", "false") != "true":
        return {"batchItemFailures": [], "notifications": "DISABLED"}
    import boto3
    config = Config(account=os.environ["EXPECTED_ACCOUNT"], region=os.environ["AWS_REGION"],
                    channel=os.environ["SLACK_CHANNEL_ID"], secret_arn=os.environ["SLACK_SECRET_ARN"],
                    dashboard_bucket=os.environ["AUDIT_BUCKET"], secret_field=os.environ.get("SLACK_SECRET_FIELD", "bot_token"),
                    notify_after_utc=os.environ.get("NOTIFY_AFTER_UTC", ""), default_service_id=os.environ.get("DEFAULT_SERVICE_ID", ""))
    dynamodb = boto3.resource("dynamodb")
    store = Store(dynamodb.Table(os.environ["NOTIFICATIONS_TABLE"]))
    registry = dynamodb.Table(os.environ["REGISTRY_TABLE"])
    cases = dynamodb.Table(os.environ["CASES_TABLE"])
    s3, secrets, sqs = boto3.client("s3"), boto3.client("secretsmanager"), boto3.client("sqs")
    sender = CredentialSlack(wrap(secrets, context), config)
    def dispatch(body):
        return deliver(body, config=config, registry=registry, store=store, s3=s3, slack=sender, cases=cases)
    def delay_retry(record, seconds):
        sqs.change_message_visibility(QueueUrl=os.environ["QUEUE_URL"], ReceiptHandle=record["receiptHandle"],
                                      VisibilityTimeout=max(180, min(43200, seconds)))
    return handle_batch(event, dispatch=dispatch, delay_retry=delay_retry)
