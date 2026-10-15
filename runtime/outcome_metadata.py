"""Bounded service and response facts; never retain Cause, raw events or tokens."""
import hashlib
import json
import re

SERVICE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
CASE = re.compile(r"inv-[0-9a-f]{32}\Z")
CODE = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,127}\Z")
OPERATION = re.compile(r"[A-Za-z0-9_.:-]{1,200}\Z")
COMPONENT_STATUSES = frozenset({"APPLIED", "ALREADY_PRESENT", "FAILED", "SKIPPED", "NOT_REQUIRED", "UNKNOWN"})
RESPONSE_STATUSES = frozenset({"APPLIED", "PARTIAL", "FAILED", "DRY_RUN", "SKIPPED", "UNVERIFIED"})
SUCCESS = frozenset({"APPLIED", "ALREADY_PRESENT"})
SLACK_STATUS_LABELS = {
    "AUTO_BLOCK_PARTIAL": "IP 차단 일부 적용 · 수동 확인 필요",
    "AUTO_BLOCK_UNVERIFIED": "IP 차단 적용 결과 미확인 · 수동 확인 필요",
    "AI1_FAILED": "1차 분석 실패 · 자동 대응 없음",
    "AI2_FAILED": "정밀 분석 실패 · 자동 대응 없음",
    "APPROVAL_FAILED": "승인 대기 처리 실패 · 수동 확인 필요",
    "PUBLICATION_FAILED": "보고서 게시 처리 실패 · 재시도 대기",
    "BLOCK_PARTIAL": "승인 후 IP 차단 일부 적용 · 확인 필요",
    "BLOCK_FAILED": "승인 후 IP 차단 실패 · 확인 필요",
    "BLOCK_UNVERIFIED": "승인 후 IP 차단 결과 미확인 · 확인 필요",
}


def safe_code(value):
    if not isinstance(value, str) or not value:
        return None
    if re.search(r"(?:AKIA|ASIA)[A-Z0-9]{12,}|xox[baprs]-|^eyJ|^[A-Za-z0-9_-]{40,}$", value):
        return "UNCLASSIFIED_ERROR"
    return value if CODE.fullmatch(value) else "UNCLASSIFIED_ERROR"


def validate_service(value):
    if not isinstance(value, str) or not SERVICE.fullmatch(value):
        raise ValueError("INVALID_SERVICE_ID")
    return value


def error_fields(payload):
    result = {}
    if not isinstance(payload, dict):
        return result
    for name in ("block_error", "isolation_error", "response_guard_error", "failure"):
        value = payload.get(name)
        if not isinstance(value, dict):
            continue
        code = safe_code(value.get("Error") or value.get("error_code") or value.get("Code"))
        if code:
            result[name] = {"Error": code}
    return result


def selected_components(value):
    if not isinstance(value, dict):
        return {}
    result = {}
    for name in ("waf", "nacl"):
        component = value.get(name)
        if not isinstance(component, dict):
            continue
        status = component.get("status")
        if not isinstance(status, str) or status not in COMPONENT_STATUSES:
            continue
        selected = {"status": status}
        code = safe_code(component.get("error_code"))
        if code:
            selected["error_code"] = code
        result[name] = selected
    return result


def block_result(payload, requested_outcome, service_id, *, case_id=None):
    """Return actual component facts, never promote Lambda HTTP 200 to success."""
    validate_service(service_id)
    payload = payload if isinstance(payload, dict) else {}
    response = payload.get("response")
    block = payload.get("block")
    if not isinstance(response, dict) and isinstance(block, dict):
        response = block.get("result") or block.get("Payload")
    failures = error_fields(payload)
    if not isinstance(response, dict):
        failed = requested_outcome == "AUTO_BLOCK_FAILED" or "block_error" in failures
        return {"outcome": "AUTO_BLOCK_FAILED" if failed else "AUTO_BLOCK_UNVERIFIED",
                "response_status": "FAILED" if failed else "UNVERIFIED", "components": {},
                "required_components": ["waf"], "error_code": failures.get("block_error", {}).get("Error", "RESPONSE_EVIDENCE_MISSING")}
    components = selected_components(response.get("components"))
    required = response.get("required_components", ["waf"])
    valid_required = isinstance(required, list) and bool(required) and len(required) <= 2 and all(
        isinstance(name, str) and name in {"waf", "nacl"} for name in required
    ) and len(set(required)) == len(required)
    status = response.get("status")
    valid = response.get("schema_version") == "1.0" and response.get("service_id") == service_id and valid_required and (case_id is None or response.get("case_id") == case_id)
    result = {"components": components, "required_components": required if valid_required else ["waf"]}
    operation_id = response.get("operation_id")
    if isinstance(operation_id, str) and OPERATION.fullmatch(operation_id):
        result["operation_id"] = operation_id
    if not valid or not isinstance(status, str) or status not in RESPONSE_STATUSES:
        result.update(outcome="AUTO_BLOCK_UNVERIFIED", response_status="UNVERIFIED", error_code="INVALID_RESPONSE_CONTRACT")
        return result
    if status in {"DRY_RUN", "SKIPPED"}:
        if any(name not in components for name in required) or any(value["status"] not in {"SKIPPED", "NOT_REQUIRED"} for value in components.values()):
            result.update(outcome="AUTO_BLOCK_UNVERIFIED", response_status="UNVERIFIED", error_code="RESPONSE_RESULT_INDETERMINATE")
            return result
        result.update(outcome="AUTO_DRY_RUN" if status == "DRY_RUN" else "AUTO_RESPONSE_EXEMPT", response_status=status)
        return result
    if any(name not in components for name in required):
        result.update(outcome="AUTO_BLOCK_UNVERIFIED", response_status="UNVERIFIED", error_code="REQUIRED_COMPONENT_EVIDENCE_MISSING")
        return result
    successful = [name for name in required if components[name]["status"] in SUCCESS]
    failed = [name for name in required if components[name]["status"] == "FAILED"]
    if len(successful) == len(required) and status == "APPLIED":
        actual = "PARTIAL" if any(item["status"] == "FAILED" for item in components.values()) else "APPLIED"
    elif successful and (failed or status in {"FAILED", "PARTIAL"}):
        actual = "PARTIAL"
    elif failed and not successful:
        actual = "FAILED"
    else:
        actual = "UNVERIFIED"
    result.update(response_status=actual, outcome={"APPLIED": "AUTO_BLOCKED", "PARTIAL": "AUTO_BLOCK_PARTIAL",
                  "FAILED": "AUTO_BLOCK_FAILED", "UNVERIFIED": "AUTO_BLOCK_UNVERIFIED"}[actual])
    code = safe_code(response.get("error_code"))
    if code:
        result["error_code"] = code
    return result


def publication_metadata(service_id, response=None, failures=None):
    result = {"service_id": validate_service(service_id)}
    if isinstance(response, dict):
        components = selected_components(response.get("components"))
        if components:
            result["actual_outcomes"] = components
        status = response.get("response_status") or response.get("status")
        if isinstance(status, str) and status in RESPONSE_STATUSES:
            result["response_status"] = status
        code = safe_code(response.get("error_code"))
        if code:
            result["response_error_code"] = code
    selected_errors = {}
    if isinstance(failures, dict):
        for name in ("block_error", "isolation_error", "response_guard_error", "failure"):
            error = failures.get(name)
            code = safe_code(error.get("Error")) if isinstance(error, dict) else None
            if code:
                selected_errors[name] = code
    if selected_errors:
        result["failure_codes"] = selected_errors
    return result


def augment_outbox(outbox, service_id, response=None, failures=None):
    """Give selected facts a stable service-scoped identity."""
    if not isinstance(outbox, dict) or not isinstance(outbox.get("detail"), dict):
        raise ValueError("INVALID_PUBLICATION_OUTBOX")
    detail = dict(outbox["detail"])
    detail.update(publication_metadata(service_id, response, failures))
    material = {"service_id": service_id, "case_id": detail.get("case_id"), "kind": detail.get("report_kind"),
                "phase": detail.get("publication_type"), "status": detail.get("status"),
                "response_status": detail.get("response_status"), "actual_outcomes": detail.get("actual_outcomes"),
                "failure_codes": detail.get("failure_codes"), "response_error_code": detail.get("response_error_code"),
                **{name: detail.get(name) for name in ("tier", "report_summary", "recommended_action", "decision", "decided_action", "action_status", "target", "result")}}
    revision = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    detail.update(event_id=revision, revision=revision)
    return {**outbox, "event_id": revision, "detail": detail}
