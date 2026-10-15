"""Private callback CAS. The caller receives flags and facts, never a TaskToken."""
from datetime import datetime, timezone
from decimal import Decimal
import ipaddress
import json
import os
import re
import time
import uuid
from outcome_metadata import safe_code
from notification_content import sanitize_summary
from publication import conditional
from service_scope import resolve


def parse_key(value, default_service_id=None):
    if not isinstance(value, str):
        raise ValueError("INVALID_APPROVAL_KEY")
    match = re.fullmatch(r"([a-z][a-z0-9-]{2,62})/(inv-[0-9a-f]{32})\.md", value)
    if match:
        return match.groups()
    legacy = re.fullmatch(r"(inv-[0-9a-f]{32})\.md", value)
    if legacy and default_service_id == "legacy-whs":
        return default_service_id, legacy.group(1)
    raise ValueError("INVALID_APPROVAL_KEY")


def view(case, service, now):
    pending = case.get("status") == "AWAITING_APPROVAL" and not case.get("decision") and bool(case.get("task_token"))
    expires = case.get("approval_expires_at")
    if expires is not None and int(expires) <= now:
        pending = False
    target = {}
    value = case.get("target")
    if isinstance(value, dict):
        if isinstance(value.get("instance_id"), str) and re.fullmatch(r"i-[a-f0-9]{8,17}", value["instance_id"]):
            target["instance_id"] = value["instance_id"]
        try:
            if isinstance(value.get("source_ip"), str):
                target["source_ip"] = str(ipaddress.ip_address(value["source_ip"]))
        except ValueError:
            pass
    result = {"ok": True, "case_id": case["case_id"], "service_id": service["service_id"],
              "status": case.get("status"), "target": target, "can_approve": pending,
              "can_reject": pending, "pending": pending, "can_retry": False, "can_retry_reject": False}
    tier = case.get("tier")
    if type(tier) in (int, Decimal) and tier in (0, 1, 2, 3):
        result["tier"] = int(tier)
    for name in ("recommended_action", "approved_action"):
        value = case.get(name)
        if isinstance(value, str) and value in {"monitor", "none", "block_ip"}:
            result[name] = value
    # Authenticated dashboard audit metadata only. Outboxes never receive these
    # user-entered fields. Preserve private first-actor evidence in the ledger.
    actor = case.get("decided_by")
    if isinstance(actor, str) and re.fullmatch(r"[A-Za-z0-9@.:_-]{1,128}", actor):
        selected_actor = sanitize_summary(actor)
        if selected_actor:
            result["decided_by"] = selected_actor
    decided_at = case.get("decided_at")
    if isinstance(decided_at, str) and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", decided_at):
        result["decided_at"] = decided_at
    reason = case.get("decision_reason")
    if isinstance(reason, str):
        result["decision_reason"] = sanitize_summary(reason)[:500]
    callback = case.get("callback_status")
    if callback in {"SENDING", "SENT", "FAILED", "UNKNOWN"}:
        result["callback_status"] = callback
    if case.get("decision") in {"approve", "reject"}:
        result["decision"] = case["decision"]
    return result


def handle(event, table, registry, sfn, *, account, default_service_id=None, clock=time.time):
    if not isinstance(event, dict) or set(event) - {"operation", "key", "decision", "reason", "user"}:
        raise ValueError("INVALID_APPROVAL_REQUEST")
    service_id, case_id = parse_key(event.get("key"), default_service_id)
    service = resolve(registry, service_id, account=account)
    case = table.get_item(Key={"case_id": case_id}, ConsistentRead=True).get("Item") or {}
    if case.get("case_id") != case_id or case.get("service_id") != service_id or case.get("dashboard_key") != event["key"]:
        raise ValueError("APPROVAL_CASE_SCOPE_MISMATCH")
    now = int(clock())
    if event.get("operation", "decide") == "status":
        return view(case, service, now)
    if event.get("operation", "decide") != "decide" or not isinstance(event.get("decision"), str) or event.get("decision") not in {"approve", "reject"}:
        raise ValueError("INVALID_APPROVAL_DECISION")
    if not view(case, service, now)["can_approve"]:
        return {**view(case, service, now), "ok": False, "code": "APPROVAL_ALREADY_DECIDED_OR_EXPIRED"}
    user, reason = event.get("user"), event.get("reason", "")
    if not isinstance(user, str) or not re.fullmatch(r"[A-Za-z0-9@.:_-]{1,128}", user) or not isinstance(reason, str) or len(reason) > 500:
        raise ValueError("INVALID_APPROVAL_ACTOR_OR_REASON")
    decision, owner = event["decision"], uuid.uuid4().hex
    action = case.get("recommended_action", "none") if decision == "approve" else "none"
    if action not in {"block_ip", "monitor", "none"}:
        action = "none"
    if action == "block_ip" and "block_ip" not in service["allowed_actions"]:
        raise ValueError("APPROVED_ACTION_OUTSIDE_SERVICE_POLICY")
    stamp = datetime.fromtimestamp(now, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    names = {"#status": "status", "#decision": "decision"}
    try:
        table.update_item(Key={"case_id": case_id},
            UpdateExpression="SET #decision = :decision, decided_by = :user, decision_reason = :reason, decided_at = :at, #status = :decided, approved_action = :action, callback_status = :sending, callback_owner = :owner",
            ConditionExpression="service_id = :service AND #status = :awaiting AND attribute_not_exists(#decision) AND task_token = :token AND (attribute_not_exists(approval_expires_at) OR approval_expires_at > :now)",
            ExpressionAttributeNames=names, ExpressionAttributeValues={":decision": decision, ":user": user, ":reason": reason,
                ":at": stamp, ":decided": "DECIDED_APPROVE" if decision == "approve" else "DECIDED_REJECT", ":action": action,
                ":sending": "SENDING", ":owner": owner, ":service": service_id, ":awaiting": "AWAITING_APPROVAL",
                ":token": case["task_token"], ":now": now})
    except Exception as error:
        if not conditional(error):
            raise
        current = table.get_item(Key={"case_id": case_id}, ConsistentRead=True).get("Item") or {}
        return {**view(current, service, now), "ok": False, "code": "APPROVAL_ALREADY_DECIDED"}
    try:
        sfn.send_task_success(taskToken=case["task_token"], output=json.dumps({"case_id": case_id, "service_id": service_id,
            "decision": decision, "approved_action": action, "user": user, "at": stamp}))
        table.update_item(Key={"case_id": case_id},
            UpdateExpression="SET callback_status = :sent, callback_sent_at = :at REMOVE task_token, callback_owner",
            ConditionExpression="service_id = :service AND callback_owner = :owner AND #decision = :decision",
            ExpressionAttributeNames={"#decision": "decision"}, ExpressionAttributeValues={":sent": "SENT", ":at": stamp,
                ":service": service_id, ":owner": owner, ":decision": decision})
    except Exception as error:
        current = table.get_item(Key={"case_id": case_id}, ConsistentRead=True).get("Item") or {}
        if current.get("callback_status") == "SENT" and current.get("decision") == decision:
            return view(current, service, now)
        code = safe_code(getattr(error, "response", {}).get("Error", {}).get("Code")) or "CALLBACK_DELIVERY_UNCONFIRMED"
        state = "FAILED" if code in {"TaskTimedOut", "TaskDoesNotExist", "InvalidToken"} else "UNKNOWN"
        try:
            table.update_item(Key={"case_id": case_id},
                UpdateExpression="SET callback_status = :state, callback_error_code = :code REMOVE callback_owner",
                ConditionExpression="service_id = :service AND callback_owner = :owner AND #decision = :decision",
                ExpressionAttributeNames={"#decision": "decision"}, ExpressionAttributeValues={":state": state, ":code": code,
                    ":service": service_id, ":owner": owner, ":decision": decision})
        except Exception:
            pass
        return {"ok": False, "case_id": case_id, "service_id": service_id, "status": "DECIDED_APPROVE" if decision == "approve" else "DECIDED_REJECT",
                "callback_status": state, "code": code, "can_approve": False, "can_reject": False, "pending": False,
                "can_retry": False, "can_retry_reject": False}
    current = table.get_item(Key={"case_id": case_id}, ConsistentRead=True).get("Item") or {}
    return view(current, service, now)


def handler(event, context):
    import boto3
    resource = boto3.resource("dynamodb")
    return handle(event, resource.Table(os.environ["CASES_TABLE"]), resource.Table(os.environ["REGISTRY_TABLE"]), boto3.client("stepfunctions"),
                  account=os.environ["EXPECTED_ACCOUNT"], default_service_id=os.environ.get("DEFAULT_SERVICE_ID"))
