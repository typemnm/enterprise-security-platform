"""Conditional stream/scheduled redelivery of committed, selected outboxes."""
import ipaddress
import json
import os
import re
import time
import uuid
from outcome_metadata import CASE, publication_metadata, selected_components, safe_code, validate_service
from publication import conditional, error_code
from notification_content import sanitize_summary

ATTRIBUTES = ("dashboard_notification_hotl", "dashboard_notification_hitl", "dashboard_notification_outcome")
DIGEST = re.compile(r"[a-f0-9]{64}\Z")
INSTANCE = re.compile(r"i-[a-f0-9]{8,17}\Z")


def project(outbox, *, expected_case, expected_service):
    if not isinstance(outbox, dict) or outbox.get("status") not in {"PENDING", "EMITTING"}:
        return None
    detail, event_id = outbox.get("detail"), outbox.get("event_id")
    if not isinstance(detail, dict) or not isinstance(event_id, str) or not DIGEST.fullmatch(event_id):
        raise ValueError("INVALID_OUTBOX_EVENT")
    if detail.get("case_id") != expected_case or not CASE.fullmatch(expected_case) or detail.get("event_id") != event_id:
        raise ValueError("OUTBOX_CASE_MISMATCH")
    if detail.get("service_id") != validate_service(expected_service):
        raise ValueError("OUTBOX_SERVICE_MISMATCH")
    kind, phase, status = detail.get("report_kind"), detail.get("publication_type"), detail.get("status")
    if kind not in {"HOTL", "HITL"} or phase not in {"INITIAL", "OUTCOME"} or not isinstance(status, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,47}", status):
        raise ValueError("INVALID_OUTBOX_STATE")
    location = detail.get("result")
    if not isinstance(location, dict) or set(location) != {"bucket", "key"} or not isinstance(location["bucket"], str):
        raise ValueError("INVALID_OUTBOX_POINTER")
    if location["key"] != expected_service + "/" + expected_case + ".md" and not (expected_service == "legacy-whs" and location["key"] == expected_case + ".md"):
        raise ValueError("INVALID_OUTBOX_POINTER")
    stamp = detail.get("published_at")
    if not isinstance(stamp, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z", stamp):
        raise ValueError("INVALID_OUTBOX_TIMESTAMP")
    selected = {"schema_version": "1.0", "event_id": event_id, "revision": event_id, "case_id": expected_case,
                "service_id": expected_service, "report_kind": kind, "publication_type": phase, "status": status,
                "result": location, "published_at": stamp}
    tier = detail.get("tier")
    if not isinstance(tier, bool) and tier in (0, 1, 2, 3):
        selected["tier"] = int(tier)
    summary = sanitize_summary(detail.get("report_summary"))
    if summary:
        selected["report_summary"] = summary
    action = detail.get("recommended_action")
    if isinstance(action, str) and action in {"block_ip", "isolate_instance", "revoke_credentials", "monitor", "none"}:
        selected["recommended_action"] = action
    decision = detail.get("decision")
    if isinstance(decision, str) and decision in {"approve", "reject"}:
        selected["decision"] = decision
    selected.update(publication_metadata(expected_service, {"components": detail.get("actual_outcomes"),
                    "response_status": detail.get("response_status"), "error_code": detail.get("response_error_code")},
                    {name: {"Error": code} for name, code in (detail.get("failure_codes") or {}).items()} if isinstance(detail.get("failure_codes"), dict) else None))
    target = detail.get("target")
    if isinstance(target, dict):
        safe = {}
        if isinstance(target.get("instance_id"), str) and INSTANCE.fullmatch(target["instance_id"]):
            safe["instance_id"] = target["instance_id"]
        try:
            if isinstance(target.get("source_ip"), str):
                safe["source_ip"] = str(ipaddress.ip_address(target["source_ip"]))
        except ValueError:
            pass
        if safe:
            selected["target"] = safe
    return selected


def refresh_marker(table, case_id, now):
    case = table.get_item(Key={"case_id": case_id}, ConsistentRead=True).get("Item") or {}
    due = []
    for name in ATTRIBUTES:
        item = case.get(name)
        if isinstance(item, dict) and item.get("status") in {"PENDING", "EMITTING"}:
            due.append(int(item.get("delivery_lease_until", now) if item["status"] == "EMITTING" else item.get("delivery_retry_at", now)))
    pending, retry_at = bool(due), min(due) if due else int(case.get("notification_retry_at", now))
    state = "PENDING" if pending else "IDLE"
    # Stream mutations performed by this publisher must not recursively create
    # a fresh marker write every second. Idle and unchanged leases are no-ops.
    if case.get("notification_state") == state and (not pending or case.get("notification_retry_at") == retry_at):
        return
    names, values, checks = {}, {":state": state, ":now": retry_at}, []
    for index, name in enumerate(ATTRIBUTES):
        item = case.get(name)
        names["#o" + str(index)] = name
        if isinstance(item, dict) and item.get("event_id"):
            names["#eid"] = "event_id"
            names["#state"] = "status"
            values[":e" + str(index)] = item["event_id"]
            values[":s" + str(index)] = item.get("status")
            checks.append("#o" + str(index) + ".#eid = :e" + str(index) + " AND #o" + str(index) + ".#state = :s" + str(index))
        else:
            checks.append("attribute_not_exists(#o" + str(index) + ")")
    try:
        table.update_item(Key={"case_id": case_id}, UpdateExpression="SET notification_state = :state, notification_retry_at = :now",
                          ConditionExpression=" AND ".join(checks), ExpressionAttributeNames=names, ExpressionAttributeValues=values)
    except Exception as error:
        if not conditional(error):
            raise


def publish_outbox(case_id, attribute, table, events, bus, *, clock=time.time, lease_seconds=90):
    if attribute not in ATTRIBUTES:
        raise ValueError("INVALID_OUTBOX_ATTRIBUTE")
    case = table.get_item(Key={"case_id": case_id}, ConsistentRead=True).get("Item") or {}
    item = case.get(attribute)
    if not isinstance(item, dict) or item.get("status") == "EMITTED":
        return "DUPLICATE" if item else "ABSENT"
    detail = project(item, expected_case=case_id, expected_service=case.get("service_id"))
    if detail is None:
        return "ABSENT"
    if detail["result"] != {"bucket": case.get("dashboard_bucket"), "key": case.get("dashboard_key")}:
        raise ValueError("OUTBOX_DESTINATION_MISMATCH")
    event_id, owner, now = item["event_id"], uuid.uuid4().hex, int(clock())
    names = {"#outbox": attribute, "#status": "status", "#event": "event_id"}
    try:
        table.update_item(Key={"case_id": case_id},
            UpdateExpression="SET #outbox.#status = :emitting, #outbox.delivery_owner = :owner, #outbox.delivery_lease_until = :lease, notification_retry_at = :lease",
            ConditionExpression="service_id = :service AND #outbox.#event = :event AND (#outbox.#status = :pending OR (#outbox.#status = :emitting AND #outbox.delivery_lease_until <= :now)) AND (attribute_not_exists(#outbox.delivery_retry_at) OR #outbox.delivery_retry_at <= :now)",
            ExpressionAttributeNames=names, ExpressionAttributeValues={":event": event_id, ":owner": owner, ":lease": now + lease_seconds,
                ":now": now, ":pending": "PENDING", ":emitting": "EMITTING", ":service": case["service_id"]})
    except Exception as error:
        if conditional(error):
            return "BUSY"
        raise
    try:
        result = events.put_events(Entries=[{"Source": "whs.hitl.dashboard", "DetailType": "DashboardReportPublished.v1",
                                           "EventBusName": bus, "Detail": json.dumps(detail, ensure_ascii=False)}])
        entries = result.get("Entries") or []
        if result.get("FailedEntryCount", 1) or len(entries) != 1 or not entries[0].get("EventId") or entries[0].get("ErrorCode"):
            raise RuntimeError("EVENT_DELIVERY_FAILED")
        table.update_item(Key={"case_id": case_id},
            UpdateExpression="SET #outbox.#status = :emitted, #outbox.emitted_at = :now REMOVE #outbox.delivery_owner, #outbox.delivery_lease_until, #outbox.delivery_retry_at",
            ConditionExpression="service_id = :service AND #outbox.#event = :event AND #outbox.delivery_owner = :owner AND #outbox.#status = :emitting",
            ExpressionAttributeNames=names, ExpressionAttributeValues={":emitted": "EMITTED", ":emitting": "EMITTING", ":event": event_id, ":owner": owner, ":now": int(clock()), ":service": case["service_id"]})
        refresh_marker(table, case_id, int(clock()))
        return "EMITTED"
    except Exception as error:
        try:
            table.update_item(Key={"case_id": case_id},
                UpdateExpression="SET #outbox.#status = :pending, #outbox.delivery_error_code = :code, #outbox.delivery_retry_at = :retry, notification_retry_at = :retry REMOVE #outbox.delivery_owner, #outbox.delivery_lease_until",
                ConditionExpression="service_id = :service AND #outbox.#event = :event AND #outbox.delivery_owner = :owner",
                ExpressionAttributeNames=names, ExpressionAttributeValues={":pending": "PENDING", ":event": event_id, ":owner": owner,
                    ":retry": int(clock()) + 30, ":code": error_code(error), ":service": case["service_id"]})
        except Exception:
            pass
        raise RuntimeError("OUTBOX_DELIVERY_PENDING") from None


def publish_case(case_id, table, events, bus, **kwargs):
    outcomes = {name: publish_outbox(case_id, name, table, events, bus, **kwargs) for name in ATTRIBUTES}
    refresh_marker(table, case_id, int(kwargs.get("clock", time.time)()))
    return outcomes


def stream_needs_delivery(record, now):
    dynamodb = record.get("dynamodb", {})
    new, old = dynamodb.get("NewImage", {}), dynamodb.get("OldImage", {})
    for name in ATTRIBUTES:
        item = new.get(name, {}).get("M", {})
        previous = old.get(name, {}).get("M", {})
        if item.get("status", {}).get("S") != "PENDING":
            continue
        try:
            due = int(item.get("delivery_retry_at", {}).get("N", 0))
        except (TypeError, ValueError):
            return True  # selected validation rejects malformed metadata safely
        if due <= now and (item.get("event_id") != previous.get("event_id") or item.get("status") != previous.get("status")):
            return True
    return False


def handler(event, context):
    import boto3
    table = boto3.resource("dynamodb").Table(os.environ["CASES_TABLE"])
    events, failed, outcomes = boto3.client("events"), [], []
    for record in event.get("Records", []):
        sequence = record.get("dynamodb", {}).get("SequenceNumber")
        try:
            if record.get("eventName") not in {"INSERT", "MODIFY"}:
                continue
            if not stream_needs_delivery(record, int(time.time())):
                continue
            case_id = record.get("dynamodb", {}).get("Keys", {}).get("case_id", {}).get("S")
            if not isinstance(case_id, str) or not CASE.fullmatch(case_id):
                raise ValueError("INVALID_STREAM_CASE")
            outcomes.append(publish_case(case_id, table, events, os.environ["NOTIFICATION_BUS"]))
        except Exception:
            if not sequence:
                raise RuntimeError("MISSING_STREAM_SEQUENCE") from None
            failed.append({"itemIdentifier": sequence})
    return {"batchItemFailures": failed, "processed": len(outcomes)}
