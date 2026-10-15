"""One service-scoped publication contract for terminal and response reports."""
import hashlib
import ipaddress
import json
import re
from notification_content import selected_content
from outcome_metadata import CASE, augment_outbox, validate_service


def make_outbox(case_id, service_id, state, tier, bucket, key, published_at, *, phase="OUTCOME",
                kind=None, summary=None, recommended_action=None, decision=None, target=None,
                response=None, failures=None, previous=None):
    validate_service(service_id)
    if not isinstance(case_id, str) or not CASE.fullmatch(case_id) or not isinstance(state, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,47}", state):
        raise ValueError("INVALID_PUBLICATION_IDENTITY")
    if phase not in {"INITIAL", "OUTCOME"}:
        raise ValueError("INVALID_PUBLICATION_PHASE")
    kind = kind or ("HOTL" if tier in (0, 1) else "HITL")
    if kind not in {"HOTL", "HITL"}:
        raise ValueError("INVALID_PUBLICATION_KIND")
    selected_target = {}
    if isinstance(target, dict):
        instance = target.get("instance_id")
        if isinstance(instance, str) and re.fullmatch(r"i-[a-f0-9]{8,17}", instance):
            selected_target["instance_id"] = instance
        try:
            if isinstance(target.get("source_ip"), str):
                selected_target["source_ip"] = str(ipaddress.ip_address(target["source_ip"]))
        except ValueError:
            pass
    detail = {"schema_version": "1.0", "case_id": case_id, "report_kind": kind, "publication_type": phase,
              "status": state, "published_at": published_at, "result": {"bucket": bucket, "key": key}, "target": selected_target}
    if not isinstance(tier, bool) and tier in (0, 1, 2, 3):
        detail["tier"] = int(tier)
    detail.update(selected_content(summary, recommended_action, decision, phase=phase, status=state))
    outbox = augment_outbox({"status": "PENDING", "event_id": "pending", "created_at": published_at, "detail": detail},
                           service_id, response, failures)
    if isinstance(previous, dict) and previous.get("event_id") == outbox["event_id"]:
        return previous
    return outbox


def outbox_attribute(phase, kind):
    return "dashboard_notification_outcome" if phase == "OUTCOME" else "dashboard_notification_" + kind.lower()
