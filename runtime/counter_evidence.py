"""Bind automatic response claims to the provider-ingress observation journal."""
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import ipaddress
import json
import re
import time


def integer(value):
    return type(value) is int or isinstance(value, Decimal) and value.is_finite() and value == value.to_integral_value()


def observation_epoch(value):
    if not isinstance(value, str) or len(value) > 50:
        raise ValueError("AUTOMATIC_OBSERVATION_TIME_INVALID")
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if moment.tzinfo is None or moment.utcoffset() != timezone.utc.utcoffset(moment):
            raise ValueError()
        return moment.timestamp()
    except (ValueError, OverflowError):
        raise ValueError("AUTOMATIC_OBSERVATION_TIME_INVALID") from None


def counter_identity(service_id, source_ip, policy_revision, rule_id, window_seconds, observed_at):
    """Pure derivation, byte-compatible with existing ingress counter keys."""
    if (not isinstance(service_id, str) or not re.fullmatch(r"[a-z][a-z0-9-]{2,47}", service_id)
            or not isinstance(policy_revision, str) or not policy_revision
            or not isinstance(rule_id, str) or not re.fullmatch(r"[A-Za-z0-9_:.-]{1,128}", rule_id)
            or not integer(window_seconds) or not 60 <= window_seconds <= 3600):
        raise ValueError("AUTOMATIC_COUNTER_IDENTITY_INVALID")
    try:
        address = str(ipaddress.ip_address(source_ip))
    except (ValueError, TypeError):
        raise ValueError("AUTOMATIC_COUNTER_IDENTITY_INVALID") from None
    seconds, observed = int(window_seconds), int(observation_epoch(observed_at))
    material = json.dumps([service_id, address, policy_revision, rule_id, observed // seconds])
    key = "threshold#" + hashlib.sha256(material.encode()).hexdigest()
    return {"key": key, "aggregate_event_id": hashlib.sha256(("waf-policy-aggregate-v1:" + key).encode()).hexdigest(),
            "window_start": observed // seconds * seconds, "window_seconds": seconds, "source_ip": address}


def verify_counter_evidence(signal, service, leases, *, now=None):
    """Strong-read authority; input numbers and hashes alone never authorize."""
    now = time.time() if now is None else now
    policy, proof = service.get("auto_block_policy"), signal.get("policy_evidence")
    if (leases is None or not isinstance(policy, dict) or policy.get("enabled") is not True
            or not isinstance(proof, dict) or signal.get("signal_type") != "WAF_PATTERN"
            or signal.get("signal_type") not in policy.get("signal_types", [])
            or proof.get("rule_id") not in policy.get("rule_ids", [])
            or proof.get("policy_revision") != service.get("revision")):
        raise ValueError("AUTOMATIC_COUNTER_EVIDENCE_REQUIRED")
    numbers = (proof.get("matched_requests"), proof.get("threshold"), proof.get("window_seconds"),
               policy.get("min_requests"), policy.get("window_seconds"))
    if (any(not integer(value) for value in numbers)
            or not 2 <= policy["min_requests"] <= 10000
            or proof["threshold"] != policy["min_requests"]
            or proof["window_seconds"] != policy["window_seconds"]
            or proof["matched_requests"] < proof["threshold"]):
        raise ValueError("AUTOMATIC_COUNTER_EVIDENCE_INVALID")
    identity = counter_identity(service["service_id"], signal.get("target", {}).get("source_ip"),
                                service["revision"], proof["rule_id"], proof["window_seconds"], signal.get("observed_at"))
    if signal.get("event_id") != identity["aggregate_event_id"]:
        raise ValueError("AUTOMATIC_AGGREGATE_IDENTITY_MISMATCH")
    row = leases.get_item(Key={"lease_id": identity["key"]}, ConsistentRead=True).get("Item") or {}
    expected = {"lease_id": identity["key"], "phase": "OBSERVATION_COUNT", "service_id": service["service_id"],
                "source_validation_version": "STORED_CLOUDWATCH_V1",
                "source_ip": identity["source_ip"], "rule_id": proof["rule_id"], "policy_revision": service["revision"],
                "window_start": identity["window_start"], "window_seconds": identity["window_seconds"], "threshold": proof["threshold"]}
    if any(row.get(name) != value for name, value in expected.items()):
        raise ValueError("AUTOMATIC_COUNTER_JOURNAL_MISMATCH")
    if not integer(row.get("count")) or row["count"] < proof["matched_requests"]:
        raise ValueError("AUTOMATIC_COUNTER_COUNT_UNPROVEN")
    latest, observed = observation_epoch(row.get("verified_latest_observation")), observation_epoch(signal.get("observed_at"))
    start, seconds = identity["window_start"], identity["window_seconds"]
    if (not start <= observed <= latest < start + seconds or latest >= int(now) + 1
            or not 0 <= int(now) - int(latest) <= seconds):
        raise ValueError("AUTOMATIC_COUNTER_OBSERVATION_EXPIRED_OR_CHANGED")
    return True
