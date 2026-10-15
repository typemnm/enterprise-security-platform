"""Resolve trusted per-service response settings; never default to another service."""
import re
from decimal import Decimal
import hashlib
import json

SERVICE = re.compile(r"[a-z][a-z0-9-]{2,47}\Z")
IPSET = re.compile(r"arn:(aws(?:-us-gov|-cn)?):wafv2:([a-z0-9-]+):(\d{12}):(regional|global)/ipset/([^/]+)/([a-z0-9-]+)\Z")


def revision_for(record):
    def number(value):
        if isinstance(value, Decimal) and value.is_finite() and value == value.to_integral_value(): return int(value)
        raise ValueError("NONCANONICAL_SERVICE_POLICY")
    fields = {key: value for key, value in record.items() if key not in {"revision", "updated_at"}}
    return hashlib.sha256(json.dumps(fields, sort_keys=True, separators=(",", ":"), default=number).encode()).hexdigest()


def resolve(table, service_id, *, account, require_enforce=False):
    if not SERVICE.fullmatch(str(service_id)):
        raise ValueError("SERVICE_ID_REQUIRED")
    item = table.get_item(Key={"service_id": service_id}, ConsistentRead=True).get("Item")
    if not item or item.get("enabled") is not True or item.get("account_id") != account:
        raise ValueError("SERVICE_NOT_REGISTERED")
    if item.get("response_mode") not in {"observe", "enforce"}:
        raise ValueError("INVALID_RESPONSE_POLICY")
    if require_enforce and item["response_mode"] != "enforce":
        raise ValueError("AUTOMATIC_RESPONSE_DISABLED")
    if not isinstance(item.get("resource_arns"), list) or not item["resource_arns"]:
        raise ValueError("SERVICE_RESOURCE_SCOPE_MISSING")
    for arn in item["resource_arns"]:
        if not isinstance(arn, str) or len(arn.split(":", 5)) != 6 or arn.split(":", 5)[4] != account:
            raise ValueError("SERVICE_ACCOUNT_MISMATCH")
    if not isinstance(item.get("allowed_actions"), list) or set(item["allowed_actions"]) - {"monitor", "block_ip", "isolate_instance"}:
        raise ValueError("INVALID_ACTION_POLICY")
    if "block_ip" in item["allowed_actions"]:
        match = IPSET.fullmatch(str(item.get("waf_ipset_arn")))
        if not match or match.group(3) != account:
            raise ValueError("INVALID_SERVICE_IPSET")
        scope = "CLOUDFRONT" if match.group(4) == "global" else "REGIONAL"
        if item.get("waf_scope") != scope or scope == "CLOUDFRONT" and match.group(2) != "us-east-1":
            raise ValueError("INVALID_SERVICE_WAF_SCOPE")
        item = dict(item, waf_region=match.group(2), waf_name=match.group(5), waf_id=match.group(6))
    return item


def ipset_for_address(service, address):
    import ipaddress
    parsed = ipaddress.ip_address(address)
    if parsed.version == 4:
        return dict(service, waf_family="IPV4")
    match = IPSET.fullmatch(str(service.get("waf_ipv6_ipset_arn")))
    if (not match or match.group(3) != service["account_id"]
            or ("CLOUDFRONT" if match.group(4) == "global" else "REGIONAL") != service["waf_scope"]
            or match.group(2) != service["waf_region"]):
        raise ValueError("SERVICE_IPV6_IPSET_REQUIRED")
    return dict(service, waf_ipset_arn=service["waf_ipv6_ipset_arn"], waf_name=match.group(5),
                waf_id=match.group(6), waf_family="IPV6")


def validate_case(case, service, source_ip, case_id, *, human_approved=False):
    if not case or case.get("case_id") != case_id or case.get("service_id") != service["service_id"]:
        raise ValueError("CASE_SERVICE_MISMATCH")
    if case.get("target", {}).get("source_ip") != source_ip:
        raise ValueError("CASE_TARGET_MISMATCH")
    tier = case.get("tier")
    # boto3 DynamoDB resource returns Number as Decimal, including integer
    # tiers. Fractional, boolean and string tiers cannot authorize an action.
    valid_tier = (type(tier) is int or isinstance(tier, Decimal) and tier.is_finite() and tier == tier.to_integral_value())
    if human_approved:
        if (not valid_tier or tier not in {2, 3}
                or case.get("status") != "DECIDED_APPROVE" or case.get("decision") != "approve"
                or case.get("callback_status") != "SENT" or case.get("approved_action") != "block_ip"
                or service.get("manual_block_enabled") is not True):
            raise ValueError("HUMAN_APPROVAL_NOT_COMMITTED")
        return True
    if case.get("recommended_action") != "block_ip":
        raise ValueError("CASE_TARGET_MISMATCH")
    if not valid_tier or tier != 1:
        raise ValueError("AUTOMATIC_BLOCK_TIER_DENIED")
    return True
