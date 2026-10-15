"""Case-bound WAF response with durable idempotency and explicit partial results."""
import hashlib
import ipaddress
import os
import time
import uuid
import re
from decimal import Decimal
from .service_scope import resolve, validate_case, ipset_for_address


class ResponseIndeterminate(RuntimeError):
    pass


def code(error):
    if isinstance(error, ValueError) and re.fullmatch(r"[A-Z][A-Z0-9_]{1,99}", str(error)):
        return str(error)
    value = getattr(error, "response", {}).get("Error", {}).get("Code", "AWS_OPERATION_FAILED")
    return value if isinstance(value, str) and value.replace("_", "").isalnum() and len(value) <= 100 else "AWS_OPERATION_FAILED"


def update_waf(waf, service, source_ip, retries=4):
    address = ipaddress.ip_address(source_ip)
    cidr = source_ip + "/" + str(address.max_prefixlen)
    for attempt in range(retries):
        current = waf.get_ip_set(Name=service["waf_name"], Scope=service["waf_scope"], Id=service["waf_id"])
        item = current["IPSet"]
        if item.get("ARN") != service["waf_ipset_arn"] or item.get("IPAddressVersion") != service.get("waf_family", "IPV4"):
            raise ValueError("WAF_METADATA_MISMATCH")
        addresses = item["Addresses"]
        if cidr in addresses:
            return {"status": "ALREADY_PRESENT"}
        request = {"Name": service["waf_name"], "Scope": service["waf_scope"], "Id": service["waf_id"],
                   "Addresses": addresses + [cidr], "LockToken": current["LockToken"],
                   "Description": item.get("Description", "")}
        try:
            waf.update_ip_set(**request)
            return {"status": "APPLIED"}
        except Exception as error:
            response = getattr(error, "response", {})
            if not response or response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0) >= 500:
                # A lost acknowledgement can follow a successful mutation.
                # A read proving the requested block is present is actionable;
                # absence/failing read does not prove the write never happened.
                try:
                    observed = waf.get_ip_set(Name=service["waf_name"], Scope=service["waf_scope"], Id=service["waf_id"])["IPSet"]
                    if observed.get("ARN") == service["waf_ipset_arn"] and cidr in observed.get("Addresses", []):
                        return {"status": "APPLIED"}
                except Exception:
                    pass
                raise ResponseIndeterminate("WAF_WRITE_RESULT_UNKNOWN") from None
            if code(error) != "WAFOptimisticLockException" or attempt + 1 == retries:
                raise
            time.sleep(min(0.1 * 2 ** attempt, 1))
    raise RuntimeError("WAF_RETRY_LIMIT")


def nacl_block(ec2, service, source_ip):
    # The caller holds the per-NACL distributed writer lease. Unreserved rules
    # are never selected and a placeholder must already be configured.
    nacl_id, slots = service.get("nacl_id"), service.get("nacl_slots")
    if not nacl_id or not isinstance(slots, list) or not slots or any(
            not (type(n) is int or isinstance(n, Decimal) and n.is_finite() and n == n.to_integral_value())
            or not 1 <= n <= 32766 for n in slots):
        raise ValueError("NACL_POLICY_INVALID")
    address = ipaddress.ip_address(source_ip)
    cidr = str(address) + "/" + str(address.max_prefixlen)
    field = "CidrBlock" if address.version == 4 else "Ipv6CidrBlock"
    placeholder = service.get("nacl_placeholder_cidr", "203.0.113.0/32")
    if ipaddress.ip_network(placeholder).version != address.version:
        raise ValueError("NACL_ADDRESS_FAMILY_NOT_CONFIGURED")
    nacls = ec2.describe_network_acls(NetworkAclIds=[nacl_id])["NetworkAcls"]
    if len(nacls) != 1 or nacls[0].get("VpcId") != service.get("vpc_id"):
        raise ValueError("NACL_SERVICE_SCOPE_MISMATCH")
    entries = {entry["RuleNumber"]: entry for entry in nacls[0].get("Entries", []) if entry.get("Egress") is True}
    candidate = None
    for slot in sorted(int(n) for n in slots):
        value = entries.get(slot, {})
        if value.get("Protocol") != "-1" or value.get("RuleAction") != "deny":
            continue
        if value.get(field) == cidr:
            return {"status": "ALREADY_PRESENT", "rule_number": slot}
        if candidate is None and value.get(field) == placeholder:
            candidate = slot
    if candidate is None:
        raise ValueError("NACL_RESERVED_SLOTS_EXHAUSTED")
    try:
        ec2.replace_network_acl_entry(NetworkAclId=nacl_id, RuleNumber=candidate, Protocol="-1", RuleAction="deny",
                                      Egress=True, **{field: cidr})
    except Exception as error:
        response = getattr(error, "response", {})
        if not response or response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0) >= 500:
            try:
                observed = ec2.describe_network_acls(NetworkAclIds=[nacl_id])["NetworkAcls"]
                if len(observed) == 1 and observed[0].get("VpcId") == service.get("vpc_id") and any(
                    row.get("Egress") is True and row.get("RuleNumber") == candidate and row.get("Protocol") == "-1"
                    and row.get("RuleAction") == "deny" and row.get(field) == cidr for row in observed[0].get("Entries", [])):
                    return {"status": "APPLIED", "rule_number": candidate}
            except Exception:
                pass
            raise ResponseIndeterminate("NACL_WRITE_RESULT_UNKNOWN") from None
        raise
    return {"status": "APPLIED", "rule_number": candidate}


def acquire(table, key, owner, ttl=120):
    now = int(time.time())
    try:
        table.put_item(Item={"lease_id": key, "owner": owner, "expires_at": now + ttl},
                       ConditionExpression="attribute_not_exists(lease_id) OR expires_at < :now",
                       ExpressionAttributeValues={":now": now})
        return True
    except Exception as error:
        if code(error) == "ConditionalCheckFailedException":
            return False
        raise


def release(table, key, owner):
    table.delete_item(Key={"lease_id": key}, ConditionExpression="#o = :owner",
                      ExpressionAttributeNames={"#o": "owner"}, ExpressionAttributeValues={":owner": owner})


def run(event, *, registry, cases, operations, leases, waf_factory, ec2_factory, account, binding_validator=None, default_dry_run=True):
    allowed = {"service_id", "case_id", "attacker_ip", "operation_id", "dry_run", "human_approved"}
    if not isinstance(event, dict) or set(event) - allowed:
        raise ValueError("INVALID_RESPONSE_INPUT")
    service = resolve(registry, event.get("service_id"), account=account)
    case_id, address = event.get("case_id"), event.get("attacker_ip")
    parsed = ipaddress.ip_address(address)
    address = str(parsed)
    if not parsed.is_global or parsed.is_multicast or parsed.is_reserved:
        raise ValueError("NON_PUBLIC_IP_DENIED")
    service = ipset_for_address(service, address)
    if "block_ip" not in service["allowed_actions"]:
        raise ValueError("SERVICE_ACTION_DENIED")
    case = cases.get_item(Key={"case_id": case_id}, ConsistentRead=True).get("Item")
    human_approved = event.get("human_approved", False)
    if type(human_approved) is not bool:
        raise ValueError("APPROVAL_FLAG_MUST_BE_BOOLEAN")
    validate_case(case, service, address, case_id, human_approved=human_approved)
    networks = [ipaddress.ip_network(value, strict=True) for value in service.get("protected_cidrs", [])]
    if any(parsed in network for network in networks if network.version == parsed.version):
        raise ValueError("PROTECTED_IP_DENIED")
    required = ["waf"] + (["nacl"] if service.get("nacl_enabled") is True else [])
    operation_id = event.get("operation_id")
    execution = case.get("workflow_execution_arn")
    execution_pattern = (r"arn:aws(?:-us-gov|-cn)?:states:[a-z0-9-]+:" + re.escape(account)
                         + r":execution:[A-Za-z0-9_-]{1,80}:" + re.escape(case_id))
    if (not isinstance(operation_id, str) or not 8 <= len(operation_id) <= 256
            or operation_id != execution or not re.fullmatch(execution_pattern, operation_id)):
        raise ValueError("RESPONSE_WORKFLOW_EXECUTION_MISMATCH")
    operation_key = "block#" + hashlib.sha256(f"{service['service_id']}:{case_id}:{operation_id}".encode()).hexdigest()
    base = {"schema_version": "1.0", "service_id": service["service_id"], "case_id": case_id,
            "operation_id": operation_id, "required_components": required}
    dry_run = event.get("dry_run", True)
    case_dry_run = case.get("dry_run", True)
    if type(dry_run) is not bool or type(case_dry_run) is not bool or type(default_dry_run) is not bool:
        raise ValueError("DRY_RUN_MUST_BE_BOOLEAN")
    if default_dry_run or case_dry_run or dry_run or (service["response_mode"] != "enforce" and not human_approved):
        return dict(base, status="DRY_RUN", components={name: {"status": "SKIPPED"} for name in required})
    previous = operations.get_item(Key={"lease_id": operation_key}, ConsistentRead=True).get("Item")
    if previous:
        if previous.get("result"):
            # A completed request never re-blocks after an administrator rollback.
            return previous["result"]
        known = previous.get("components") or {"waf": {"status": "UNKNOWN", "error_code": "PREVIOUS_RESPONSE_INDETERMINATE"}}
        return dict(base, status="SKIPPED", components=dict(known, nacl={"status": "SKIPPED"}))
    if case.get("registry_revision") != service.get("revision"):
        raise ValueError("RESPONSE_POLICY_REVISION_CHANGED")
    if not human_approved:
        from .case_pipeline import automatic_policy
        from .counter_evidence import verify_counter_evidence
        proof = {name: case.get(name) for name in ("target", "signal_type", "policy_evidence", "observed_at")}
        if not automatic_policy(proof, service, now=int(time.time())):
            raise ValueError("AUTOMATIC_RESPONSE_EVIDENCE_EXPIRED_OR_CHANGED")
    if binding_validator is not None:
        binding_validator(service)
    if not human_approved:
        proof["event_id"] = case.get("source_event_id")
        verify_counter_evidence(proof, service, leases, now=time.time())
    owner = uuid.uuid4().hex
    try:
        operations.put_item(Item={"lease_id": operation_key, "owner": owner, "phase": "WAF_CALL_STARTED",
                                  "service_id": service["service_id"], "case_id": case_id},
                            ConditionExpression="attribute_not_exists(lease_id)")
    except Exception as error:
        if code(error) == "ConditionalCheckFailedException":
            return dict(base, status="SKIPPED", components={"waf": {"status": "FAILED", "error_code": "RESPONSE_IN_PROGRESS"}})
        raise
    components = {"nacl": {"status": "NOT_REQUIRED"}}
    try:
        components["waf"] = update_waf(waf_factory(service["waf_region"]), service, address)
    except ResponseIndeterminate:
        components["waf"] = {"status": "UNKNOWN", "error_code": "WAF_WRITE_RESULT_UNKNOWN"}
    except Exception as error:
        components["waf"] = {"status": "FAILED", "error_code": code(error)}
    # Persist the first component before making a second side effect. A process
    # timeout can then be reported as partial/unknown instead of losing WAF facts.
    operations.update_item(Key={"lease_id": operation_key}, UpdateExpression="SET components = :components, phase = :phase",
                           ConditionExpression="#o = :owner", ExpressionAttributeNames={"#o": "owner"},
                           ExpressionAttributeValues={":components": components, ":phase": "WAF_COMMITTED", ":owner": owner})
    if "nacl" in required:
        if components["waf"]["status"] not in {"APPLIED", "ALREADY_PRESENT"}:
            components["nacl"] = {"status": "SKIPPED"}
        else:
            lock_key = "nacl#" + service["nacl_id"]
            locked = False
            try:
                locked = acquire(leases, lock_key, owner)
                if not locked:
                    raise ValueError("NACL_WRITER_BUSY")
                components["nacl"] = nacl_block(ec2_factory(service["region"]), service, address)
            except ResponseIndeterminate:
                components["nacl"] = {"status": "UNKNOWN", "error_code": "NACL_WRITE_RESULT_UNKNOWN"}
            except Exception as error:
                components["nacl"] = {"status": "FAILED", "error_code": code(error)}
            finally:
                if locked:
                    try:
                        release(leases, lock_key, owner)
                    except Exception:
                        pass  # lease has a bounded expiry; no unrelated owner deletion
    succeeded = [components[name]["status"] in {"APPLIED", "ALREADY_PRESENT"} for name in required]
    status = ("APPLIED" if all(succeeded) else "PARTIAL" if any(succeeded) else
              "UNVERIFIED" if any(components[name]["status"] == "UNKNOWN" for name in required) else "FAILED")
    result = dict(base, status=status, components=components)
    operations.update_item(Key={"lease_id": operation_key}, UpdateExpression="SET #r = :result, phase = :complete",
                           ConditionExpression="#o = :owner", ExpressionAttributeNames={"#r": "result", "#o": "owner"},
                           ExpressionAttributeValues={":result": result, ":complete": "COMPLETED", ":owner": owner})
    return result


def handler(event, context):
    import boto3
    from botocore.config import Config
    settings = Config(connect_timeout=2, read_timeout=5, retries={"mode": "standard", "total_max_attempts": 2})
    resource = boto3.resource("dynamodb", config=settings)
    return run(event, registry=resource.Table(os.environ["REGISTRY_TABLE"]), cases=resource.Table(os.environ["CASES_TABLE"]),
               operations=resource.Table(os.environ["OPERATIONS_TABLE"]), leases=resource.Table(os.environ["LEASE_TABLE"]),
               account=os.environ["EXPECTED_ACCOUNT"], binding_validator=assert_binding,
               default_dry_run=os.environ.get("DEFAULT_DRY_RUN", "true") != "false",
               waf_factory=lambda region: boto3.client("wafv2", region_name=region, config=settings),
               ec2_factory=lambda region: boto3.client("ec2", region_name=region, config=settings))


def assert_binding(service):
    from .discovery import AWS
    api = AWS()
    if service.get("resource_type") not in {"ALB", "CLOUDFRONT"} or len(service["resource_arns"]) != 1:
        raise ValueError("RESPONSE_RESOURCE_BINDING_REQUIRED")
    resource = {"type": service["resource_type"], "arn": service["resource_arns"][0], "region": service["region"],
                "id": service["resource_arns"][0].rsplit("/", 1)[-1]}
    if api.associated_acl(resource) != service.get("web_acl_arn"):
        raise ValueError("RESPONSE_WAF_ASSOCIATION_CHANGED")
    if api.acl_resources(resource, service["web_acl_arn"]) != set(service["resource_arns"]):
        raise ValueError("RESPONSE_SHARED_WEBACL_DENIED")
    current = api.current_acl(resource)["WebACL"]
    rules = current.get("Rules", [])
    matching = [rule for rule in rules if rule.get("Statement") == {"IPSetReferenceStatement": {"ARN": service["waf_ipset_arn"]}}
                and rule.get("Action") == {"Block": {}}]
    if not matching:
        raise ValueError("RESPONSE_IPSET_RULE_CHANGED")
    # An earlier allow or opaque rule group could short-circuit this block.
    first = min(rule["Priority"] for rule in matching)
    for rule in rules:
        if rule["Priority"] < first and ("Allow" in rule.get("Action", {}) or
                any(key in rule.get("Statement", {}) for key in ("RuleGroupReferenceStatement", "ManagedRuleGroupStatement"))
                and rule.get("OverrideAction") != {"Count": {}}):
            raise ValueError("RESPONSE_IPSET_PRIORITY_REVIEW_REQUIRED")
