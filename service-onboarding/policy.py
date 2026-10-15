"""Manage a discovered service's response policy; --plan is entirely local.

Only policy fields can be submitted. --apply resolves the owned installation
and existing registry record, preserving every discovered resource binding.
"""
import argparse
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from runtime.service_scope import revision_for
SERVICE = re.compile(r"[a-z][a-z0-9-]{2,47}\Z")
INSTALLATION = re.compile(r"[a-z][a-z0-9-]{2,30}\Z")
REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-\d\Z")
RULE = re.compile(r"[A-Za-z0-9_:.-]{1,128}\Z")
GROUP = re.compile(r"[A-Za-z0-9][A-Za-z0-9_+=,.@-]{0,127}\Z")
POLICY_FIELDS = frozenset({"response_mode", "manual_block_enabled", "auto_block_policy", "protected_cidrs",
                           "allowed_actions", "allowed_admin_groups", "allowed_reader_groups"})
REQUIRED = frozenset({"service_id", "response_mode", "manual_block_enabled", "auto_block_policy", "protected_cidrs"})
ACTIONS = frozenset({"monitor", "block_ip"})


class PolicyError(RuntimeError):
    """A bounded operator-facing code, never a submitted value or AWS response."""


def _safe_identifier(value, pattern):
    return (isinstance(value, str) and pattern.fullmatch(value) is not None
            and not value.startswith("arn:")
            and not re.search(r"xox[baprs]-|^eyJ|(?:AKIA|ASIA)[A-Z0-9]{12,}", value))


def _list(value, *, maximum, pattern=None, choices=None, allow_empty=True):
    if not isinstance(value, list) or len(value) > maximum or not allow_empty and not value:
        raise PolicyError("INVALID_POLICY_LIST")
    if any(not isinstance(item, str) or choices is not None and item not in choices
           or pattern is not None and not _safe_identifier(item, pattern) for item in value):
        raise PolicyError("INVALID_POLICY_LIST")
    if len(value) != len(set(value)):
        raise PolicyError("DUPLICATE_POLICY_VALUE")
    return sorted(value)


def validate(document):
    if not isinstance(document, dict) or not REQUIRED <= set(document) or set(document) - (REQUIRED | POLICY_FIELDS):
        raise PolicyError("INVALID_POLICY_FIELDS")
    if not isinstance(document["service_id"], str) or not SERVICE.fullmatch(document["service_id"]):
        raise PolicyError("INVALID_SERVICE_ID")
    if not isinstance(document["response_mode"], str) or document["response_mode"] not in {"observe", "enforce"} or type(document["manual_block_enabled"]) is not bool:
        raise PolicyError("INVALID_RESPONSE_POLICY")
    auto = document["auto_block_policy"]
    expected = {"enabled", "signal_types", "rule_ids", "window_seconds", "min_requests"}
    if (not isinstance(auto, dict) or "enabled" not in auto or set(auto) - expected
            or type(auto["enabled"]) is not bool or auto["enabled"] and set(auto) != expected):
        raise PolicyError("INVALID_AUTOMATIC_POLICY")
    seconds, threshold = auto.get("window_seconds"), auto.get("min_requests")
    if ("window_seconds" in auto and (type(seconds) is not int or not 60 <= seconds <= 3600)
            or "min_requests" in auto and (type(threshold) is not int or not 2 <= threshold <= 10000)):
        raise PolicyError("INVALID_AUTOMATIC_THRESHOLD")
    signals = _list(auto.get("signal_types", []), maximum=1, choices={"WAF_PATTERN"}, allow_empty=not auto["enabled"])
    rules = _list(auto.get("rule_ids", []), maximum=100, pattern=RULE, allow_empty=not auto["enabled"])
    networks = _list(document["protected_cidrs"], maximum=256)
    selected = []
    for network in networks:
        try:
            if "/" not in network:
                raise ValueError()
            selected.append(str(ipaddress.ip_network(network, strict=True)))
        except ValueError:
            raise PolicyError("INVALID_PROTECTED_CIDR") from None
    if len(set(selected)) != len(selected):
        raise PolicyError("DUPLICATE_PROTECTED_CIDR")
    result = {"service_id": document["service_id"], "response_mode": document["response_mode"],
              "manual_block_enabled": document["manual_block_enabled"],
              "auto_block_policy": {"enabled": auto["enabled"]},
              "protected_cidrs": sorted(selected)}
    for name, value in (("signal_types", signals), ("rule_ids", rules), ("window_seconds", seconds), ("min_requests", threshold)):
        if value:
            result["auto_block_policy"][name] = value
    if "allowed_actions" in document:
        result["allowed_actions"] = _list(document["allowed_actions"], maximum=2, choices=ACTIONS, allow_empty=False)
    for name in ("allowed_admin_groups", "allowed_reader_groups"):
        if name in document:
            result[name] = _list(document[name], maximum=100, pattern=GROUP)
    return result


def policy_changes(document, service, ceiling):
    existing = service.get("allowed_actions")
    if not isinstance(existing, list) or any(not isinstance(action, str) for action in existing):
        raise PolicyError("INVALID_SERVICE_ACTION_POLICY")
    permitted = set(existing) & set(ceiling) & ACTIONS
    requested = set(document.get("allowed_actions", sorted(permitted)))
    if not requested or not requested <= permitted:
        raise PolicyError("INSTALLATION_ACTION_CEILING_DENIED")
    changes = {name: document[name] for name in POLICY_FIELDS if name in document}
    changes["allowed_actions"] = sorted(requested)
    if (document["response_mode"] == "enforce" or document["manual_block_enabled"] or document["auto_block_policy"]["enabled"]) and "block_ip" not in requested:
        raise PolicyError("BLOCK_ACTION_NOT_ALLOWED")
    # Omitted groups are preserved; they cannot accidentally broaden readers or
    # lock operators out during an unrelated response-policy edit.
    revision = revision_for({**service, **changes})
    return changes, revision


def plan(document, *, installation_id=None):
    document = validate(document)
    if installation_id is not None and (not isinstance(installation_id, str) or not INSTALLATION.fullmatch(installation_id)):
        raise PolicyError("INVALID_INSTALLATION_ID")
    return {"status": "PLAN", "service_id": document["service_id"], "installation_id": installation_id or "RESOLVED_AT_APPLY",
            "policy": {name: value for name, value in document.items() if name != "service_id"},
            "aws_calls": 0, "resource_inputs_accepted": False,
            "apply_checks": ["STS account", "owned foundation stack", "enabled registered service", "installation/service action ceiling", "revision CAS"],
            "pending_cases": "POLICY_REVISION_CHANGE_REQUIRES_NEW_REVIEW"}


def _installer():
    # Reuse the single argv-based AWS CLI helper without importing boto3 in plan.
    spec = importlib.util.spec_from_file_location("enterprise_policy_installer", ROOT / "install.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def apply(document, *, installation_id, profile, region, enable_enforcement=False, call=None):
    document = validate(document)
    if not isinstance(installation_id, str) or not INSTALLATION.fullmatch(installation_id):
        raise PolicyError("INVALID_INSTALLATION_ID")
    if not isinstance(region, str) or not REGION.fullmatch(region) or not isinstance(profile, str) or not profile or len(profile) > 128:
        raise PolicyError("EXPLICIT_PROFILE_REGION_REQUIRED")
    if document["response_mode"] == "enforce" and enable_enforcement is not True:
        raise PolicyError("ENABLE_ENFORCEMENT_REQUIRED")
    if call is None:
        call = _installer().cli
    invoke = lambda *arguments: call(*arguments, profile=profile, region=region)
    identity = invoke("sts", "get-caller-identity")
    account, actor = identity.get("Account"), identity.get("Arn", "")
    actor_parts = actor.split(":", 5) if isinstance(actor, str) else []
    if (not isinstance(account, str) or not re.fullmatch(r"\d{12}", account) or len(actor_parts) != 6
            or actor_parts[:2] != ["arn", "aws"] or actor_parts[2] not in {"iam", "sts"} or actor_parts[4] != account):
        raise PolicyError("UNSUPPORTED_ACCOUNT_PARTITION_REVIEW_REQUIRED")
    stacks = invoke("cloudformation", "describe-stacks", "--stack-name", installation_id).get("Stacks", [])
    if len(stacks) != 1:
        raise PolicyError("FOUNDATION_OWNERSHIP_REVIEW_REQUIRED")
    stack = stacks[0]
    tags = {row.get("Key"): row.get("Value") for row in stack.get("Tags", [])}
    if (tags.get("ManagedBy") != "enterprise-security" or tags.get("InstallationId") != installation_id
            or stack.get("StackName") != installation_id
            or not str(stack.get("StackId", "")).startswith(f"arn:aws:cloudformation:{region}:{account}:stack/{installation_id}/")):
        raise PolicyError("FOUNDATION_OWNERSHIP_REVIEW_REQUIRED")
    if stack.get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"}:
        raise PolicyError("FOUNDATION_NOT_STABLE_REVIEW_REQUIRED")
    outputs = {row["OutputKey"]: row["OutputValue"] for row in stack.get("Outputs", [])}
    table, table_arn = outputs.get("RegistryTableName"), outputs.get("RegistryTableArn")
    if (outputs.get("InstallationId") != installation_id or not isinstance(table, str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{3,255}", table)
            or table_arn != f"arn:aws:dynamodb:{region}:{account}:table/{table}"):
        raise PolicyError("REGISTRY_OUTPUT_SCOPE_REVIEW_REQUIRED")
    parameters = {row["ParameterKey"]: row["ParameterValue"] for row in stack.get("Parameters", [])}
    ceiling = parameters.get("AllowedActions", "").split(",")
    if not ceiling or len(ceiling) != len(set(ceiling)) or set(ceiling) - ACTIONS:
        raise PolicyError("INSTALLATION_ACTION_POLICY_REQUIRED")
    from boto3.dynamodb.types import TypeDeserializer, TypeSerializer
    serializer, deserializer = TypeSerializer(), TypeDeserializer()
    encode = lambda values: {name: serializer.serialize(value) for name, value in values.items()}
    key = json.dumps(encode({"service_id": document["service_id"]}), separators=(",", ":"))
    raw = invoke("dynamodb", "get-item", "--table-name", table, "--key", key, "--consistent-read").get("Item", {})
    service = {name: deserializer.deserialize(value) for name, value in raw.items()}
    if (service.get("service_id") != document["service_id"] or service.get("account_id") != account or service.get("enabled") is not True
            or not isinstance(service.get("revision"), str) or not 1 <= len(service["revision"]) <= 128):
        raise PolicyError("SERVICE_NOT_REGISTERED_REVIEW_REQUIRED")
    changes, revision = policy_changes(document, service, ceiling)
    if service["revision"] == revision:
        return {"status": "UNCHANGED", "service_id": document["service_id"], "revision": revision, "pending_cases": "UNCHANGED"}
    names = {"#revision": "revision", "#account": "account_id", "#enabled": "enabled"}
    values = {":old": service["revision"], ":account": account, ":enabled": True, ":revision": revision}
    assignments = ["#revision = :revision"]
    for index, (name, value) in enumerate(sorted(changes.items())):
        alias, token = "#p" + str(index), ":p" + str(index)
        names[alias], values[token] = name, value
        assignments.append(alias + " = " + token)
    try:
        invoke("dynamodb", "update-item", "--table-name", table, "--key", key,
               "--update-expression", "SET " + ", ".join(assignments),
               "--condition-expression", "#revision = :old AND #account = :account AND #enabled = :enabled",
               "--expression-attribute-names", json.dumps(names, separators=(",", ":")),
               "--expression-attribute-values", json.dumps(encode(values), separators=(",", ":")))
    except Exception as error:
        if getattr(error, "code", None) == "ConditionalCheckFailedException" or getattr(error, "response", {}).get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return {"status": "REVIEW_REQUIRED", "reason_code": "REGISTRY_CHANGED", "service_id": document["service_id"], "mutation": "NOT_APPLIED"}
        # A lost CLI acknowledgement may follow a committed CAS. Observe only;
        # do not overwrite a newer policy or retry against a refreshed revision.
        try:
            observed = invoke("dynamodb", "get-item", "--table-name", table, "--key", key, "--consistent-read").get("Item", {})
            if observed.get("revision") == {"S": revision} and observed.get("account_id") == {"S": account} and observed.get("enabled") == {"BOOL": True}:
                return {"status": "APPLIED", "service_id": document["service_id"], "revision": revision,
                        "pending_cases": "NEW_REVIEW_REQUIRED", "acknowledgement": "VERIFIED_BY_STRONG_READ"}
        except Exception:
            pass
        return {"status": "REVIEW_REQUIRED", "reason_code": "POLICY_WRITE_RESULT_UNVERIFIED", "service_id": document["service_id"], "mutation": "UNKNOWN"}
    return {"status": "APPLIED", "service_id": document["service_id"], "revision": revision, "pending_cases": "NEW_REVIEW_REQUIRED"}


def _strict_object(pairs):
    value = {}
    for name, item in pairs:
        if name in value:
            raise PolicyError("DUPLICATE_JSON_FIELD")
        value[name] = item
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--plan", action="store_true")
    modes.add_argument("--apply", action="store_true")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--installation-id")
    parser.add_argument("--profile")
    parser.add_argument("--region")
    parser.add_argument("--enable-enforcement", action="store_true")
    args = parser.parse_args(argv)
    if args.apply and not all((args.installation_id, args.profile, args.region)):
        parser.error("--apply requires --installation-id, --profile and --region")
    try:
        raw = args.config.read_bytes()
        if len(raw) > 65536:
            raise PolicyError("POLICY_FILE_TOO_LARGE")
        document = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_strict_object)
        result = (plan(document, installation_id=args.installation_id) if args.plan else
                  apply(document, installation_id=args.installation_id, profile=args.profile, region=args.region,
                        enable_enforcement=args.enable_enforcement))
        print(json.dumps(result, ensure_ascii=False))
        return 2 if result["status"] == "REVIEW_REQUIRED" else 0
    except Exception as error:
        code = str(error) if isinstance(error, PolicyError) else "POLICY_OPERATION_FAILED"
        print(json.dumps({"status": "REVIEW_REQUIRED", "reason_code": code}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    sys.exit(main())
