"""Offline migration gates; never print plan values, import IDs or diagnostics.

Examples (keep these inputs outside the source checkout):
  python tools/terraform_migration_guard.py --plan-json PLAN.json --phase import
  python tools/terraform_migration_guard.py --plan-json PLAN.json --phase adoption \
      --allow-create-address module.governance.aws_lambda_function.Publication
  python tools/terraform_migration_guard.py --template-json TEMPLATE.json \
      --actual-resource-ids-json LOGICAL_IDS.json --conditions-json CONDITIONS.json

The last input is an optional map of independently resolved CFN condition names
to booleans. Only exact false permits a template resource absent from the live
LogicalResourceId set. The caller must use a complete, current resource snapshot
(not a partial page or deleted historical resources) and the deployed template.
This tool performs no AWS, Terraform, subprocess or network operation.

Terraform plan format: https://developer.hashicorp.com/terraform/internals/json-format
"""
import argparse
import json
from pathlib import Path
import re
import sys

MAX_JSON_BYTES = 64 * 1024 * 1024
IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_-]*"
INDEX = r'(?:\[(?:[0-9]+|"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*")\])?'
ADDRESS = re.compile(r"^(?:module\." + IDENTIFIER + INDEX + r"\.)*(?:data\.)?" + IDENTIFIER + r"\." + IDENTIFIER + INDEX + r"$")
LOGICAL_ID = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,254}$")
KNOWN_ACTIONS = {"no-op", "read", "create", "update", "delete", "forget", "replace"}


class GuardError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(condition, code):
    if not condition:
        raise GuardError(code)


def strict_object(pairs):
    value = {}
    for name, item in pairs:
        require(name not in value, "DUPLICATE_JSON_FIELD")
        value[name] = item
    return value


def reject_constant(value):
    raise GuardError("NONSTANDARD_JSON_VALUE")


def read_json(path):
    try:
        with Path(path).open("rb") as source:
            body = source.read(MAX_JSON_BYTES + 1)
        require(len(body) <= MAX_JSON_BYTES, "JSON_SIZE_LIMIT")
        return json.loads(body.decode("utf-8-sig"), object_pairs_hook=strict_object,
                          parse_constant=reject_constant)
    except GuardError:
        raise
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise GuardError("JSON_INPUT_INVALID") from None


def safe_address(value):
    return (isinstance(value, str) and len(value) <= 2048 and ADDRESS.fullmatch(value) is not None
            and not re.search(r"(?i)xox[baprs]-|github_pat_|gh[pousr]_|AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}|bearer|-----BEGIN", value))


def summary(kind, findings, resources=(), **metadata):
    return {"status": "FAILED" if findings else "PASSED", "kind": kind, **metadata,
            "resource_count": len(resources), "resources": list(resources), "findings": findings}


def check_statuses(value):
    """Inspect only check metadata, including raw-state check_results objects."""
    require(isinstance(value, list), "CHECK_RESULTS_INVALID")
    for check in value:
        require(isinstance(check, dict), "CHECK_RESULTS_INVALID")
        require(check.get("status") == "pass", "CHECK_NOT_PASSED")
        for name in ("instances", "objects"):
            if name in check:
                require(isinstance(check[name], list), "CHECK_RESULTS_INVALID")
                for instance in check[name]:
                    require(isinstance(instance, dict) and instance.get("status") == "pass", "CHECK_NOT_PASSED")


def validate_plan(plan, phase="import", allow_create_addresses=()):
    """Return a safe verdict. Only exact create-address membership is used."""
    findings, resources = [], []
    try:
        require(isinstance(phase, str) and phase in {"import", "adoption"}, "PHASE_INVALID")
        require(isinstance(allow_create_addresses, (list, tuple, set, frozenset)), "CREATE_ALLOWLIST_INVALID")
        require(all(safe_address(address) for address in allow_create_addresses), "CREATE_ALLOWLIST_INVALID")
        allow = set(allow_create_addresses)
        require(not allow or phase == "adoption", "IMPORT_CREATE_ALLOWLIST_FORBIDDEN")
        require(isinstance(plan, dict), "PLAN_OBJECT_REQUIRED")
        require(isinstance(plan.get("format_version"), str) and re.fullmatch(r"1\.[0-9]+", plan["format_version"]), "PLAN_FORMAT_UNSUPPORTED")
        require(plan.get("errored") is False, "PLAN_ERRORED_OR_UNKNOWN")
        require(plan.get("complete") is True, "PLAN_INCOMPLETE_OR_UNKNOWN")
        if "applyable" in plan:
            require(type(plan["applyable"]) is bool, "PLAN_APPLYABLE_INVALID")
        if "deferred_changes" in plan:
            require(plan["deferred_changes"] == [], "PLAN_DEFERRED_CHANGES")
        for name in ("checks", "check_results"):
            if name in plan:
                check_statuses(plan[name])
        if "diagnostics" in plan:
            require(isinstance(plan["diagnostics"], list), "PLAN_DIAGNOSTICS_INVALID")
            require(all(isinstance(row, dict) and row.get("severity") == "warning" for row in plan["diagnostics"]), "PLAN_DIAGNOSTIC_ERROR_OR_UNKNOWN")
        changes = plan.get("resource_changes")
        require(isinstance(changes, list) and len(changes) <= 100000, "RESOURCE_CHANGES_INVALID")
        seen = set()
        for row in changes:
            address, actions = None, None
            try:
                require(isinstance(row, dict), "RESOURCE_CHANGE_INVALID")
                require(safe_address(row.get("address")), "RESOURCE_ADDRESS_INVALID")
                address = row["address"]
                require(address not in seen, "DUPLICATE_RESOURCE_ADDRESS")
                seen.add(address)
                require(not row.get("deposed"), "DEPOSED_RESOURCE_REVIEW_REQUIRED")
                require(isinstance(row.get("mode"), str) and row["mode"] in {"managed", "data"}, "RESOURCE_MODE_INVALID")
                change = row.get("change")
                require(isinstance(change, dict), "RESOURCE_CHANGE_INVALID")
                raw_actions = change.get("actions")
                require(isinstance(raw_actions, list) and raw_actions and all(isinstance(action, str) and action in KNOWN_ACTIONS for action in raw_actions), "RESOURCE_ACTION_UNKNOWN")
                actions = list(raw_actions)
                resources.append({"address": address, "actions": actions})
                require(not change.get("replace_paths"), "REPLACEMENT_NOT_ALLOWED")
                require(len(actions) == 1 and actions[0] not in {"delete", "forget", "replace"}, "DESTRUCTIVE_ACTION_NOT_ALLOWED")
                action = actions[0]
                require(action in ({"no-op", "read"} if phase == "import" else {"no-op", "read", "update", "create"}), "IMPORT_MUTATION_NOT_ALLOWED")
                require(action != "create" or address in allow, "CREATE_ADDRESS_NOT_ALLOWED")
                if "importing" in change:
                    importing = change["importing"]
                    require(isinstance(importing, dict) and isinstance(importing.get("id"), str) and bool(importing["id"].strip()), "IMPORT_ID_UNKNOWN_OR_INVALID")
                    require(action == "no-op", "IMPORT_MUST_BE_NO_OP")
                require(plan.get("applyable") is not False or action == "no-op", "PLAN_NOT_APPLYABLE")
            except GuardError as error:
                finding = {"code": error.code}
                if address is not None:
                    finding["address"] = address
                if actions is not None:
                    finding["actions"] = actions
                findings.append(finding)
    except GuardError as error:
        findings.append({"code": error.code})
    return summary("terraform_plan", findings, resources, phase=phase if isinstance(phase, str) and phase in {"import", "adoption"} else "invalid")


def verify_retention(template, actual_resource_ids, condition_values=None):
    """Require exact live logical-ID coverage and Retain for both CFN policies."""
    findings, resources = [], []
    try:
        require(isinstance(template, dict) and isinstance(template.get("Resources"), dict) and bool(template["Resources"]), "TEMPLATE_RESOURCES_REQUIRED")
        require(isinstance(actual_resource_ids, (list, tuple, set, frozenset)) and bool(actual_resource_ids), "ACTUAL_RESOURCE_IDS_REQUIRED")
        require(all(isinstance(name, str) and LOGICAL_ID.fullmatch(name) for name in actual_resource_ids), "ACTUAL_RESOURCE_IDS_INVALID")
        require(len(set(actual_resource_ids)) == len(actual_resource_ids), "DUPLICATE_ACTUAL_RESOURCE_ID")
        conditions = {} if condition_values is None else condition_values
        require(isinstance(conditions, dict) and all(isinstance(name, str) and type(value) is bool for name, value in conditions.items()), "CONDITION_VALUES_INVALID")
        declared_conditions = template.get("Conditions", {})
        require(isinstance(declared_conditions, dict), "TEMPLATE_CONDITIONS_INVALID")
        declarations, actual = template["Resources"], set(actual_resource_ids)
        require(all(isinstance(name, str) and LOGICAL_ID.fullmatch(name) and isinstance(value, dict) for name, value in declarations.items()), "TEMPLATE_RESOURCE_INVALID")
        for name in sorted(actual - set(declarations)):
            findings.append({"code": "ACTUAL_RESOURCE_NOT_IN_TEMPLATE", "address": name, "actions": []})
        for name, resource in sorted(declarations.items()):
            if name not in actual:
                condition = resource.get("Condition")
                if not isinstance(condition, str) or condition not in declared_conditions or conditions.get(condition) is not False:
                    findings.append({"code": "TEMPLATE_RESOURCE_MISSING_OR_CONDITION_UNKNOWN", "address": name, "actions": []})
                continue
            resources.append({"address": name, "actions": []})
            if resource.get("DeletionPolicy") != "Retain":
                findings.append({"code": "DELETION_RETAIN_REQUIRED", "address": name, "actions": []})
            if resource.get("UpdateReplacePolicy") != "Retain":
                findings.append({"code": "REPLACEMENT_RETAIN_REQUIRED", "address": name, "actions": []})
    except GuardError as error:
        findings.append({"code": error.code})
    return summary("cloudformation_retention", findings, resources)


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        print(json.dumps(summary("input", [{"code": "CLI_ARGUMENTS_INVALID"}])))
        raise SystemExit(2)


def main(argv=None):
    parser = SafeParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--plan-json", type=Path)
    inputs.add_argument("--template-json", type=Path)
    parser.add_argument("--phase", choices=("import", "adoption"), default="import")
    parser.add_argument("--allow-create-address", action="append", default=[])
    parser.add_argument("--actual-resource-ids-json", type=Path, help="JSON array of complete live CFN LogicalResourceIds")
    parser.add_argument("--conditions-json", type=Path, help="JSON object of independently resolved CFN condition booleans")
    args = parser.parse_args(argv)
    try:
        if args.plan_json:
            require(not args.actual_resource_ids_json and not args.conditions_json, "CLI_ARGUMENTS_INVALID")
            result = validate_plan(read_json(args.plan_json), args.phase, args.allow_create_address)
        else:
            require(args.actual_resource_ids_json is not None and not args.allow_create_address, "CLI_ARGUMENTS_INVALID")
            conditions = read_json(args.conditions_json) if args.conditions_json else None
            result = verify_retention(read_json(args.template_json), read_json(args.actual_resource_ids_json), conditions)
    except GuardError as error:
        result = summary("input", [{"code": error.code}])
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASSED" else 1


if __name__ == "__main__":
    sys.exit(main())
