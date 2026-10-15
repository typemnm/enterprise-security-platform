"""Validate/render installation and delegate guarded discovery to the deployed backend.

No manual business ARN is required or accepted. Discovery reads AWS inventory;
the backend alone verifies ownership, preserves existing ACL rules, and writes
registry documents. Reconcile must be explicitly requested by the operator.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent


def safe_report(value):
    """Project discovery output; raw AWS configs/header/secret bodies never print."""
    if not isinstance(value, dict):
        raise ValueError("Discovery backend response must be a metadata object")
    scalar_keys = {"status", "service_id", "resource_type", "resource_arn", "account_id", "region", "response_mode",
                   "waf_scope", "waf_ipset_arn", "web_acl_arn", "revision", "error_code", "eligible", "enabled",
                   "discovered", "enrolled", "skipped", "failed", "dry_run", "reason_code",
                   "reason", "logging_state", "operation", "count", "rule_count", "existing_web_acl_arn",
                   "shared_acl", "fms_owned", "logging_adapter", "existing_logging", "original_rule_count"}
    list_keys = {"results", "candidates", "plans", "errors", "resources"}
    output = {}
    for key, item in value.items():
        if key in scalar_keys and isinstance(item, (str, int, bool, type(None))):
            if isinstance(item, str) and (len(item) > 512 or any(x in item.lower() for x in ["xoxb-", "bearer ", "-----begin"])):
                continue
            output[key] = item
        elif key in list_keys and isinstance(item, list):
            output[key] = [safe_report(row) for row in item if isinstance(row, dict)]
        elif key in {"rule_names", "log_destination_arns"} and isinstance(item, list):
            output[key] = [row for row in item[:128] if isinstance(row, str) and len(row) <= 512
                           and not any(x in row.lower() for x in ["xoxb-", "bearer ", "-----begin"])]
    return output


def validate(document):
    if document.get("principal_scopes"):
        raise ValueError("CloudTrail principal adapter is not installed; principal_scopes must be empty")
    from jsonschema import Draft202012Validator
    schema = json.loads((ROOT / "schema.json").read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(document), key=lambda e: str(e.path))
    if errors:
        # Do not print submitted values: principal scopes may be sensitive metadata.
        raise ValueError("Invalid installation fields: " + ", ".join(".".join(map(str, e.path)) or "document" for e in errors))
    if document.get("dashboard_origin"):
        origin = urlsplit(document["dashboard_origin"])
        if origin.scheme != "https" or not origin.hostname or origin.username or origin.password or origin.path or origin.query or origin.fragment:
            raise ValueError("dashboard_origin must be a verified HTTPS origin without credentials/path/query")
        if origin.port is not None and not 1 <= origin.port <= 65535:
            raise ValueError("Invalid dashboard port")
    if document["response_mode"] == "enforce" and "block_ip" not in document["allowed_actions"]:
        raise ValueError("enforce requires explicitly allowed block_ip")
    if len(json.dumps(document["discovery"].get("exclude_tags", {}), ensure_ascii=False, separators=(",", ":")).encode()) > 1536:
        raise ValueError("exclude_tags exceeds the supported Lambda environment budget")
    for scope in document.get("principal_scopes", []):
        account = scope["principal_arn"].split(":")[4]
        if document.get("account_id") and account != document["account_id"]:
            raise ValueError("principal scope belongs to a different account")
        for value in scope["resource_arns"] + ([scope["source_function_arn"]] if scope.get("source_function_arn") else []):
            parts = value.split(":", 5)
            if len(parts) != 6 or parts[4] != account:
                raise ValueError("principal resource scope must match its exact account")
    return document


def aws(*args, profile, region):
    proc = subprocess.run(["aws", *args, "--profile", profile, "--region", region, "--output", "json", "--no-cli-pager"],
                          capture_output=True)
    if proc.returncode:
        raise RuntimeError("AWS operation failed: " + " ".join(args[:2]))
    for encoding in ("utf-8", "cp949"):
        try:
            return json.loads((proc.stdout or b"{}").decode(encoding))
        except (ValueError, UnicodeDecodeError):
            pass
    raise RuntimeError("AWS JSON decode failed")


def render_parameters(config, args):
    if not all([args.code_bucket, args.code_key, args.dashboard_code_bucket, args.dashboard_code_key]):
        raise ValueError("--render requires tested runtime and dashboard artifact bucket/key arguments")
    values = {"Environment": config["environment"], "DashboardOrigin": config.get("dashboard_origin", ""),
              "DashboardRoleName": args.dashboard_role or "", "InstallationScope": config["discovery"]["scope"],
              "DiscoveryRegions": ",".join(config["discovery"]["regions"]), "ResponseMode": config["response_mode"],
              "AllowedActions": ",".join(config["allowed_actions"]),
              "PrincipalScopesJson": json.dumps(config.get("principal_scopes", []), separators=(",", ":")),
              "ExcludeTagsJson": json.dumps(config["discovery"].get("exclude_tags", {"security:exclude": "true"}), separators=(",", ":")),
              "DiscoveryCodeBucket": args.code_bucket, "DiscoveryCodeKey": args.code_key,
              "DiscoveryCodeVersion": args.code_version or "", "DiscoveryHandler": args.handler, "DiscoveryRuntime": args.runtime,
              "DashboardCodeBucket": args.dashboard_code_bucket, "DashboardCodeKey": args.dashboard_code_key,
              "DashboardCodeVersion": args.dashboard_code_version or "", "DashboardHandler": args.dashboard_handler}
    return [{"ParameterKey": k, "ParameterValue": v} for k, v in values.items()]


def discover(config, args, call=aws):
    account = call("sts", "get-caller-identity", profile=args.profile, region=args.region)["Account"]
    if config.get("account_id") and config["account_id"] != account:
        raise ValueError("Wrong AWS account")
    if config["discovery"]["scope"] == "all-supported" and not args.allow_all_supported:
        raise ValueError("all-supported requires --allow-all-supported; tagged is the default installation scope")
    if args.apply and args.confirm_installation_id != config["installation_id"]:
        raise ValueError("--apply requires the exact --confirm-installation-id")
    stack = call("cloudformation", "describe-stacks", "--stack-name", config["installation_id"], profile=args.profile, region=args.region)["Stacks"][0]
    if stack["StackStatus"] not in {"CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"}:
        raise ValueError("Foundation stack is not in a stable state")
    outputs = {x["OutputKey"]: x["OutputValue"] for x in stack.get("Outputs", [])}
    function = outputs.get("DiscoveryFunctionArn", "")
    if not re.fullmatch(r"arn:aws(?:-us-gov|-cn)?:lambda:" + re.escape(args.region) + ":" + re.escape(account) + r":function:[A-Za-z0-9_-]+", function):
        raise ValueError("Foundation discovery function must belong to the current account/region")
    deployed_params = {x["ParameterKey"]: x["ParameterValue"] for x in stack.get("Parameters", [])}
    expected = {"InstallationScope": config["discovery"]["scope"], "ResponseMode": config["response_mode"],
                "Environment": config["environment"], "DiscoveryRegions": ",".join(config["discovery"]["regions"]),
                "AllowedActions": ",".join(config["allowed_actions"])}
    if any(deployed_params.get(k) != v for k, v in expected.items()):
        raise ValueError("Installation file and deployed scope differ; prepare a reviewed foundation update first")
    payload = {"operation": "reconcile" if args.apply else "discover"}
    with tempfile.TemporaryDirectory(prefix="enterprise-discovery-") as directory:
        request = Path(directory) / "request.json"
        response = Path(directory) / "result.json"
        request.write_text(json.dumps(payload), encoding="utf-8")
        outcome = call("lambda", "invoke", "--function-name", function, "--invocation-type", "RequestResponse",
                       "--cli-binary-format", "raw-in-base64-out", "--payload", "fileb://" + str(request), str(response),
                       profile=args.profile, region=args.region)
        if outcome.get("FunctionError") or outcome.get("StatusCode") != 200:
            raise RuntimeError("Guarded discovery backend failed; inspect operations alarms")
        result = json.loads(response.read_text(encoding="utf-8"))
    # Backend output must be sanitized inventory/decisions, never raw
    # CloudFront DistributionConfig custom header values or credentials.
    return {"account_id": account, "operation": payload["operation"], "result": safe_report(result)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--validate", action="store_true")
    mode.add_argument("--render", type=Path)
    mode.add_argument("--discover", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--confirm-installation-id")
    parser.add_argument("--allow-all-supported", action="store_true")
    parser.add_argument("--profile", default="default")
    parser.add_argument("--region", default="ap-northeast-2")
    parser.add_argument("--code-bucket")
    parser.add_argument("--code-key")
    parser.add_argument("--code-version")
    parser.add_argument("--handler", default="runtime.discovery.handler")
    parser.add_argument("--runtime", default="python3.13", choices=["python3.13"])
    parser.add_argument("--dashboard-code-bucket")
    parser.add_argument("--dashboard-code-key")
    parser.add_argument("--dashboard-code-version")
    parser.add_argument("--dashboard-handler", default="lambda.handler")
    parser.add_argument("--dashboard-role")
    args = parser.parse_args()
    if args.apply and not args.discover:
        parser.error("--apply is valid only with --discover")
    config = validate(json.loads(args.config.read_text(encoding="utf-8")))
    if args.render:
        args.render.parent.mkdir(parents=True, exist_ok=True)
        args.render.write_text(json.dumps(render_parameters(config, args), indent=2) + "\n", encoding="utf-8")
        result = {"status": "RENDERED", "file": str(args.render), "business_target_arn_required": False}
    elif args.discover:
        result = discover(config, args)
    else:
        result = {"status": "VALID", "installation_id": config["installation_id"], "scope": config["discovery"]["scope"],
                  "business_target_arn_required": False}
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
