"""Validate owned regional alarm relay on a notification-disabled validation install.

Only an owned metric alarm's temporary state is changed. No Slack messages,
subscriptions, WAF rules, business services or alarm definitions are modified.
Metric evidence is aggregate delivery evidence, not an exact message receipt.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
import time

from install import cli

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "service-onboarding"))


def require(condition, code):
    if not condition:
        raise ValueError(code)


def verified_rule_name(physical_id, expected_name, bus_name, region, account, describe):
    """CFN custom-bus IDs are bus|name; metrics require DescribeRule.Name."""
    require(physical_id in {expected_name, bus_name + "|" + expected_name}, "RULE_PHYSICAL_ID_SCOPE_MISMATCH")
    row = describe(expected_name, bus_name, region)
    path = expected_name if bus_name == "default" else bus_name + "/" + expected_name
    expected_arn = f"arn:aws:events:{region}:{account}:rule/{path}"
    require(row.get("Name") == expected_name and row.get("EventBusName") == bus_name
            and row.get("Arn") == expected_arn and row.get("State") == "ENABLED", "RULE_METADATA_SCOPE_MISMATCH")
    return row["Name"], row["Arn"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", required=True)
    parser.add_argument("--profile", default="default")
    parser.add_argument("--region", default="ap-northeast-2")
    parser.add_argument("--source-region", default="us-east-1")
    parser.add_argument("--install-result", type=Path, help="Optional legacy receipt; Terraform outputs supply installation metadata")
    parser.add_argument("--deployment-outputs", type=Path, help="External terraform output -json file")
    parser.add_argument("--output", type=Path, default=ROOT / "build/operations-validation-result.json")
    parser.add_argument("--timeout", type=int, default=360)
    args = parser.parse_args()
    require(60 <= args.timeout <= 600, "INVALID_VALIDATION_TIMEOUT")
    for region in (args.region, args.source_region):
        require(re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d", region), "INVALID_REGION")
    from deployment_contract import installation_result
    install = installation_result(args.install_result, deployment_outputs=args.deployment_outputs, legacy_path=ROOT / "build/install-result.json")
    name, account = install.get("installation_id"), install.get("account_id")
    require(isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9-]{2,30}", name), "INVALID_INSTALLATION_ID")
    require(isinstance(account, str) and re.fullmatch(r"\d{12}", account), "INVALID_ACCOUNT_ID")
    require(install.get("status") == "VALIDATED_AUTOMATIC_ONBOARDING_DISABLED" and install.get("automatic_onboarding_enabled") is False,
            "VALIDATION_ONLY_INSTALLATION_REQUIRED")
    result = {"schema_version": "1.0", "status": "PREPARING", "installation_id": name,
              "account_id": account, "release_id": install.get("release_id"),
              "source_region": args.source_region, "control_region": args.region,
              "synthetic_alarm_state": True, "slack_delivery": "DISABLED_NOT_TESTED",
              "business_changes": False, "stages": []}

    def save(stage=None):
        if stage:
            result["stages"].append(stage)
            print(json.dumps({"stage": stage}), flush=True)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    def aws(*arguments, region=None):
        return cli(*arguments, "--cli-connect-timeout", "5", "--cli-read-timeout", "20",
                   profile=args.profile, region=region or args.region)

    def stack(stack_name, region):
        if deployment:
            require(stack_name in {name, name + "-governance", name + "-ingress"}, "EXACT_STACK_REQUIRED")
            out = dict(deployment.outputs)
            if region in deployment.ingress_arns:
                out["SecurityLogIngressArn"] = deployment.ingress_arns[region]
            params = deployment.governance_parameters if stack_name == name + "-governance" else deployment.foundation_parameters
            return {}, out, params
        rows = aws("cloudformation", "describe-stacks", "--stack-name", stack_name, region=region).get("Stacks", [])
        require(len(rows) == 1, "EXACT_STACK_REQUIRED")
        row = rows[0]
        require(row.get("StackStatus") in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}, "STACK_NOT_STABLE")
        require(row.get("StackName") == stack_name and row.get("StackId", "").startswith(f"arn:aws:cloudformation:{region}:{account}:stack/{stack_name}/"), "STACK_SCOPE_MISMATCH")
        tags = {x["Key"]: x["Value"] for x in row.get("Tags", [])}
        require(tags.get("ManagedBy") == "enterprise-security" and tags.get("InstallationId") == name, "STACK_OWNER_MISMATCH")
        return row, {x["OutputKey"]: x["OutputValue"] for x in row.get("Outputs", [])}, {x["ParameterKey"]: x.get("ParameterValue") for x in row.get("Parameters", [])}

    def resource(stack_name, logical, region):
        if deployment:
            return deployment.resource(logical, scope="governance" if stack_name == name + "-governance" else "foundation", region=region)
        row = aws("cloudformation", "describe-stack-resource", "--stack-name", stack_name, "--logical-resource-id", logical, region=region)["StackResourceDetail"]
        require(row.get("StackId", "").startswith(f"arn:aws:cloudformation:{region}:{account}:stack/{stack_name}/"), "RESOURCE_SCOPE_MISMATCH")
        return row["PhysicalResourceId"]

    alarm, deployment = None, None
    try:
        save()
        require(aws("sts", "get-caller-identity").get("Account") == account, "WRONG_AWS_ACCOUNT")
        if args.deployment_outputs:
            from deployment_contract import resolve_terraform
            deployment = resolve_terraform(args.deployment_outputs, installation_id=name, account_id=account,
                                           profile=args.profile, region=args.region, call=cli)
        _, foundation, fp = stack(name, args.region)
        _, governance, gp = stack(name + "-governance", args.region)
        source_stack = name if args.source_region == args.region else name + "-ingress"
        _, source, _ = stack(source_stack, args.source_region)
        require(fp.get("AutomaticOnboardingEnabled") == "false" and fp.get("ResponseMode") == "observe", "ONBOARDING_MUST_REMAIN_OFF")
        require(gp.get("DefaultDryRun") == "true" and not gp.get("SlackSecretArn") and not gp.get("SlackChannelId"), "SLACK_MUST_BE_OFF")
        topic, ops = foundation["OpsTopicArn"], governance["OpsFunctionArn"]
        require(topic.startswith(f"arn:aws:sns:{args.region}:{account}:") and ops.startswith(f"arn:aws:lambda:{args.region}:{account}:function:{name}-governance-ops:"), "OPS_ENDPOINT_SCOPE_MISMATCH")
        subscription = aws("sns", "list-subscriptions-by-topic", "--topic-arn", topic)
        require(not subscription.get("NextToken") and len(subscription.get("Subscriptions", [])) == 1
                and subscription["Subscriptions"][0].get("Protocol") == "lambda"
                and subscription["Subscriptions"][0].get("Endpoint") == ops, "EXCLUSIVE_DISABLED_OPS_SUBSCRIPTION_REQUIRED")
        config = aws("lambda", "get-function-configuration", "--function-name", ops, "--query",
                     "{CodeSha256:CodeSha256,Environment:Environment.Variables.{NOTIFICATIONS_ENABLED:NOTIFICATIONS_ENABLED,SLACK_SECRET_ARN:SLACK_SECRET_ARN,SLACK_CHANNEL_ID:SLACK_CHANNEL_ID}}")
        env = config.get("Environment", {})
        require(config.get("CodeSha256") == gp.get("RuntimeCodeSha256") and env.get("NOTIFICATIONS_ENABLED") == "false"
                and not env.get("SLACK_SECRET_ARN") and not env.get("SLACK_CHANNEL_ID"), "OPS_NOT_PINNED_DISABLED")
        alarm_name = resource(source_stack, "IngressErrorsAlarm", args.source_region)
        require(alarm_name == name + "-" + args.source_region + "-log-ingress-errors", "EXACT_OWNED_ALARM_REQUIRED")
        alarms = aws("cloudwatch", "describe-alarms", "--alarm-names", alarm_name, region=args.source_region).get("MetricAlarms", [])
        require(len(alarms) == 1 and alarms[0].get("Namespace") == "AWS/Lambda" and alarms[0].get("MetricName") == "Errors"
                and not alarms[0].get("AlarmActions") and not alarms[0].get("OKActions") and not alarms[0].get("InsufficientDataActions"), "RELAY_ONLY_METRIC_ALARM_REQUIRED")
        require(alarms[0].get("Dimensions") == [{"Name": "FunctionName", "Value": source["SecurityLogIngressArn"].rsplit(":", 1)[-1]}], "ALARM_FUNCTION_BINDING_MISMATCH")
        alarm = alarm_name
        def describe_rule(rule_name, bus_name, region):
            return aws("events", "describe-rule", "--name", rule_name, "--event-bus-name", bus_name, region=region)
        regional_rule, regional_rule_arn = verified_rule_name(
            resource(source_stack, "IngressAlarmStateChangeRelay", args.source_region),
            name + "-" + args.source_region + "-ingress-relay", "default", args.source_region, account, describe_rule)
        central_rule, central_rule_arn = verified_rule_name(
            resource(name + "-governance", "IngressOpsRule", args.region), name + "-ingress-ops",
            foundation["SecurityEventBusName"], args.region, account, describe_rule)
        require(governance.get("IngressOpsRuleArn") == central_rule_arn, "CENTRAL_RULE_OUTPUT_BINDING_MISMATCH")
        topic_name = topic.rsplit(":", 1)[-1]
        queries = []
        for ident, namespace, metric, dimensions in (
                ("central_success", "AWS/Events", "SuccessfulInvocationAttempts", {"EventBusName": foundation["SecurityEventBusName"], "RuleName": central_rule}),
                ("sns_published", "AWS/SNS", "NumberOfMessagesPublished", {"TopicName": topic_name}),
                ("sns_delivered", "AWS/SNS", "NumberOfNotificationsDelivered", {"TopicName": topic_name})):
            queries.append({"Id": ident, "MetricStat": {"Metric": {"Namespace": namespace, "MetricName": metric,
                "Dimensions": [{"Name": k, "Value": v} for k, v in dimensions.items()]}, "Period": 60, "Stat": "Sum"}, "ReturnData": True})
        begin = int(time.time() // 60 * 60)
        end = time.monotonic() + args.timeout
        result.update(alarm_name=alarm, regional_rule=regional_rule, regional_rule_arn=regional_rule_arn,
                      central_rule=central_rule, central_rule_arn=central_rule_arn)
        save("SAFE_ALARM_AND_DISABLED_SUBSCRIPTION_VERIFIED")
        aws("cloudwatch", "set-alarm-state", "--alarm-name", alarm, "--state-value", "OK", "--state-reason", "Synthetic validation preparation", region=args.source_region)
        aws("cloudwatch", "set-alarm-state", "--alarm-name", alarm, "--state-value", "ALARM", "--state-reason", "Synthetic regional alarm relay validation", region=args.source_region)
        save("SYNTHETIC_OWNED_ALARM_TRIGGERED")
        while time.monotonic() < end:
            values = aws("cloudwatch", "get-metric-data", "--metric-data-queries", json.dumps(queries),
                         "--start-time", datetime.fromtimestamp(begin, timezone.utc).isoformat(),
                         "--end-time", datetime.fromtimestamp(time.time() + 60, timezone.utc).isoformat())
            totals = {x["Id"]: sum(x.get("Values", [])) for x in values.get("MetricDataResults", [])}
            result["delivery_metrics"] = totals
            save()
            if totals.get("central_success", 0) >= 1 and totals.get("sns_published", 0) >= 1 and totals.get("sns_delivered", 0) >= 1:
                result["status"] = "REGIONAL_ALARM_DELIVERY_METRICS_PASSED"
                save("CENTRAL_SNS_AND_DISABLED_OPS_DELIVERY_OBSERVED")
                return 0
            time.sleep(10)
        raise ValueError("ALARM_DELIVERY_METRICS_NOT_OBSERVED_IN_BUDGET")
    except Exception as error:
        result.update(status="OPERATIONS_VALIDATION_FAILED", error_code=str(error) if isinstance(error, ValueError) else type(error).__name__)
        save("FAILED")
        return 1
    finally:
        if alarm:
            try:
                aws("cloudwatch", "set-alarm-state", "--alarm-name", alarm, "--state-value", "OK", "--state-reason", "Synthetic validation completed; native evaluation resumes", region=args.source_region)
                result["alarm_restored"] = True
            except Exception:
                result["alarm_restored"] = False
                result.update(status="ALARM_STATE_RESTORE_INCOMPLETE",
                              delivery_evidence_passed=result.get("status") == "REGIONAL_ALARM_DELIVERY_METRICS_PASSED")
            save()
            if not result["alarm_restored"]:
                return 1


if __name__ == "__main__":
    raise SystemExit(main())
