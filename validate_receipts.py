"""Prove four synthetic outcome deliveries in the owned, disabled Slack queue.

Messages are never deleted. Receipt handles and message contents stay in memory;
temporary read visibility is reset in finally. No Secrets or Slack APIs are used.
"""
import argparse
import json
from pathlib import Path
import re
import sys
import time

from install import cli

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "service-onboarding"))
DIGEST = re.compile(r"[a-f0-9]{64}\Z")


def require(condition, code):
    if not condition:
        raise ValueError(code)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", required=True)
    parser.add_argument("--profile", default="default")
    parser.add_argument("--region", default="ap-northeast-2")
    parser.add_argument("--install-result", type=Path, help="Optional legacy receipt; Terraform outputs supply installation metadata")
    parser.add_argument("--deployment-outputs", type=Path, help="External terraform output -json file")
    parser.add_argument("--cloud-result", type=Path, default=ROOT / "build/cloud-validation-result.json")
    parser.add_argument("--output", type=Path, default=ROOT / "build/queue-validation-result.json")
    parser.add_argument("--timeout", type=int, default=240)
    args = parser.parse_args()
    require(60 <= args.timeout <= 600 and re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d", args.region), "INVALID_VALIDATION_BUDGET_OR_REGION")
    from deployment_contract import installation_result
    install = installation_result(args.install_result, deployment_outputs=args.deployment_outputs, legacy_path=ROOT / "build/install-result.json")
    acceptance = json.loads(args.cloud_result.read_text(encoding="utf-8"))
    name, account = install.get("installation_id"), install.get("account_id")
    require(isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9-]{2,30}", name), "INVALID_INSTALLATION_ID")
    require(isinstance(account, str) and re.fullmatch(r"\d{12}", account), "INVALID_ACCOUNT_ID")
    require(install.get("status") == "VALIDATED_AUTOMATIC_ONBOARDING_DISABLED" and install.get("automatic_onboarding_enabled") is False, "VALIDATION_ONLY_INSTALLATION_REQUIRED")
    require(acceptance.get("status") == "SYNTHETIC_ACCEPTANCE_PASSED" and acceptance.get("synthetic_only") is True
            and acceptance.get("installation_id") == name and acceptance.get("account_id") == account
            and acceptance.get("control_region") == args.region, "PASSED_SYNTHETIC_RESULT_REQUIRED")
    service = acceptance.get("service_id")
    require(isinstance(service, str) and re.fullmatch(r"validation-fixture-[a-f0-9]{8}", service), "OWNED_SYNTHETIC_SERVICE_REQUIRED")
    expected = {}
    for kind, row in acceptance.get("cases", {}).items():
        event_id, case_id, outcome = row.get("outbox", {}).get("event_id"), row.get("case_id"), row.get("business_outcome")
        require(isinstance(event_id, str) and DIGEST.fullmatch(event_id) and isinstance(case_id, str)
                and re.fullmatch(r"inv-[a-f0-9]{32}", case_id) and outcome in {"REJECTED", "NO_ACTION", "AUTO_DRY_RUN"}, "SAFE_OUTCOME_IDENTITY_REQUIRED")
        require(event_id not in expected, "DISTINCT_OUTCOME_EVENTS_REQUIRED")
        expected[event_id] = {"case_id": case_id, "status": outcome, "kind": kind}
    require(len(expected) == 4, "EXACT_FOUR_SYNTHETIC_OUTCOMES_REQUIRED")
    result = {"schema_version": "1.0", "status": "PREPARING", "installation_id": name,
              "account_id": account, "control_region": args.region, "release_id": install.get("release_id"),
              "synthetic_run_id": acceptance.get("run_id"), "service_id": service,
              "messages_deleted": 0, "message_contents_saved": False, "receipt_handles_saved": False,
              "slack_delivery": "DISABLED_NOT_TESTED", "outcomes": {}, "stages": []}
    receipts, queue = {}, None

    def save(stage=None):
        if stage:
            result["stages"].append(stage)
            print(json.dumps({"stage": stage, "observed_outcomes": len(result["outcomes"])}), flush=True)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    def aws(*arguments):
        return cli(*arguments, "--cli-connect-timeout", "5", "--cli-read-timeout", "20", profile=args.profile, region=args.region)

    try:
        save()
        require(aws("sts", "get-caller-identity").get("Account") == account, "WRONG_AWS_ACCOUNT")
        deployment = None
        if args.deployment_outputs:
            from deployment_contract import resolve_terraform
            deployment = resolve_terraform(args.deployment_outputs, installation_id=name, account_id=account,
                                           profile=args.profile, region=args.region, call=cli)
            foundation = governance = deployment.outputs
            fp, gp = deployment.foundation_parameters, deployment.governance_parameters
        else:
            stacks = {}
            for stack_name in (name, name + "-governance"):
                rows = aws("cloudformation", "describe-stacks", "--stack-name", stack_name).get("Stacks", [])
                require(len(rows) == 1, "EXACT_OWNED_STACK_REQUIRED")
                row = rows[0]
                require(row.get("StackStatus") in {"CREATE_COMPLETE", "UPDATE_COMPLETE"} and row.get("StackName") == stack_name
                        and row.get("StackId", "").startswith(f"arn:aws:cloudformation:{args.region}:{account}:stack/{stack_name}/"), "STABLE_OWNED_STACK_REQUIRED")
                tags = {x["Key"]: x["Value"] for x in row.get("Tags", [])}
                require(tags.get("ManagedBy") == "enterprise-security" and tags.get("InstallationId") == name, "STACK_OWNER_MISMATCH")
                stacks[stack_name] = ({x["OutputKey"]: x["OutputValue"] for x in row.get("Outputs", [])},
                                      {x["ParameterKey"]: x.get("ParameterValue") for x in row.get("Parameters", [])})
            foundation, fp = stacks[name]
            governance, gp = stacks[name + "-governance"]
        require(fp.get("AutomaticOnboardingEnabled") == "false" and fp.get("ResponseMode") == "observe", "ONBOARDING_MUST_REMAIN_OFF")
        require(gp.get("DefaultDryRun") == "true" and not gp.get("SlackSecretArn") and not gp.get("SlackChannelId"), "SLACK_MUST_BE_OFF")
        require(acceptance.get("runtime_code_sha256") == gp.get("RuntimeCodeSha256"), "SYNTHETIC_RUNTIME_HASH_MISMATCH")
        queue, arn = governance["NotificationQueueUrl"], governance["NotificationQueueArn"]
        require(re.fullmatch(r"https://sqs\." + re.escape(args.region) + r"\.amazonaws\.com/" + account + r"/[A-Za-z0-9_-]+", queue)
                and arn == f"arn:aws:sqs:{args.region}:{account}:" + queue.rsplit("/", 1)[-1], "QUEUE_SCOPE_MISMATCH")
        if deployment:
            require(deployment.resource("NotificationQueue", scope="governance") == queue, "QUEUE_NOT_OWNED_BY_INSTALLATION")
        else:
            resource = aws("cloudformation", "describe-stack-resource", "--stack-name", name + "-governance", "--logical-resource-id", "NotificationQueue")["StackResourceDetail"]
            require(resource.get("PhysicalResourceId") == queue, "QUEUE_NOT_OWNED_BY_STACK")
        config = aws("lambda", "get-function-configuration", "--function-name", governance["NotifierFunctionArn"], "--query",
                     "{CodeSha256:CodeSha256,Environment:Environment.Variables.{NOTIFICATIONS_ENABLED:NOTIFICATIONS_ENABLED,SLACK_SECRET_ARN:SLACK_SECRET_ARN,SLACK_CHANNEL_ID:SLACK_CHANNEL_ID,QUEUE_URL:QUEUE_URL}}")
        env = config.get("Environment", {})
        require(config.get("CodeSha256") == gp.get("RuntimeCodeSha256") and env.get("NOTIFICATIONS_ENABLED") == "false"
                and not env.get("SLACK_SECRET_ARN") and not env.get("SLACK_CHANNEL_ID") and env.get("QUEUE_URL") == queue, "NOTIFIER_NOT_PINNED_DISABLED")
        mappings = aws("lambda", "list-event-source-mappings", "--function-name", governance["NotifierFunctionArn"]).get("EventSourceMappings", [])
        require(len([x for x in mappings if x.get("EventSourceArn") == arn]) == 1
                and all(x.get("State") == "Disabled" for x in mappings if x.get("EventSourceArn") == arn), "QUEUE_CONSUMER_MUST_BE_DISABLED")
        attributes = aws("sqs", "get-queue-attributes", "--queue-url", queue, "--attribute-names", "QueueArn", "KmsMasterKeyId")["Attributes"]
        require(attributes.get("QueueArn") == arn and attributes.get("KmsMasterKeyId") == foundation["OpsKeyArn"], "OWNED_CMK_QUEUE_REQUIRED")
        save("OWNED_DISABLED_CMK_QUEUE_VERIFIED")
        deadline = time.monotonic() + args.timeout
        batches = 0
        while time.monotonic() < deadline and batches < 30:
            data = aws("sqs", "receive-message", "--queue-url", queue, "--max-number-of-messages", "10", "--visibility-timeout", "300", "--wait-time-seconds", "5")
            batches += 1
            for message in data.get("Messages", []):
                receipts[message["MessageId"]] = message["ReceiptHandle"]
                try:
                    event = json.loads(message.get("Body", ""))
                except (ValueError, TypeError):
                    continue
                detail = event.get("detail") if isinstance(event, dict) else None
                if not isinstance(detail, dict) or detail.get("event_id") not in expected:
                    continue
                identifier = detail["event_id"]
                wanted = expected[identifier]
                require(event.get("source") == "whs.hitl.dashboard" and event.get("detail-type") == "DashboardReportPublished.v1"
                        and event.get("account") == account and event.get("region") == args.region
                        and detail.get("publication_type") == "OUTCOME" and detail.get("service_id") == service
                        and detail.get("case_id") == wanted["case_id"] and detail.get("status") == wanted["status"], "ACTUAL_SQS_OUTCOME_CONTENT_MISMATCH")
                result["outcomes"][wanted["kind"]] = {"event_id": identifier, "case_id": wanted["case_id"], "status": wanted["status"], "actual_sqs_delivery": True}
            result["read_batches"] = batches
            save()
            if len(result["outcomes"]) == 4:
                result["status"] = "FOUR_OUTCOME_SQS_DELIVERIES_PASSED"
                save("ACTUAL_FOUR_SYNTHETIC_OUTCOMES_RECEIVED")
                return 0
        raise ValueError("FOUR_OUTCOME_DELIVERIES_NOT_OBSERVED_IN_BUDGET")
    except Exception as error:
        result.update(status="QUEUE_VALIDATION_FAILED", error_code=str(error) if isinstance(error, ValueError) else type(error).__name__)
        save("FAILED")
        return 1
    finally:
        restored = True
        if queue:
            values = list(receipts.values())
            for offset in range(0, len(values), 10):
                try:
                    entries = [{"Id": str(index), "ReceiptHandle": handle, "VisibilityTimeout": 0} for index, handle in enumerate(values[offset:offset + 10])]
                    response = aws("sqs", "change-message-visibility-batch", "--queue-url", queue, "--entries", json.dumps(entries))
                    if response.get("Failed"):
                        restored = False
                except Exception:
                    restored = False
        result.update(temporary_visibility_restored=restored, messages_read=len(receipts), visibility_expires_without_delete_seconds=300)
        if not restored:
            result.update(status="QUEUE_VISIBILITY_RESTORE_INCOMPLETE", delivery_evidence_passed=len(result["outcomes"]) == 4)
        save()
        if not restored:
            return 1


if __name__ == "__main__":
    raise SystemExit(main())
