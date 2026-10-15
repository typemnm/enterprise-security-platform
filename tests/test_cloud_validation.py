"""No network: validate command scopes, fixture ownership, and saved evidence."""
import base64
import copy
from decimal import Decimal
import hashlib
import gzip
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "runtime"))
from install import AwsError
from validate_cloud import CloudValidation, ValidationError, attribute, decoded
from test_ingress_security import Journal, Transactions, StoredLogs

ACCOUNT, REGION, NAME = "123456789012", "ap-northeast-2", "security-validation"
RUN = "abcdef01"
DIGEST = base64.b64encode(hashlib.sha256(b"runtime fixture").digest()).decode()
INSTALLATION = {"status": "VALIDATED_AUTOMATIC_ONBOARDING_DISABLED", "automatic_onboarding_enabled": False,
    "admin_bootstrap": "NOT_REQUESTED", "account_id": ACCOUNT, "installation_id": NAME}


class FakeAws:
    def __init__(self):
        self.calls, self.cases, self.profile = [], {}, None
        self.wrong_account, self.unsafe_dry_run, self.unsafe_slack, self.stuck_outbox, self.fixture_exists = False, False, False, False, False
        self.missing_mapping = False
        self.wrong_ingress_hash = False; self.wrong_ingress_role = False; self.wrong_ingress_account = False
        self.journal, self.index_delay = Journal(), 0
        self.transactions = Transactions(self.journal)
        self.log_groups = {}
        self.execution_states = []
        self.foundation_arn = f"arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/{NAME}/fixture"
        self.governance_arn = f"arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/{NAME}-governance/fixture"
        self.ingress_stack = NAME + "-ingress"
        self.ingress_stack_arn = f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:stack/{self.ingress_stack}/fixture"
        self.ingress = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:{NAME}-ingress-provider"
        self.ingress_role = NAME + "-ingress-role"
        self.queue_url = f"https://sqs.{REGION}.amazonaws.com/{ACCOUNT}/notification-queue"
        self.queue_arn = f"arn:aws:sqs:{REGION}:{ACCOUNT}:notification-queue"
        self.bucket = "security-validation-audit"
        self.f = {"InstallationId": NAME, "RegistryTableName": "fixture-registry", "CasesTableName": "fixture-cases", "ResponseOperationsTableName": "fixture-operations", "AuditBucketName": self.bucket,
            "LeaseTableName": self.journal.name, "SecurityEventBusArn": f"arn:aws:events:{REGION}:{ACCOUNT}:event-bus/{NAME}-security"}
        for field in ["RegistryTable", "CasesTable", "ResponseOperationsTable", "LeaseTable"]:
            self.f[field + "Arn"] = f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/" + self.f[field + "Name"]
        self.g = {"PipelineStateMachineArn": f"arn:aws:states:{REGION}:{ACCOUNT}:stateMachine:{NAME}-governance-pipeline",
            "NotificationQueueUrl": self.queue_url, "NotificationQueueArn": self.queue_arn}
        for output, suffix in [("SignalIngressFunctionArn", "pipeline"), ("ApprovalFunctionArn", "approval"), ("NotifierFunctionArn", "notifier"), ("OpsFunctionArn", "ops")]:
            self.g[output] = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{NAME}-governance-{suffix}:live"

    def item(self, case):
        return {key: attribute(int(value) if isinstance(value, Decimal) else value) for key, value in case.items()}

    def final(self, row, state):
        row.update(status=state, publication_state="PUBLISHED", publication_revision=hashlib.sha256(state.encode()).hexdigest())
        row["dashboard_notification_outcome"] = {"event_id": hashlib.sha256((row["case_id"] + state).encode()).hexdigest(), "status": "PENDING" if self.stuck_outbox else "EMITTED",
            "detail": {"status": state, "publication_type": "OUTCOME"}}
        if state == "AUTO_DRY_RUN":
            row["block_response"] = {"response_status": "DRY_RUN", "components": {"waf": {"status": "SKIPPED"}}}

    def start_case(self, detail):
        case_id = "inv-" + hashlib.sha256((detail["service_id"] + ":" + detail["event_id"]).encode()).hexdigest()[:32]
        existing = case_id in self.cases
        if not existing:
            evidence_error, tier = None, 2 if detail.get("suggested_action") == "block_ip" else 3
            if "policy_evidence" in detail:
                from runtime.counter_evidence import verify_counter_evidence
                from datetime import datetime
                try:
                    verify_counter_evidence(detail, self.profile, self.journal, now=datetime.fromisoformat(detail["observed_at"].replace("Z", "+00:00")).timestamp() + 2)
                    tier = 1
                except ValueError as error: evidence_error = str(error)
            row = {"case_id": case_id, "service_id": detail["service_id"], "status": "AWAITING_APPROVAL", "tier": tier,
                "dry_run": True, "recommended_action": detail["suggested_action"], "dashboard_bucket": self.bucket,
                "dashboard_key": detail["service_id"] + "/" + case_id + ".md", "task_token": "must-never-be-read", "report_md": "must-never-be-read", "registry_revision": RUN}
            if tier == 1: row["policy_evidence"] = copy.deepcopy(detail["policy_evidence"])
            if evidence_error: row["automatic_evidence_error_code"] = evidence_error
            self.cases[case_id] = row
            if row["tier"] == 1: self.final(row, "AUTO_DRY_RUN")
        return {"case_id": case_id, "service_id": detail["service_id"], "execution_arn": self.g["PipelineStateMachineArn"].replace(":stateMachine:", ":execution:") + ":" + case_id,
                "state": "DUPLICATE" if existing else "STARTED"}

    def project(self, row, fields, aliases):
        result = {}
        for field in fields.split(","):
            parts = [aliases.get(part, part) for part in field.split(".")]
            value = row
            for part in parts:
                if not isinstance(value, dict) or part not in value:
                    break
                value = value[part]
            else:
                target = result
                for part in parts[:-1]:
                    target = target.setdefault(part, {})
                target[parts[-1]] = copy.deepcopy(value)
        return result

    def __call__(self, *args, profile, region):
        self.calls.append(args)
        service, action = args[:2]
        value = lambda name: args[args.index(name) + 1]
        if (service, action) == ("sts", "get-caller-identity"):
            return {"Account": "999999999999" if self.wrong_account else ACCOUNT}
        if (service, action) == ("cloudformation", "describe-stacks"):
            foundation = value("--stack-name") == NAME
            ingress = value("--stack-name") == self.ingress_stack
            params = {"AutomaticOnboardingEnabled": "false", "InstallationScope": "tagged", "ResponseMode": "observe", "Environment": "validation", "IngressArnsJson": json.dumps({"us-east-1": self.ingress})} if foundation else {
                "DefaultDryRun": "true", "SlackSecretArn": "", "SlackChannelId": "", "ModelArn": "", "RuntimeCodeSha256": DIGEST,
                "RegistryTableName": self.f["RegistryTableName"], "CasesTableName": "foreign-cases" if self.missing_mapping else self.f["CasesTableName"],
                "OperationsTableName": self.f["ResponseOperationsTableName"], "AuditBucketName": self.bucket}
            if ingress:
                params = {"ControlPlaneRegion": REGION, "RegistryTableName": self.f["RegistryTableName"], "LeaseTableName": self.journal.name, "InstallationId": NAME, "SecurityEventBusArn": self.f["SecurityEventBusArn"]}
            return {"Stacks": [{"StackName": self.ingress_stack if ingress else NAME if foundation else NAME + "-governance", "StackId": self.ingress_stack_arn if ingress else self.foundation_arn if foundation else self.governance_arn,
                "StackStatus": "CREATE_COMPLETE", "Tags": [{"Key": "ManagedBy", "Value": "enterprise-security"}, {"Key": "InstallationId", "Value": NAME}],
                "Outputs": [{"OutputKey": k, "OutputValue": v} for k, v in ({"SecurityLogIngressArn": self.ingress} if ingress else self.f if foundation else self.g).items()],
                "Parameters": [{"ParameterKey": k, "ParameterValue": v} for k, v in params.items()]}]}
        if (service, action) == ("cloudformation", "describe-stack-resource"):
            names = {"ServiceRegistry": "fixture-registry", "CasesTable": "fixture-cases", "ResponseOperationsTable": "fixture-operations", "DiscoveryLeaseTable": self.journal.name,
                "SecurityLogIngressFunction": self.ingress.rsplit(":", 1)[-1], "SecurityLogIngressRole": self.ingress_role}
            return {"StackResourceDetail": {"PhysicalResourceId": names[value("--logical-resource-id")], "StackId": self.ingress_stack_arn if value("--stack-name") == self.ingress_stack else self.foundation_arn}}
        if (service, action) == ("dynamodb", "describe-table"):
            return {"TableArn": f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/" + value("--table-name"), "TableStatus": "ACTIVE"}
        if (service, action) == ("lambda", "get-alias"):
            return {"AliasArn": value("--function-name") + ":live", "FunctionVersion": "1"}
        if (service, action) == ("lambda", "get-function-configuration"):
            function = value("--function-name")
            if function == self.ingress:
                return {"FunctionArn": self.ingress, "CodeSha256": "wrong" if self.wrong_ingress_hash else DIGEST, "State": "Active", "Handler": "runtime.ingest.handler",
                    "Role": f"arn:aws:iam::{ACCOUNT}:role/" + ("foreign-role" if self.wrong_ingress_role else self.ingress_role),
                    "Environment": {"EXPECTED_ACCOUNT": "999999999999" if self.wrong_ingress_account else ACCOUNT, "CONTROL_PLANE_REGION": REGION,
                        "REGISTRY_TABLE": self.f["RegistryTableName"], "LEASE_TABLE": self.journal.name, "CASES_TABLE": self.f["CasesTableName"], "EVENT_BUS_ARN": self.f["SecurityEventBusArn"],
                        "AUDIT_BUCKET": self.bucket, "INSTALLATION_ID": NAME, "ENVIRONMENT": "validation"}}
            suffix = function.rsplit(":", 2)[1].rsplit("-", 1)[-1]
            env = {"DEFAULT_DRY_RUN": "false" if self.unsafe_dry_run else "true", "MODEL_ARN": "", "PIPELINE_STATE_MACHINE_ARN": self.g["PipelineStateMachineArn"],
                "REGISTRY_TABLE": self.f["RegistryTableName"], "CASES_TABLE": self.f["CasesTableName"], "NOTIFICATIONS_ENABLED": "true" if self.unsafe_slack else "false",
                "SLACK_SECRET_ARN": "", "SLACK_CHANNEL_ID": "", "QUEUE_URL": self.queue_url}
            return {"FunctionArn": function.rsplit(":", 1)[0] + ":1", "CodeSha256": DIGEST, "Version": "1", "Environment": env}
        if (service, action) == ("lambda", "list-tags"):
            return {"Tags": {"ManagedBy": "enterprise-security", "InstallationId": NAME}}
        if (service, action) == ("iam", "get-role"):
            return {"Arn": f"arn:aws:iam::{ACCOUNT}:role/" + self.ingress_role, "Tags": [{"Key": "ManagedBy", "Value": "enterprise-security"}, {"Key": "Environment", "Value": "validation"}]}
        if (service, action) == ("lambda", "list-event-source-mappings"):
            return [{"State": "Disabled", "EventSourceArn": self.queue_arn}]
        if (service, action) == ("s3api", "head-bucket"):
            return {}
        if (service, action) == ("sqs", "get-queue-attributes"):
            return {"Attributes": {"ApproximateNumberOfMessages": str(len(self.cases) * 2), "ApproximateNumberOfMessagesNotVisible": "0", "ApproximateNumberOfMessagesDelayed": "0"}}
        if (service, action) == ("dynamodb", "put-item"):
            if self.fixture_exists:
                raise AwsError("dynamodb put-item", "ConditionalCheckFailedException")
            self.profile = {k: decoded(v) for k, v in json.loads(value("--item")).items()}
            return {}
        if (service, action) == ("dynamodb", "update-item"):
            self.profile["response_mode"] = "observe"
            self.profile.pop("auto_block_policy", None)
            return {}
        if (service, action) == ("lambda", "invoke"):
            request = Path(value("--payload").removeprefix("fileb://"))
            response = Path(args[args.index("--payload") + 2])
            payload = json.loads(request.read_text(encoding="utf-8"))
            if value("--function-name") == self.g["SignalIngressFunctionArn"]:
                result = self.start_case(payload["detail"])
            elif value("--function-name") == self.ingress:
                from runtime import ingest
                outer = self
                class Registry:
                    def query(inner, **kwargs): return {"Items": [{"service_id": outer.profile["service_id"]}]}
                    def get_item(inner, **kwargs): return {"Item": copy.deepcopy(outer.profile)}
                class Events:
                    def put_events(inner, Entries):
                        for entry in Entries: outer.start_case(json.loads(entry["Detail"]))
                        return {"FailedEntryCount": 0}
                logs = json.loads(gzip.decompress(base64.b64decode(payload["awslogs"]["data"])))
                stored = self.log_groups[logs["logGroup"]]["streams"][logs["logStream"]]
                authority = StoredLogs({"logGroup": logs["logGroup"], "logStream": logs["logStream"], "logEvents": [
                    {"id": row["eventId"], "timestamp": row["timestamp"], "message": row["message"]} for row in stored]})
                require_now = logs["logEvents"][0]["timestamp"] // 1000 + 2
                result = ingest.accept_waf(logs, registry=Registry(), leases=self.journal, ddb=self.transactions, events=Events(), logs=authority, account=ACCOUNT,
                    bus=self.f["SecurityEventBusArn"], source_region=region, clock=lambda: require_now)
            else:
                case_id = payload["key"].split("/")[1].removesuffix(".md")
                row = self.cases[case_id]
                if payload.get("operation") == "status":
                    result = {"case_id": case_id, "service_id": row["service_id"], "can_approve": True, "can_reject": True, "recommended_action": row["recommended_action"]}
                elif row.get("decision"):
                    result = {"ok": False}
                else:
                    row.update(decision=payload["decision"], decided_by=payload["user"], callback_status="SENT", approved_action="monitor" if payload["decision"] == "approve" else "none")
                    self.final(row, "NO_ACTION" if row["decision"] == "approve" else "REJECTED")
                    result = {"case_id": case_id, "service_id": row["service_id"], "callback_status": "SENT"}
            response.write_text(json.dumps(result), encoding="utf-8")
            return {"StatusCode": 200}
        if (service, action) == ("dynamodb", "get-item"):
            keys = json.loads(value("--key"))
            row = self.journal.items.get(keys["lease_id"]["S"], {}) if "lease_id" in keys else self.cases.get(keys["case_id"]["S"], {})
            projected = self.project(row, value("--projection-expression"), json.loads(value("--expression-attribute-names")))
            projected = {key: int(value) if key == "count" else value for key, value in projected.items()}
            return {"Item": self.item(projected)}
        if (service, action) == ("dynamodb", "query"):
            if self.index_delay:
                self.index_delay -= 1
                return {"Items": []}
            return {"Items": [{"service_id": attribute(self.profile["service_id"])}]}
        if (service, action) == ("dynamodb", "scan"):
            return {"Count": len(self.cases)}
        if (service, action) == ("logs", "create-log-group"):
            group = value("--log-group-name")
            self.log_groups[group] = {"tags": json.loads(value("--tags")), "streams": {}}
            return {}
        if (service, action) == ("logs", "put-retention-policy"):
            self.log_groups[value("--log-group-name")]["retention"] = value("--retention-in-days")
            return {}
        if (service, action) == ("logs", "create-log-stream"):
            self.log_groups[value("--log-group-name")]["streams"][value("--log-stream-name")] = []
            return {}
        if (service, action) == ("logs", "put-log-events"):
            entries = json.loads(Path(value("--log-events").removeprefix("file://")).read_text(encoding="utf-8"))
            stream = value("--log-stream-name")
            self.log_groups[value("--log-group-name")]["streams"][stream] = [dict(row, eventId="stored-real-id-" + str(index), logStreamName=stream) for index, row in enumerate(entries)]
            return {}
        if (service, action) == ("logs", "filter-log-events"):
            stream = value("--log-stream-names")
            return {"events": copy.deepcopy(self.log_groups[value("--log-group-name")]["streams"][stream])}
        if (service, action) == ("stepfunctions", "describe-execution"):
            return {"status": self.execution_states.pop(0) if self.execution_states else "SUCCEEDED", "executionArn": value("--execution-arn")}
        if (service, action) == ("s3api", "head-object"):
            row = next(row for row in self.cases.values() if row["dashboard_key"] == value("--key"))
            return {"ContentLength": 100, "ContentType": "text/markdown", "Metadata": {"publication-revision": row["publication_revision"], "service-id": row["service_id"]}}
        raise AssertionError("Unexpected AWS API " + service + "/" + action)


class CloudValidationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "cloud-validation.json"
        self.aws, self.now = FakeAws(), 0
        self.output = io.StringIO()

    def validation(self, **kwargs):
        return CloudValidation(INSTALLATION, profile="validation", region=REGION, destination=self.path, run_id=RUN, call=self.aws,
            clock=lambda: 1791950000, monotonic=lambda: self.now, sleep=lambda seconds: setattr(self, "now", self.now + seconds), **kwargs)

    def test_all_four_cases_only_use_platform_metadata_apis_and_script_actors(self):
        with redirect_stdout(self.output):
            result = self.validation().run()
        self.assertEqual(result["status"], "SYNTHETIC_ACCEPTANCE_PASSED")
        self.assertEqual(len(result["cases"]), 4)
        self.assertEqual(result["fixture_case_count"], 4)
        ingress = result["cases"]["HOTL_INGEST_DRY_RUN"]
        self.assertTrue(ingress["ingress_to_eventbridge_to_sfn"])
        self.assertTrue(ingress["unique_count_preserved_on_replay"])
        self.assertEqual(ingress["source_provenance"], "STORED_CLOUDWATCH_V1")
        self.assertEqual(ingress["unique_observations"], 100)
        self.assertTrue(result["cases"]["FORGED_PROOF_REJECTED"]["counterless_proof_not_automatic"])
        self.assertEqual(result["cases"]["FORGED_PROOF_REJECTED"]["business_outcome"], "REJECTED")
        self.assertFalse(result["synthetic_log_fixture"]["actual_waf_log_delivery"])
        self.assertEqual({row["business_outcome"] for row in result["cases"].values()}, {"AUTO_DRY_RUN", "REJECTED", "NO_ACTION"})
        self.assertFalse(result["human_approval"])
        self.assertFalse(result["waf_mutations"])
        self.assertEqual(result["slack_delivery"], "DISABLED_NOT_TESTED")
        text = self.path.read_text(encoding="utf-8") + self.output.getvalue()
        self.assertNotIn("must-never-be-read", text)
        self.assertNotIn("TaskToken", text)
        self.assertTrue(all(row["same_execution_on_replay"] for row in result["cases"].values()))
        self.assertTrue(all(row["first_decision_and_actor_preserved"] for row in result["cases"].values() if row["tier"] == 3))
        self.assertEqual(self.aws.profile["response_mode"], "observe")
        self.assertNotIn("auto_block_policy", self.aws.profile)
        for call in self.aws.calls:
            self.assertNotIn(call[0], {"wafv2", "secretsmanager", "cognito-idp", "cloudfront"})
            self.assertNotIn(call[1], {"get-object", "receive-message", "send-message", "send-task-success", "start-execution"})
            if call[:2] == ("dynamodb", "get-item"):
                aliases = json.loads(call[call.index("--expression-attribute-names") + 1])
                self.assertNotIn("task_token", aliases.values())
                self.assertNotIn("report_md", aliases.values())
            if call[:2] == ("stepfunctions", "describe-execution"):
                query = call[call.index("--query") + 1]
                self.assertNotIn("input", query)
                self.assertNotIn("output", query)
                self.assertNotIn("Cause", query)

    def test_wrong_account_and_mapping_fail_before_any_fixture_mutation(self):
        for field in ("wrong_account", "missing_mapping", "unsafe_dry_run", "unsafe_slack", "wrong_ingress_hash", "wrong_ingress_role", "wrong_ingress_account"):
            self.aws = FakeAws()
            setattr(self.aws, field, True)
            with redirect_stdout(self.output), self.assertRaises(ValidationError):
                self.validation().run()
            self.assertFalse(any(call[:2] == ("dynamodb", "put-item") for call in self.aws.calls))
            self.assertEqual(json.loads(self.path.read_text())["status"], "SYNTHETIC_ACCEPTANCE_FAILED")

    def test_fixture_is_created_conditionally_and_foreign_collision_never_overwritten(self):
        self.aws.fixture_exists = True
        with redirect_stdout(self.output), self.assertRaisesRegex(ValidationError, "ConditionalCheckFailedException"):
            self.validation().run()
        put = next(call for call in self.aws.calls if call[:2] == ("dynamodb", "put-item"))
        self.assertEqual(put[put.index("--condition-expression") + 1], "attribute_not_exists(service_id)")
        self.assertIsNone(self.aws.profile)
        self.assertFalse(self.aws.cases)

    def test_timeout_retains_started_execution_evidence_without_claiming_success(self):
        self.aws.stuck_outbox = True
        with redirect_stdout(self.output), self.assertRaises(ValidationError):
            self.validation(timeout=30).run()
        result = json.loads(self.path.read_text())
        self.assertEqual(result["status"], "SYNTHETIC_ACCEPTANCE_FAILED")
        self.assertEqual(result["cases"]["FORGED_PROOF_REJECTED"]["state"], "STARTED")
        self.assertIn("execution_arn", result["cases"]["FORGED_PROOF_REJECTED"])
        self.assertNotIn("business_outcome", result["cases"]["FORGED_PROOF_REJECTED"])

    def test_regular_production_installation_is_rejected_without_aws_calls(self):
        with self.assertRaises(ValidationError):
            CloudValidation({**INSTALLATION, "status": "DEPLOYED_CONNECTED", "automatic_onboarding_enabled": True}, profile="validation", region=REGION, destination=self.path, call=self.aws)
        self.assertFalse(self.aws.calls)

    def test_synthetic_ingress_index_delay_is_bounded_and_all_writes_target_owned_fixture(self):
        self.aws.index_delay = 2
        with redirect_stdout(self.output): result = self.validation().run()
        self.assertEqual(result["status"], "SYNTHETIC_ACCEPTANCE_PASSED")
        self.assertEqual(self.now, 10)
        ingress_calls = [row for row in self.aws.calls if row[:2] == ("lambda", "invoke") and row[row.index("--function-name") + 1] == self.aws.ingress]
        self.assertEqual(len(ingress_calls), 2)
        self.assertTrue(self.aws.profile["validation_fixture"])
        self.assertEqual(self.aws.profile["web_acl_arn"].split(":")[4], ACCOUNT)
        self.assertTrue(self.aws.profile["log_group_name"].startswith("aws-waf-logs-validation-"))

    def test_eventually_consistent_running_status_is_retried_to_success(self):
        self.aws.execution_states = ["RUNNING", "RUNNING", "SUCCEEDED"]
        with redirect_stdout(self.output):
            result = self.validation().run()
        self.assertEqual(result["status"], "SYNTHETIC_ACCEPTANCE_PASSED")
        self.assertEqual(self.now, 10)
        self.assertEqual(result["cases"]["FORGED_PROOF_REJECTED"]["observed_workflow_status"], "SUCCEEDED")

    def test_terminal_execution_failure_is_saved_without_retry_or_false_success(self):
        self.aws.execution_states = ["FAILED"]
        with redirect_stdout(self.output), self.assertRaisesRegex(ValidationError, "SYNTHETIC_EXECUTION_NOT_SUCCEEDED"):
            self.validation().run()
        result = json.loads(self.path.read_text())
        self.assertEqual(result["cases"]["FORGED_PROOF_REJECTED"]["observed_workflow_status"], "FAILED")
        self.assertEqual(result["cases"]["FORGED_PROOF_REJECTED"]["observed_business_status"], "REJECTED")
        self.assertNotIn("business_outcome", result["cases"]["FORGED_PROOF_REJECTED"])
        self.assertEqual(self.now, 0)

    def test_budget_is_shared_including_guards_and_rejects_over_1800(self):
        self.assertEqual(self.validation().timeout, 600)
        with self.assertRaises(ValidationError):
            self.validation(timeout=1801)
        validation = self.validation(timeout=1800)
        validation.guard = lambda: setattr(self, "now", 1801)
        validation.seed = lambda: validation.aws("dynamodb", "put-item")
        with redirect_stdout(self.output), self.assertRaisesRegex(ValidationError, "VALIDATION_POLL_DEADLINE_EXCEEDED"):
            validation.run()
        self.assertFalse(self.aws.calls)


if __name__ == "__main__":
    unittest.main()
