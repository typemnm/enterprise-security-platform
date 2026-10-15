"""Synthetic platform acceptance only. --execute makes explicitly scoped AWS calls.

The script never invokes WAF, onboarding, Slack, Secret or user-invitation APIs.
It leaves one owned observe-only fixture and four terminal cases for review.
Step Functions inputs/outputs/Cause and private callback tokens are not queried.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import gzip
import json
from pathlib import Path
import re
import tempfile
import time
import uuid

from install import AwsError, cli

ROOT = Path(__file__).resolve().parent
STABLE = {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
FINAL = {"AUTO_DRY_RUN", "REJECTED", "NO_ACTION"}
STATE_FINAL = {"SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"}
CASE = re.compile(r"inv-[0-9a-f]{32}\Z")
SAFE_CODE = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,100}\Z")


class ValidationError(RuntimeError):
    pass


def require(test, code):
    if not test:
        raise ValidationError(code)


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def attribute(value):
    if type(value) is bool:
        return {"BOOL": value}
    if type(value) is int:
        return {"N": str(value)}
    if isinstance(value, str):
        return {"S": value}
    if isinstance(value, list):
        return {"L": [attribute(item) for item in value]}
    if isinstance(value, dict):
        return {"M": {key: attribute(item) for key, item in value.items()}}
    raise ValidationError("UNSUPPORTED_FIXTURE_ATTRIBUTE")


def decoded(value):
    if not isinstance(value, dict):
        return None
    if "S" in value:
        return value["S"]
    if "N" in value:
        return int(value["N"])
    if "BOOL" in value:
        return value["BOOL"]
    if "M" in value:
        return {name: decoded(item) for name, item in value["M"].items()}
    if "L" in value:
        return [decoded(item) for item in value["L"]]
    return None


def outputs(stack):
    return {item["OutputKey"]: item["OutputValue"] for item in stack.get("Outputs", [])}


def parameters(stack):
    return {item["ParameterKey"]: item.get("ParameterValue") for item in stack.get("Parameters", [])}


class CloudValidation:
    def __init__(self, installation, *, profile, region, destination, timeout=600, call=cli,
                 run_id=None, clock=time.time, monotonic=time.monotonic, sleep=time.sleep):
        require(installation.get("status") == "VALIDATED_AUTOMATIC_ONBOARDING_DISABLED" and installation.get("automatic_onboarding_enabled") is False,
                "VALIDATION_ONLY_INSTALLATION_REQUIRED")
        require(installation.get("admin_bootstrap") == "NOT_REQUESTED", "ADMIN_INVITATION_NOT_ALLOWED")
        self.installation = installation
        self.account, self.name = installation.get("account_id"), installation.get("installation_id")
        require(isinstance(self.account, str) and re.fullmatch(r"\d{12}", self.account), "INVALID_INSTALLATION_ACCOUNT")
        require(isinstance(self.name, str) and re.fullmatch(r"[a-z][a-z0-9-]{2,30}", self.name), "INVALID_INSTALLATION_ID")
        require(30 <= timeout <= 1800, "TIMEOUT_MUST_BE_30_TO_1800_SECONDS")
        require(re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d", region), "INVALID_CONTROL_REGION")
        self.profile, self.region, self.destination, self.call = profile, region, Path(destination), call
        self.timeout, self.clock, self.monotonic, self.sleep = timeout, clock, monotonic, sleep
        self.run_id = run_id or uuid.uuid4().hex[:8]
        require(re.fullmatch(r"[a-f0-9]{8}", self.run_id), "INVALID_VALIDATION_RUN_ID")
        self.service_id = "validation-fixture-" + self.run_id
        self.deadline = None
        self.result = {"schema_version": "1.0", "status": "PREPARING", "run_id": self.run_id,
            "installation_id": self.name, "account_id": self.account, "control_region": region,
            "synthetic_only": True, "actual_security_detection": False, "human_approval": False,
            "waf_mutations": False, "slack_delivery": "DISABLED_NOT_TESTED", "service_id": self.service_id,
            "cases": {}, "stages": []}
        self.save()

    def aws(self, *arguments, region=None):
        if self.deadline is not None:
            require(self.monotonic() < self.deadline, "VALIDATION_POLL_DEADLINE_EXCEEDED")
        return self.call(*arguments, "--cli-connect-timeout", "5", "--cli-read-timeout", "30", profile=self.profile, region=region or self.region)

    def save(self):
        self.destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.destination.with_suffix(self.destination.suffix + ".tmp")
        temporary.write_text(json.dumps(self.result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temporary.replace(self.destination)

    def stage(self, name, **metadata):
        safe = {"stage": name, **metadata}
        self.result["stages"].append(safe)
        self.save()
        print(encoded({"run_id": self.run_id, **safe}), flush=True)

    def stack(self, name, *, region=None):
        selected_region = region or self.region
        rows = self.aws("cloudformation", "describe-stacks", "--stack-name", name, region=selected_region).get("Stacks", [])
        require(len(rows) == 1, "EXACT_PLATFORM_STACK_REQUIRED")
        stack = rows[0]
        require(stack.get("StackStatus") in STABLE and stack.get("StackName") == name, "PLATFORM_STACK_NOT_STABLE")
        require(str(stack.get("StackId", "")).startswith(f"arn:aws:cloudformation:{selected_region}:{self.account}:stack/{name}/"), "PLATFORM_STACK_ACCOUNT_REGION_MISMATCH")
        tags = {item["Key"]: item["Value"] for item in stack.get("Tags", [])}
        require(tags.get("ManagedBy") == "enterprise-security" and tags.get("InstallationId") == self.name, "PLATFORM_STACK_OWNERSHIP_MISMATCH")
        return stack

    def alias(self, value, stack, suffix, expected_hash):
        require(isinstance(value, str) and value == f"arn:aws:lambda:{self.region}:{self.account}:function:{self.name}-governance-{suffix}:live", "PLATFORM_ALIAS_SCOPE_MISMATCH")
        base = value.rsplit(":", 1)[0]
        alias = self.aws("lambda", "get-alias", "--function-name", base, "--name", "live")
        require(alias.get("AliasArn") == value and str(alias.get("FunctionVersion", "")).isdigit(), "PLATFORM_ALIAS_NOT_PINNED")
        selected = "{FunctionArn:FunctionArn,Version:Version,CodeSha256:CodeSha256,Environment:Environment.Variables.{DEFAULT_DRY_RUN:DEFAULT_DRY_RUN,NOTIFICATIONS_ENABLED:NOTIFICATIONS_ENABLED,SLACK_SECRET_ARN:SLACK_SECRET_ARN,SLACK_CHANNEL_ID:SLACK_CHANNEL_ID,MODEL_ARN:MODEL_ARN,PIPELINE_STATE_MACHINE_ARN:PIPELINE_STATE_MACHINE_ARN,REGISTRY_TABLE:REGISTRY_TABLE,CASES_TABLE:CASES_TABLE,QUEUE_URL:QUEUE_URL}}"
        configuration = self.aws("lambda", "get-function-configuration", "--function-name", value, "--query", selected)
        require(configuration.get("Version") == alias["FunctionVersion"] and configuration.get("CodeSha256") == expected_hash, "PLATFORM_RUNTIME_VERSION_OR_HASH_MISMATCH")
        require(configuration.get("FunctionArn") in {base, base + ":" + alias["FunctionVersion"], value}, "PLATFORM_FUNCTION_ARN_MISMATCH")
        labels = self.aws("lambda", "list-tags", "--resource", base).get("Tags", {})
        require(labels.get("ManagedBy") == "enterprise-security" and (labels.get("InstallationId") == self.name or labels.get("aws:cloudformation:stack-id") == stack["StackId"]), "PLATFORM_FUNCTION_OWNERSHIP_MISMATCH")
        self.stage("PINNED_" + suffix.upper() + "_ALIAS_VERIFIED")
        return configuration.get("Environment", {})

    def table(self, name, arn, logical, foundation):
        require(isinstance(name, str) and arn == f"arn:aws:dynamodb:{self.region}:{self.account}:table/{name}", "PLATFORM_TABLE_SCOPE_MISMATCH")
        resource = self.aws("cloudformation", "describe-stack-resource", "--stack-name", self.name, "--logical-resource-id", logical).get("StackResourceDetail", {})
        require(resource.get("PhysicalResourceId") == name and resource.get("StackId") == foundation["StackId"], "PLATFORM_TABLE_NOT_OWNED")
        table = self.aws("dynamodb", "describe-table", "--table-name", name, "--query", "Table.{TableArn:TableArn,TableStatus:TableStatus}")
        require(table.get("TableArn") == arn and table.get("TableStatus") == "ACTIVE", "PLATFORM_TABLE_NOT_ACTIVE")

    def guard(self):
        identity = self.aws("sts", "get-caller-identity")
        require(identity.get("Account") == self.account, "WRONG_AWS_ACCOUNT")
        self.stage("ACCOUNT_MATCH_VERIFIED")
        foundation, governance = self.stack(self.name), self.stack(self.name + "-governance")
        self.foundation, self.governance = outputs(foundation), outputs(governance)
        fp, gp = parameters(foundation), parameters(governance)
        require(fp.get("AutomaticOnboardingEnabled") == "false" and fp.get("InstallationScope") in {"tagged", "all-supported"} and fp.get("ResponseMode") == "observe", "ONBOARDING_MUST_REMAIN_DISABLED_OBSERVE")
        require(gp.get("DefaultDryRun") == "true" and gp.get("SlackSecretArn", "") == "" and gp.get("SlackChannelId", "") == "" and gp.get("ModelArn", "") == "", "GOVERNANCE_MUST_BE_DRY_RUN_WITH_NOTIFICATIONS_AND_MODEL_OFF")
        require(self.foundation.get("InstallationId") == self.name, "FOUNDATION_INSTALLATION_OUTPUT_MISMATCH")
        self.stage("OWNED_VALIDATION_ONLY_STACKS_VERIFIED")
        self.registry, self.cases, self.operations = [self.foundation.get(name) for name in ("RegistryTableName", "CasesTableName", "ResponseOperationsTableName")]
        for name, arn_field, logical in ((self.registry, "RegistryTableArn", "ServiceRegistry"), (self.cases, "CasesTableArn", "CasesTable"), (self.operations, "ResponseOperationsTableArn", "ResponseOperationsTable")):
            self.table(name, self.foundation.get(arn_field), logical, foundation)
        self.leases = self.foundation.get("LeaseTableName")
        self.table(self.leases, self.foundation.get("LeaseTableArn"), "DiscoveryLeaseTable", foundation)
        require(gp.get("RegistryTableName") == self.registry and gp.get("CasesTableName") == self.cases and gp.get("OperationsTableName") == self.operations, "GOVERNANCE_TABLE_MAPPING_MISMATCH")
        self.stage("PLATFORM_TABLE_MAPPING_VERIFIED")
        self.machine = self.governance.get("PipelineStateMachineArn")
        require(self.machine == f"arn:aws:states:{self.region}:{self.account}:stateMachine:{self.name}-governance-pipeline", "PLATFORM_WORKFLOW_SCOPE_MISMATCH")
        self.pipeline, self.approval = self.governance.get("SignalIngressFunctionArn"), self.governance.get("ApprovalFunctionArn")
        digest = gp.get("RuntimeCodeSha256")
        require(isinstance(digest, str) and re.fullmatch(r"[A-Za-z0-9+/]{43}=", digest), "PINNED_RUNTIME_HASH_REQUIRED")
        pipeline = self.alias(self.pipeline, governance, "pipeline", digest)
        self.alias(self.approval, governance, "approval", digest)
        notifier = self.alias(self.governance.get("NotifierFunctionArn"), governance, "notifier", digest)
        ops = self.alias(self.governance.get("OpsFunctionArn"), governance, "ops", digest)
        require(pipeline.get("DEFAULT_DRY_RUN") == "true" and pipeline.get("MODEL_ARN", "") == "" and pipeline.get("PIPELINE_STATE_MACHINE_ARN") == self.machine,
                "PIPELINE_RUNTIME_NOT_SAFE_FOR_SYNTHETIC_TEST")
        require(pipeline.get("REGISTRY_TABLE") == self.registry and pipeline.get("CASES_TABLE") == self.cases, "PIPELINE_RUNTIME_TABLE_MAPPING_MISMATCH")
        for env in (notifier, ops):
            require(env.get("NOTIFICATIONS_ENABLED") == "false" and not env.get("SLACK_SECRET_ARN") and not env.get("SLACK_CHANNEL_ID"), "SLACK_RUNTIME_MUST_BE_DISABLED")
        self.bucket, self.queue = self.foundation.get("AuditBucketName"), self.governance.get("NotificationQueueUrl")
        require(gp.get("AuditBucketName") == self.bucket, "GOVERNANCE_AUDIT_MAPPING_MISMATCH")
        require(isinstance(self.bucket, str) and re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", self.bucket), "INVALID_PLATFORM_AUDIT_BUCKET")
        self.aws("s3api", "head-bucket", "--bucket", self.bucket, "--expected-bucket-owner", self.account)
        require(isinstance(self.queue, str) and re.fullmatch(r"https://sqs\." + re.escape(self.region) + r"\.amazonaws\.com/" + self.account + r"/[A-Za-z0-9_-]+", self.queue), "PLATFORM_QUEUE_SCOPE_MISMATCH")
        require(notifier.get("QUEUE_URL") == self.queue, "NOTIFIER_QUEUE_MAPPING_MISMATCH")
        selected_mappings = self.aws("lambda", "list-event-source-mappings", "--function-name", self.governance["NotifierFunctionArn"],
            "--query", "EventSourceMappings[].{EventSourceArn:EventSourceArn,State:State}")
        mappings = selected_mappings if isinstance(selected_mappings, list) else selected_mappings.get("EventSourceMappings", [])
        # --query returns a list directly; SDK-shaped fakes may wrap it.
        if mappings is None:
            mappings = []
        expected_queue = self.governance.get("NotificationQueueArn")
        require(expected_queue == f"arn:aws:sqs:{self.region}:{self.account}:" + self.queue.rsplit("/", 1)[-1], "PLATFORM_QUEUE_ARN_MISMATCH")
        require(any(row.get("EventSourceArn") == expected_queue and row.get("State") == "Disabled" for row in mappings), "NOTIFIER_QUEUE_CONSUMER_MUST_BE_DISABLED")
        self.environment = fp.get("Environment", "prod")
        self.result["runtime_code_sha256"] = digest
        self.guard_ingress(foundation, fp, digest)
        self.result["queue_before"] = self.queue_counts()
        self.stage("SAFE_PLATFORM_GUARDS_PASSED", automatic_onboarding=False, default_dry_run=True, notifications_enabled=False)

    def guard_ingress(self, foundation, foundation_parameters, digest):
        """Verify the owned us-east-1 provider adapter before seeding anything."""
        region = "us-east-1"
        shard = foundation if self.region == region else self.stack(self.name + "-ingress", region=region)
        self.ingress = outputs(shard).get("SecurityLogIngressArn")
        require(isinstance(self.ingress, str) and re.fullmatch(f"arn:aws:lambda:{region}:{self.account}:function:[A-Za-z0-9_-]+", self.ingress), "VALIDATION_INGRESS_SCOPE_MISMATCH")
        if self.region != region:
            sp = parameters(shard)
            require(sp.get("ControlPlaneRegion") == self.region and sp.get("RegistryTableName") == self.registry and sp.get("LeaseTableName") == self.leases
                    and sp.get("InstallationId") == self.name and sp.get("SecurityEventBusArn") == self.foundation.get("SecurityEventBusArn"), "REGIONAL_INGRESS_TABLE_MAPPING_MISMATCH")
        configured = json.loads(foundation_parameters.get("IngressArnsJson", "{}"))
        require(isinstance(configured, dict) and configured.get(region) == self.ingress, "FOUNDATION_INGRESS_MAPPING_MISMATCH")
        function = self.aws("cloudformation", "describe-stack-resource", "--stack-name", shard["StackName"], "--logical-resource-id", "SecurityLogIngressFunction", region=region).get("StackResourceDetail", {})
        require(function.get("StackId") == shard["StackId"] and function.get("PhysicalResourceId") in {self.ingress, self.ingress.rsplit(":", 1)[-1]}, "INGRESS_FUNCTION_NOT_OWNED")
        config = self.aws("lambda", "get-function-configuration", "--function-name", self.ingress, "--query",
            "{FunctionArn:FunctionArn,CodeSha256:CodeSha256,State:State,Handler:Handler,Role:Role,Environment:Environment.Variables.{EXPECTED_ACCOUNT:EXPECTED_ACCOUNT,CONTROL_PLANE_REGION:CONTROL_PLANE_REGION,REGISTRY_TABLE:REGISTRY_TABLE,LEASE_TABLE:LEASE_TABLE,CASES_TABLE:CASES_TABLE,EVENT_BUS_ARN:EVENT_BUS_ARN,AUDIT_BUCKET:AUDIT_BUCKET,INSTALLATION_ID:INSTALLATION_ID,ENVIRONMENT:ENVIRONMENT}}", region=region)
        require(config.get("FunctionArn") == self.ingress and config.get("State") == "Active" and config.get("Handler") == "runtime.ingest.handler" and config.get("CodeSha256") == digest, "INGRESS_RUNTIME_CODE_OR_STATE_MISMATCH")
        env = config.get("Environment", {})
        for variable, value in {"EXPECTED_ACCOUNT": self.account, "CONTROL_PLANE_REGION": self.region, "REGISTRY_TABLE": self.registry,
                               "LEASE_TABLE": self.leases, "CASES_TABLE": self.cases, "EVENT_BUS_ARN": self.foundation.get("SecurityEventBusArn"),
                               "AUDIT_BUCKET": self.bucket, "INSTALLATION_ID": self.name, "ENVIRONMENT": self.environment}.items():
            require(isinstance(value, str) and env.get(variable) == value, "INGRESS_RUNTIME_SCOPE_MISMATCH")
        role = self.aws("cloudformation", "describe-stack-resource", "--stack-name", shard["StackName"], "--logical-resource-id", "SecurityLogIngressRole", region=region).get("StackResourceDetail", {})
        expected_role = f"arn:aws:iam::{self.account}:role/" + str(role.get("PhysicalResourceId", ""))
        require(role.get("StackId") == shard["StackId"] and config.get("Role") == expected_role, "INGRESS_ROLE_NOT_OWNED")
        actual = self.aws("iam", "get-role", "--role-name", role["PhysicalResourceId"], "--query", "Role.{Arn:Arn,Tags:Tags}", region=region)
        tags = {item["Key"]: item["Value"] for item in actual.get("Tags", [])}
        require(actual.get("Arn") == expected_role and tags.get("ManagedBy") == "enterprise-security" and tags.get("Environment") == self.environment, "INGRESS_ROLE_ACCOUNT_OR_TAG_MISMATCH")
        self.stage("OWNED_US_EAST_1_INGRESS_VERIFIED", code_hash_verified=True, role_owned=True)

    def queue_counts(self):
        attributes = self.aws("sqs", "get-queue-attributes", "--queue-url", self.queue, "--attribute-names",
            "ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible", "ApproximateNumberOfMessagesDelayed").get("Attributes", {})
        return {name: int(attributes[name]) for name in ("ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible", "ApproximateNumberOfMessagesDelayed") if name in attributes}

    def invoke(self, function, payload, *, region=None):
        with tempfile.TemporaryDirectory(prefix="enterprise-synthetic-acceptance-") as directory:
            request, response = Path(directory) / "request.json", Path(directory) / "response.json"
            request.write_text(encoded(payload), encoding="utf-8")
            metadata = self.aws("lambda", "invoke", "--function-name", function, "--invocation-type", "RequestResponse",
                "--cli-binary-format", "raw-in-base64-out", "--payload", "fileb://" + str(request), str(response), region=region)
            require(metadata.get("StatusCode") == 200 and not metadata.get("FunctionError"), "SYNTHETIC_LAMBDA_INVOCATION_FAILED")
            require(response.is_file() and response.stat().st_size <= 65536, "SYNTHETIC_LAMBDA_OUTPUT_NOT_BOUNDED")
            result = json.loads(response.read_text(encoding="utf-8"))
            require(isinstance(result, dict), "SYNTHETIC_LAMBDA_OUTPUT_SCHEMA_INVALID")
            return result

    def seed(self):
        self.fixture = {"service_id": self.service_id, "environment": self.environment, "account_id": self.account, "region": "us-east-1",
            "enabled": True, "response_mode": "enforce", "resource_type": "CLOUDFRONT", "resource_arns": [f"arn:aws:cloudfront::{self.account}:distribution/VALIDATION_FIXTURE_{self.run_id}"],
            "allowed_actions": ["monitor", "block_ip"], "waf_scope": "CLOUDFRONT",
            "web_acl_arn": f"arn:aws:wafv2:us-east-1:{self.account}:global/webacl/security-validation-{self.run_id}/{uuid.uuid4()}",
            "log_group_name": "aws-waf-logs-validation-" + self.run_id, "log_region": "us-east-1",
            "waf_ipset_arn": f"arn:aws:wafv2:us-east-1:{self.account}:global/ipset/security-validation-{self.run_id}/{uuid.uuid4()}",
            "audit_bucket": self.bucket, "revision": self.run_id, "manual_block_enabled": False, "nacl_enabled": False,
            "validation_fixture": True, "validation_run_id": self.run_id, "validation_platform_id": self.name,
            "auto_block_policy": {"enabled": True, "signal_types": ["WAF_PATTERN"], "rule_ids": ["synthetic-rate-rule"], "min_requests": 100, "window_seconds": 300}}
        self.aws("dynamodb", "put-item", "--table-name", self.registry, "--item", encoded({key: attribute(value) for key, value in self.fixture.items()}),
            "--condition-expression", "attribute_not_exists(service_id)")
        self.stage("SYNTHETIC_SERVICE_CREATED", response_mode="enforce", fixture_only=True, actual_resource_created=False)

    def observation_mode(self):
        self.aws("dynamodb", "update-item", "--table-name", self.registry, "--key", encoded({"service_id": {"S": self.service_id}}),
            "--update-expression", "SET response_mode = :observe REMOVE auto_block_policy",
            "--condition-expression", "validation_run_id = :run AND validation_platform_id = :platform",
            "--expression-attribute-values", encoded({":observe": {"S": "observe"}, ":run": {"S": self.run_id}, ":platform": {"S": self.name}}))
        self.stage("SYNTHETIC_SERVICE_OBSERVE_ONLY", response_mode="observe", manual_block_enabled=False)

    def lease(self, key):
        fields = ("lease_id", "phase", "service_id", "count", "rule_id", "policy_revision", "window_start", "window_seconds", "threshold",
                  "source_ip", "verified_latest_observation", "source_validation_version")
        names = {"#p" + str(index): name for index, name in enumerate(fields)}
        response = self.aws("dynamodb", "get-item", "--table-name", self.leases, "--consistent-read", "--key", encoded({"lease_id": {"S": key}}),
            "--projection-expression", ",".join(names), "--expression-attribute-names", encoded(names))
        row = {name: decoded(value) for name, value in response.get("Item", {}).items()}
        require(row.get("lease_id") == key and row.get("service_id") == self.service_id, "SYNTHETIC_OBSERVATION_JOURNAL_SCOPE_MISMATCH")
        return row

    def ingest_hotl(self):
        from runtime.ingest import aggregate_event_id, policy_counter, waf_signal
        kind = "HOTL_INGEST_DRY_RUN"
        # The registry index is eventually consistent. Do not mistake a newly
        # seeded fixture's short index delay for acceptance of zero requests.
        while True:
            response = self.aws("dynamodb", "query", "--table-name", self.registry, "--index-name", "WebAclArnIndex",
                "--key-condition-expression", "#acl = :acl", "--expression-attribute-names", encoded({"#acl": "web_acl_arn", "#s": "service_id"}),
                "--expression-attribute-values", encoded({":acl": {"S": self.fixture["web_acl_arn"]}}), "--projection-expression", "#s", "--limit", "25")
            services = [decoded(item.get("service_id")) for item in response.get("Items", [])]
            require(all(value == self.service_id for value in services), "SYNTHETIC_WEBACL_INDEX_SCOPE_MISMATCH")
            if services: break
            require(self.monotonic() + 5 < self.deadline, "SYNTHETIC_REGISTRY_INDEX_POLL_TIMEOUT")
            self.sleep(5)
        now = int(self.clock())
        timestamp = (now - 2) * 1000
        source = self.fixture["resource_arns"][0].rsplit("/", 1)[-1]
        records = [{"webaclId": self.fixture["web_acl_arn"], "httpSourceName": "CF", "httpSourceId": source,
            "timestamp": timestamp, "action": "COUNT", "nonTerminatingMatchingRules": [{"ruleId": "synthetic-rate-rule"}],
            "httpRequest": {"requestId": "synthetic-" + self.run_id + "-" + str(index), "clientIp": "8.8.8.8"}} for index in range(100)]
        stream = "synthetic-validation-" + self.run_id
        self.aws("logs", "create-log-group", "--log-group-name", self.fixture["log_group_name"], "--tags",
            encoded({"ManagedBy": "enterprise-security", "InstallationId": self.name, "ValidationRunId": self.run_id, "ValidationFixture": "true"}), region="us-east-1")
        self.aws("logs", "put-retention-policy", "--log-group-name", self.fixture["log_group_name"], "--retention-in-days", "1", region="us-east-1")
        self.aws("logs", "create-log-stream", "--log-group-name", self.fixture["log_group_name"], "--log-stream-name", stream, region="us-east-1")
        stored = [{"timestamp": timestamp, "message": encoded(row)} for row in records]
        with tempfile.TemporaryDirectory(prefix="enterprise-synthetic-cw-") as directory:
            request = Path(directory) / "events.json"
            request.write_text(encoded(stored), encoding="utf-8")
            accepted = self.aws("logs", "put-log-events", "--log-group-name", self.fixture["log_group_name"], "--log-stream-name", stream,
                "--log-events", "file://" + str(request), region="us-east-1")
            require(not accepted.get("rejectedLogEventsInfo"), "SYNTHETIC_CLOUDWATCH_LOGS_REJECTED")
        self.result["synthetic_log_fixture"] = {"group": self.fixture["log_group_name"], "stream": stream, "region": "us-east-1", "retention_days": 1,
            "provider": "CLOUDWATCH_STORAGE_WITH_SYNTHETIC_CONTENT", "actual_waf_log_delivery": False}
        self.stage(kind + "_CLOUDWATCH_STORED", synthetic_observations=100, actual_waf_log_delivery=False)
        expected_messages = {item["message"] for item in stored}
        while True:
            pointers, token = {}, None
            for _ in range(8):
                arguments = ["logs", "filter-log-events", "--log-group-name", self.fixture["log_group_name"], "--log-stream-names", stream,
                    "--start-time", str(timestamp), "--end-time", str(timestamp + 1), "--limit", "1000", "--no-paginate"]
                if token: arguments += ["--next-token", token]
                found = self.aws(*arguments, region="us-east-1")
                for item in found.get("events", []):
                    require(item.get("logStreamName") == stream and item.get("timestamp") == timestamp and item.get("message") in expected_messages,
                            "SYNTHETIC_STORED_CLOUDWATCH_CONTENT_MISMATCH")
                    require(isinstance(item.get("eventId"), str), "SYNTHETIC_STORED_LOG_ID_REQUIRED")
                    pointers[item["message"]] = {"id": item["eventId"], "timestamp": item["timestamp"], "message": item["message"]}
                token = found.get("nextToken")
                if not token: break
            if len(pointers) == 100: break
            require(self.monotonic() + 5 < self.deadline, "SYNTHETIC_CLOUDWATCH_POINTER_POLL_TIMEOUT")
            self.sleep(5)
        signal = waf_signal(records[0], self.fixture)
        counter = policy_counter(signal, self.fixture, now)
        require(counter is not None, "SYNTHETIC_THRESHOLD_FIXTURE_INVALID")
        event_id = aggregate_event_id(counter)
        case_id = "inv-" + hashlib.sha256((self.service_id + ":" + event_id).encode()).hexdigest()[:32]
        execution = self.machine.replace(":stateMachine:", ":execution:") + ":" + case_id
        self.result["cases"][kind] = {"case_id": case_id, "execution_arn": execution, "state": "INGEST_PREPARED", "provider_observations": 100,
            "expected_aggregate_event_id": event_id, "actual_provider_requests": False}
        self.stage(kind + "_PREPARED", case_id=case_id, synthetic_observations=100, actual_log_group_created=True, actual_waf_resource_created=False)
        payload = {"owner": self.account, "logGroup": self.fixture["log_group_name"], "logStream": stream, "messageType": "DATA_MESSAGE",
            "logEvents": [pointers[item["message"]] for item in stored]}
        compressed = {"awslogs": {"data": base64.b64encode(gzip.compress(encoded(payload).encode(), mtime=0)).decode()}}
        first = self.invoke(self.ingress, compressed, region="us-east-1")
        require(first.get("accepted") == 1 and first.get("budget_limited") == 0, "SYNTHETIC_INGRESS_DID_NOT_PUBLISH_ONE_AGGREGATE")
        self.result["cases"][kind]["state"] = "EVENTBRIDGE_ACCEPTED"
        self.stage(kind + "_EVENTBRIDGE_ACCEPTED", case_id=case_id, aggregate_events=1)
        initial = self.lease(counter["key"])
        require(initial.get("phase") == "OBSERVATION_COUNT" and initial.get("count") == 100 and initial.get("policy_revision") == self.run_id
                and initial.get("rule_id") == "synthetic-rate-rule" and initial.get("threshold") == 100 and initial.get("window_seconds") == 300
                and initial.get("source_validation_version") == "STORED_CLOUDWATCH_V1" and initial.get("source_ip") == "8.8.8.8",
                "SYNTHETIC_UNIQUE_OBSERVATION_COUNT_NOT_PROVEN")
        reservation = self.lease("signal#" + self.service_id + "#" + event_id)
        require(reservation.get("phase") == "EMITTED", "SYNTHETIC_AGGREGATE_PUBLICATION_NOT_COMMITTED")
        self.result["cases"][kind].update(unique_observations=100, signal_reservation_state="EMITTED", source_provenance="STORED_CLOUDWATCH_V1")
        self.stage(kind + "_UNIQUE_COUNT_VERIFIED", unique_observations=100, signal_reservation_state="EMITTED")
        repeated = self.invoke(self.ingress, compressed, region="us-east-1")
        require(repeated.get("accepted") == 0 and repeated.get("budget_limited") == 0, "SYNTHETIC_INGRESS_REPLAY_PUBLISHED_NEW_AGGREGATE")
        observed = self.lease(counter["key"])
        require(observed.get("count") == 100, "SYNTHETIC_INGRESS_REPLAY_INFLATED_COUNTER")
        self.result["cases"][kind].update(same_execution_on_replay=True, unique_count_preserved_on_replay=True)
        self.stage(kind + "_REPLAY_DEDUPLICATED", unique_observations=100, additional_aggregate_events=0)
        self.finish(case_id, "AUTO_DRY_RUN", kind)
        row = self.case(case_id)
        expected = {"rule_id": "synthetic-rate-rule", "matched_requests": 100, "threshold": 100, "window_seconds": 300, "policy_revision": self.run_id}
        require(row.get("policy_evidence") == expected and row.get("registry_revision") == self.run_id, "INGEST_THRESHOLD_PROOF_NOT_RECORDED_BY_PIPELINE")
        self.result["cases"][kind].update(ingress_to_eventbridge_to_sfn=True, threshold_proof_recorded=True)
        self.stage(kind + "_PIPELINE_PROOF_VERIFIED", case_id=case_id, actual_waf_action=False)

    def fixture_case_count(self):
        total, next_key = 0, None
        for _ in range(5):
            arguments = ["dynamodb", "scan", "--table-name", self.cases, "--consistent-read", "--select", "COUNT", "--limit", "1000", "--no-paginate",
                "--filter-expression", "#s = :service", "--expression-attribute-names", encoded({"#s": "service_id"}),
                "--expression-attribute-values", encoded({":service": {"S": self.service_id}})]
            if next_key: arguments += ["--exclusive-start-key", encoded(next_key)]
            response = self.aws(*arguments)
            total += response.get("Count", 0)
            next_key = response.get("LastEvaluatedKey")
            if not next_key: return total
        raise ValidationError("SYNTHETIC_CASE_COUNT_SCAN_BOUND_EXCEEDED")

    def start(self, kind, action, proof=False):
        event_id = "validation:" + self.run_id + ":" + kind
        detail = {"schema_version": "1.0", "service_id": self.service_id, "event_id": event_id, "signal_type": "WAF_PATTERN",
            "observed_at": datetime.fromtimestamp(self.clock() - 2, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "target": {"source_ip": "8.8.8.8"}, "source_resource_arn": self.fixture["resource_arns"][0], "confidence": "provider_signal",
            "summary": "[SYNTHETIC PLATFORM VALIDATION] 실제 탐지 및 사람의 승인이 아닙니다. 실제 AWS 대응과 Slack 발송을 실행하지 않습니다.", "suggested_action": action}
        if proof:
            from runtime.counter_evidence import counter_identity
            detail["target"]["source_ip"] = "8.8.4.4"
            detail["policy_evidence"] = {"rule_id": "synthetic-rate-rule", "matched_requests": 100, "threshold": 100, "window_seconds": 300, "policy_revision": self.run_id}
            # Correct hash and matching numbers still have no authority when
            # this counter does not exist in the private observation journal.
            detail["event_id"] = counter_identity(self.service_id, "8.8.4.4", self.run_id, "synthetic-rate-rule", 300, detail["observed_at"])["aggregate_event_id"]
        expected_case = "inv-" + hashlib.sha256((self.service_id + ":" + detail["event_id"]).encode()).hexdigest()[:32]
        event = {"source": "security.service", "detail-type": "ServiceSecuritySignal.v1", "account": self.account, "region": self.region, "detail": detail}
        first = self.invoke(self.pipeline, event)
        execution = self.machine.replace(":stateMachine:", ":execution:") + ":" + expected_case
        require(first.get("case_id") == expected_case and first.get("service_id") == self.service_id and first.get("execution_arn") == execution,
                "SYNTHETIC_STARTER_SCOPE_MISMATCH")
        self.result["cases"][kind] = {"case_id": expected_case, "execution_arn": execution, "state": "STARTED"}
        self.stage(kind + "_STARTED", case_id=expected_case, execution_arn=execution)
        duplicate = self.invoke(self.pipeline, event)
        require(duplicate.get("execution_arn") == execution and duplicate.get("case_id") == expected_case and duplicate.get("state") in {"STARTED", "DUPLICATE"}, "STARTER_REPLAY_CREATED_DIFFERENT_EXECUTION")
        self.result["cases"][kind]["same_execution_on_replay"] = True
        self.stage(kind + "_STARTER_REPLAY_SAME_EXECUTION", case_id=expected_case)
        return expected_case

    def case(self, case_id):
        paths = ["case_id", "service_id", "status", "tier", "dry_run", "recommended_action", "approved_action", "decision", "decided_by", "callback_status",
            "created_at", "recorded_at", "dashboard_bucket", "dashboard_key", "publication_state", "publication_revision",
            "dashboard_publication.state", "dashboard_publication.revision", "dashboard_publication.body_sha256",
            "block_response.response_status", "block_response.components.waf.status", "block_response.components.nacl.status", "registry_revision",
            "policy_evidence.rule_id", "policy_evidence.matched_requests", "policy_evidence.window_seconds", "policy_evidence.threshold", "policy_evidence.policy_revision", "automatic_evidence_error_code"]
        for outbox in ("dashboard_notification_hotl", "dashboard_notification_hitl", "dashboard_notification_outcome"):
            paths += [outbox + ".event_id", outbox + ".status", outbox + ".detail.status", outbox + ".detail.publication_type"]
        aliases, names, expressions = {}, {}, []
        for path in paths:
            selected = []
            for name in path.split("."):
                if name not in aliases:
                    aliases[name] = "#p" + str(len(aliases))
                    names[aliases[name]] = name
                selected.append(aliases[name])
            expressions.append(".".join(selected))
        response = self.aws("dynamodb", "get-item", "--table-name", self.cases, "--consistent-read", "--key", encoded({"case_id": {"S": case_id}}),
            "--projection-expression", ",".join(expressions), "--expression-attribute-names", encoded(names))
        row = {name: decoded(value) for name, value in response.get("Item", {}).items()}
        if row:
            require(row.get("case_id") == case_id and row.get("service_id") == self.service_id and row.get("dry_run") is True, "SYNTHETIC_CASE_SCOPE_OR_DRY_RUN_MISMATCH")
            require(row.get("dashboard_bucket") == self.bucket and row.get("dashboard_key") == self.service_id + "/" + case_id + ".md", "SYNTHETIC_REPORT_DESTINATION_MISMATCH")
        return row

    def wait(self, case_id, predicate, kind):
        last = None
        while True:
            row = self.case(case_id)
            state = row.get("status")
            if state != last:
                require(state is None or state in FINAL | {"TRIAGED", "AWAITING_APPROVAL", "DECIDED_APPROVE", "DECIDED_REJECT"}, "UNEXPECTED_SYNTHETIC_BUSINESS_STATE")
                self.stage(kind + "_PROGRESS", case_id=case_id, status=state)
                last = state
            if row and predicate(row):
                return row
            require(self.monotonic() + 5 < self.deadline, "SYNTHETIC_CASE_POLL_TIMEOUT")
            self.sleep(5)

    def finish(self, case_id, expected, kind, *, action="monitor"):
        row = self.wait(case_id, lambda item: item.get("status") == expected and item.get("publication_state") == "PUBLISHED"
            and item.get("dashboard_notification_outcome", {}).get("status") == "EMITTED", kind)
        self.result["cases"][kind].update(observed_business_status=row["status"], publication_state="PUBLISHED", outbox_state="EMITTED")
        self.save()
        self.wait_execution(kind)
        head = self.aws("s3api", "head-object", "--bucket", self.bucket, "--key", row["dashboard_key"], "--expected-bucket-owner", self.account,
            "--query", "{ContentLength:ContentLength,ContentType:ContentType,Metadata:Metadata,VersionId:VersionId}")
        meta = head.get("Metadata", {})
        require(meta.get("publication-revision") == row.get("publication_revision") and meta.get("service-id") == self.service_id, "SYNTHETIC_S3_PUBLICATION_REVISION_MISMATCH")
        require(isinstance(head.get("ContentLength"), int) and 0 < head["ContentLength"] <= 65536, "SYNTHETIC_REPORT_SIZE_INVALID")
        components = row.get("block_response", {}).get("components", {})
        if expected == "AUTO_DRY_RUN":
            require(row.get("tier") == 1 and row.get("block_response", {}).get("response_status") == "DRY_RUN" and components.get("waf", {}).get("status") == "SKIPPED", "HOTL_DRY_RUN_RESULT_NOT_PROVEN")
        else:
            require(row.get("tier") in (2, 3) and row.get("recommended_action") == action and row.get("callback_status") == "SENT", "HITL_CALLBACK_NOT_COMMITTED")
        receipt = row["dashboard_notification_outcome"]
        self.result["cases"][kind].update(state="SUCCEEDED", business_outcome=expected, tier=row["tier"], dry_run=True,
            recommended_action=row.get("recommended_action"), decision=row.get("decision"), approved_action=row.get("approved_action"),
            callback_status=row.get("callback_status"), report={"bucket": self.bucket, "key": row["dashboard_key"], "revision": row["publication_revision"], "size": head["ContentLength"]},
            outbox={"state": "EMITTED", "event_id": receipt.get("event_id")}, actual_components=components)
        self.stage(kind + "_COMPLETE", case_id=case_id, business_outcome=expected, workflow_state="SUCCEEDED", outbox_state="EMITTED")

    def wait_execution(self, kind):
        execution = self.result["cases"][kind]["execution_arn"]
        last = None
        while True:
            try:
                row = self.aws("stepfunctions", "describe-execution", "--execution-arn", execution,
                    "--included-data", "METADATA_ONLY", "--query", "{executionArn:executionArn,status:status,startDate:startDate,stopDate:stopDate}")
                require(row.get("executionArn") == execution and row.get("status") in STATE_FINAL | {"RUNNING", "PENDING_REDRIVE"}, "INVALID_EXECUTION_STATUS_METADATA")
                state = row["status"]
            except AwsError as error:
                if error.code != "ExecutionDoesNotExist":
                    raise
                state = "NOT_YET_VISIBLE"
            if state != last:
                self.result["cases"][kind]["observed_workflow_status"] = state
                self.stage(kind + "_WORKFLOW_PROGRESS", workflow_state=state)
                last = state
            if state == "SUCCEEDED":
                return
            require(state not in {"FAILED", "TIMED_OUT", "ABORTED"}, "SYNTHETIC_EXECUTION_NOT_SUCCEEDED")
            require(self.monotonic() + 5 < self.deadline, "SYNTHETIC_EXECUTION_POLL_TIMEOUT")
            self.sleep(5)

    def decide(self, case_id, decision, kind, *, action="monitor"):
        self.wait(case_id, lambda row: row.get("status") == "AWAITING_APPROVAL", kind)
        key = self.service_id + "/" + case_id + ".md"
        status = self.invoke(self.approval, {"operation": "status", "key": key})
        require(status.get("case_id") == case_id and status.get("service_id") == self.service_id and status.get("can_reject") is True and status.get("recommended_action") == action, "SYNTHETIC_APPROVAL_NOT_PENDING")
        response = self.invoke(self.approval, {"key": key, "decision": decision, "reason": "Synthetic platform validation; monitor only; not a human approval.", "user": "validation-script"})
        require(response.get("case_id") == case_id and response.get("service_id") == self.service_id and response.get("callback_status") == "SENT", "SYNTHETIC_CALLBACK_NOT_SENT")
        self.stage(kind + "_SCRIPT_DECISION_COMMITTED", case_id=case_id, decision=decision, human_approval=False)
        repeated = self.invoke(self.approval, {"key": key, "decision": "reject" if decision == "approve" else "approve", "user": "validation-duplicate"})
        require(repeated.get("ok") is False, "DUPLICATE_APPROVAL_WAS_ACCEPTED")
        row = self.case(case_id)
        require(row.get("decision") == decision and row.get("decided_by") == "validation-script" and row.get("callback_status") == "SENT", "FIRST_SCRIPT_DECISION_OR_ACTOR_CHANGED")
        self.result["cases"][kind]["first_decision_and_actor_preserved"] = True
        self.stage(kind + "_DUPLICATE_DECISION_REJECTED", case_id=case_id, first_actor_preserved=True)

    def run(self):
        try:
            self.deadline = self.monotonic() + self.timeout
            self.guard()
            self.seed()
            forged = self.start("FORGED_PROOF_REJECTED", "block_ip", proof=True)
            row = self.wait(forged, lambda item: item.get("status") == "AWAITING_APPROVAL", "FORGED_PROOF_REJECTED")
            require(row.get("tier") in (2, 3) and row.get("automatic_evidence_error_code") and not row.get("policy_evidence"), "FORGED_COUNTER_PROOF_WAS_TRUSTED")
            self.result["cases"]["FORGED_PROOF_REJECTED"]["counterless_proof_not_automatic"] = True
            self.decide(forged, "reject", "FORGED_PROOF_REJECTED", action="block_ip")
            self.finish(forged, "REJECTED", "FORGED_PROOF_REJECTED", action="block_ip")
            self.ingest_hotl()
            self.observation_mode()
            reject = self.start("HITL_REJECT", "monitor")
            approve = self.start("HITL_APPROVE_MONITOR", "monitor")
            self.decide(reject, "reject", "HITL_REJECT")
            self.decide(approve, "approve", "HITL_APPROVE_MONITOR")
            self.finish(reject, "REJECTED", "HITL_REJECT")
            self.finish(approve, "NO_ACTION", "HITL_APPROVE_MONITOR")
            count = self.fixture_case_count()
            require(count == 4 and len(self.result["cases"]) == 4, "SYNTHETIC_EXPECTED_FOUR_CASES_NOT_PROVEN")
            self.result["fixture_case_count"] = count
            self.result["queue_after"] = self.queue_counts()
            self.result.update(status="SYNTHETIC_ACCEPTANCE_PASSED", fixture_retained_for_review=True, fixture_response_mode="observe",
                notifications={"outbox_emitted": True, "eventbridge_accepted": True, "sqs_delivery": "APPROXIMATE_COUNTS_ONLY", "slack_delivery": "DISABLED_NOT_TESTED"},
                report_contents_read=False, callback_tokens_read=False)
            self.stage("COMPLETE", status=self.result["status"], cases_succeeded=4, actual_aws_response=False, slack_delivered=False)
            return self.result
        except Exception as error:
            code = error.code if isinstance(error, AwsError) else str(error) if isinstance(error, ValidationError) else type(error).__name__
            self.result.update(status="SYNTHETIC_ACCEPTANCE_FAILED", error_code=code if SAFE_CODE.fullmatch(code) else "VALIDATION_DEPENDENCY_FAILED")
            self.save()
            print(encoded({"run_id": self.run_id, "status": self.result["status"], "error_code": self.result["error_code"]}), flush=True)
            raise ValidationError(self.result["error_code"]) from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", required=True, help="Run four scoped synthetic cases, including 100-observation provider ingestion, on the validation-only platform")
    parser.add_argument("--install-result", type=Path, default=ROOT / "build/install-result.json")
    parser.add_argument("--output", type=Path, default=ROOT / "build/cloud-validation-result.json")
    parser.add_argument("--profile", default="default")
    parser.add_argument("--region", default="ap-northeast-2")
    parser.add_argument("--timeout", type=int, default=600, help="Shared budget for guards and all four cases; 30..1800 seconds")
    args = parser.parse_args()
    installation = json.loads(args.install_result.read_text(encoding="utf-8"))
    try:
        result = CloudValidation(installation, profile=args.profile, region=args.region, destination=args.output, timeout=args.timeout).run()
    except ValidationError:
        return 1
    print(encoded({"status": result["status"], "run_id": result["run_id"], "result_file": str(args.output.resolve())}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
