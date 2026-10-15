import argparse
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


install = load("installer_tests", "install.py")
release = load("release_tests", "build_release.py")


class InstallationBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((ROOT / "service-onboarding/installation.example.json").read_text())
        self.args = argparse.Namespace(region="ap-northeast-2", profile="company", enable_enforcement=False,
            slack_secret_arn=None, slack_channel_id=None, model_arn=None, admin_email=None, timeout=30)
        self.identity = {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:role/CompanyInstaller"}
        self.calls = []

    def call(self, *arguments, **kwargs):
        self.calls.append(arguments)
        if arguments[:2] == ("sts", "get-caller-identity"):
            return self.identity
        raise AssertionError("Unexpected AWS mutation or read")

    def test_plan_is_local_and_unknown_service_is_not_blocked(self):
        with patch.object(install.subprocess, "run", side_effect=AssertionError("No AWS CLI in plan")):
            plan = install.installation_plan(self.config, self.args)
        self.assertFalse(plan["business_target_arn_required"])
        self.assertFalse(plan["workloads_created"])
        self.assertFalse(plan["slack_enabled"])
        self.assertFalse(plan["admin_invitation"])
        self.assertIn("us-east-1", plan["artifact_and_ingress_regions"])

    def test_validation_install_does_not_enable_automation_or_reconcile(self):
        self.args.validation_only = True
        plan = install.installation_plan(self.config, self.args)
        self.assertFalse(plan["automatic_onboarding_after_verification"])
        self.assertIn("read-only discover; no WAF reconciliation", plan["phases"])

    def test_environment_limit_counts_utf8_and_fails_before_deployment(self):
        install.environment_budget({"REGISTRY_TABLE": "registry"})
        with self.assertRaisesRegex(install.InstallError, "ENVIRONMENT_BUDGET"):
            install.environment_budget({"INGRESS_ARNS_JSON": "가" * 1400})

    def test_alarm_parameter_budget_fails_in_local_plan_before_aws(self):
        config = copy.deepcopy(self.config)
        config["installation_id"] = "company-security-" + "a" * 14
        config["discovery"]["regions"] = ["ap-long-region-" + str(index) for index in range(25)]
        with patch.object(install.subprocess, "run", side_effect=AssertionError("No AWS in local plan")):
            with self.assertRaisesRegex(install.InstallError, "INGRESS_ALARM_PARAMETER_BUDGET"):
                install.installation_plan(config, self.args)

    def test_wrong_account_stops_before_bucket_or_stack_mutation(self):
        config = {**self.config, "account_id": "999999999999"}
        with self.assertRaisesRegex(install.InstallError, "WRONG_AWS_ACCOUNT"):
            install.Installer(config, self.args, {"release_id": "release"}, call=self.call)
        self.assertEqual(self.calls, [("sts", "get-caller-identity")])

    def test_foreign_secret_and_noncommercial_partition_are_reviewed(self):
        self.args.slack_secret_arn = "arn:aws:secretsmanager:ap-northeast-2:999999999999:secret:slack-id"
        with self.assertRaisesRegex(install.InstallError, "SLACK_SECRET_ACCOUNT_REGION"):
            install.Installer(self.config, self.args, {}, call=self.call)
        self.args.slack_secret_arn = None
        self.identity["Arn"] = "arn:aws-us-gov:iam::123456789012:role/CompanyInstaller"
        with self.assertRaisesRegex(install.InstallError, "PARTITION_REVIEW_REQUIRED"):
            install.Installer(self.config, self.args, {}, call=self.call)
        self.assertEqual(len(self.calls), 2)

    def test_admin_invitation_is_not_requested_by_default(self):
        instance = install.Installer(self.config, self.args, {}, call=self.call)
        self.assertEqual(instance.bootstrap_admin({}), "NOT_REQUESTED")
        self.assertEqual(len(self.calls), 1)

    def test_existing_exact_event_source_grants_are_preserved_before_first_update(self):
        instance = install.Installer(self.config, self.args, {}, call=self.call)
        sources = {"OpsEventBridgeRuleArns": "arn:aws:events:ap-northeast-2:123456789012:rule/owned-bus/owned-ops",
                   "DiscoveryEventBridgeRuleArns": "arn:aws:events:ap-northeast-2:123456789012:rule/owned-schedule"}
        instance.call = lambda *a, **kw: {"Stacks": [{"Tags": [{"Key": "ManagedBy", "Value": "enterprise-security"},
            {"Key": "InstallationId", "Value": self.config["installation_id"]}],
            "Parameters": [{"ParameterKey": key, "ParameterValue": value} for key, value in sources.items()]}]}
        self.assertEqual(instance.existing_ops_event_sources(), sources["OpsEventBridgeRuleArns"])
        self.assertEqual(instance.discovery_event_bridge_rule_arns, sources["DiscoveryEventBridgeRuleArns"])

    def test_foreign_wildcard_or_oversized_operational_event_sources_are_rejected(self):
        instance = install.Installer(self.config, self.args, {}, call=self.call)
        for value in ["arn:aws:events:us-east-1:123456789012:rule/foreign-region", "arn:aws:events:ap-northeast-2:999999999999:rule/foreign-account",
                      "arn:aws:events:ap-northeast-2:123456789012:rule/owned-*", "x" * 4097]:
            with self.subTest(value=value[:80]), self.assertRaisesRegex(install.InstallError, "OPERATIONAL_EVENT_SOURCE_SCOPE"):
                instance.validate_ops_event_sources(value)

    def test_foreign_stack_is_never_updated(self):
        instance = install.Installer(self.config, self.args, {"release_id": "release"}, call=self.call)
        def describe(*arguments, **kwargs):
            if arguments[:2] == ("cloudformation", "describe-stacks"):
                return {"Stacks": [{"StackStatus": "CREATE_COMPLETE", "Tags": []}]}
            raise AssertionError("Foreign stack mutation")
        instance.call = describe
        with self.assertRaisesRegex(install.InstallError, "FOREIGN_STACK"):
            instance.stack(self.config["installation_id"], "foundation.template.json", {}, self.args.region)

    def test_missing_versioned_checksum_rejects_artifact(self):
        instance = install.Installer(self.config, self.args, {"release_id": "release"}, call=self.call)
        instance.call = lambda *a, **kw: {"VersionId": "version", "ChecksumSHA256": "wrong"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.zip"
            path.write_bytes(b"runtime")
            with self.assertRaisesRegex(install.InstallError, "VERSION_CHECKSUM_REQUIRED"):
                instance.upload("owned-bucket", path, self.args.region)

    def test_stack_event_complete_waits_for_describe_outputs(self):
        instance = install.Installer(self.config, self.args, {"release_id": "release"}, call=self.call)
        template = json.loads((ROOT / "infrastructure/security-log-ingress.template.json").read_text())
        values = {key: str(value.get("Default", "placeholder")) for key, value in template["Parameters"].items()}
        state = {"describes": 0, "token": None}
        def fake(*arguments, **kwargs):
            operation = arguments[:2]
            if operation == ("cloudformation", "describe-stacks"):
                state["describes"] += 1
                if state["describes"] == 1:
                    raise install.AwsError("describe-stacks", "ValidationError")
                outputs = [] if state["describes"] == 2 else [{"OutputKey": key, "OutputValue": "verified-ingress-arn" if key == "SecurityLogIngressArn" else "verified-" + key}
                    for key in template["Outputs"]]
                return {"Stacks": [{"StackStatus": "CREATE_COMPLETE", "Outputs": outputs,
                    "Parameters": [{"ParameterKey": key, "ParameterValue": value} for key, value in values.items()]}]}
            if operation == ("cloudformation", "create-change-set"):
                return {}
            if operation == ("cloudformation", "describe-change-set"):
                return {"Status": "CREATE_COMPLETE", "Changes": []}
            if operation == ("cloudformation", "execute-change-set"):
                state["token"] = arguments[arguments.index("--client-request-token") + 1]
                return {}
            if operation == ("cloudformation", "describe-stack-events"):
                return {"StackEvents": [{"ClientRequestToken": state["token"], "ResourceType": "AWS::CloudFormation::Stack", "ResourceStatus": "CREATE_COMPLETE"}]}
            raise AssertionError(operation)
        instance.call = fake
        with patch.object(install.time, "sleep"):
            result = instance.stack(self.config["installation_id"] + "-ingress", "security-log-ingress.template.json", values, "us-east-1")
        self.assertEqual(result["SecurityLogIngressArn"], "verified-ingress-arn")
        self.assertEqual(set(result), set(template["Outputs"]))
        self.assertEqual(state["describes"], 3)

    def test_no_change_resume_refreshes_missing_output_contract(self):
        instance = install.Installer(self.config, self.args, {"release_id": "release"}, call=self.call)
        template = json.loads((ROOT / "infrastructure/security-log-ingress.template.json").read_text())
        values = {key: str(value.get("Default", "placeholder")) for key, value in template["Parameters"].items()}
        state = {"describes": 0, "deleted": False}
        def fake(*arguments, **kwargs):
            operation = arguments[:2]
            if operation == ("cloudformation", "describe-stacks"):
                state["describes"] += 1
                outputs = [] if state["describes"] < 3 else [{"OutputKey": key, "OutputValue": "resumed-ingress-arn" if key == "SecurityLogIngressArn" else "resumed-" + key}
                    for key in template["Outputs"]]
                return {"Stacks": [{"StackStatus": "CREATE_COMPLETE", "Outputs": outputs,
                    "Tags": [{"Key": "ManagedBy", "Value": "enterprise-security"}, {"Key": "InstallationId", "Value": self.config["installation_id"]}],
                    "Parameters": [{"ParameterKey": key, "ParameterValue": value} for key, value in values.items()]}]}
            if operation == ("cloudformation", "create-change-set"):
                return {}
            if operation == ("cloudformation", "describe-change-set"):
                return {"Status": "FAILED", "StatusReason": "The submitted information didn't contain changes."}
            if operation == ("cloudformation", "delete-change-set"):
                state["deleted"] = True
                return {}
            raise AssertionError("Unexpected mutation: " + str(operation))
        instance.call = fake
        with patch.object(install.time, "sleep"):
            result = instance.stack(self.config["installation_id"] + "-ingress", "security-log-ingress.template.json", values, "us-east-1")
        self.assertEqual(result["SecurityLogIngressArn"], "resumed-ingress-arn")
        self.assertEqual(set(result), set(template["Outputs"]))
        self.assertTrue(state["deleted"])
        self.assertEqual(state["describes"], 3)


class ReleaseBoundaryTests(unittest.TestCase):
    def test_local_validation_counters_reject_empty_or_partially_passed_suites(self):
        self.assertEqual(release.test_result("python", "Ran 12 tests in 0.1s\n\nOK")["tests"], 12)
        self.assertTrue(release.test_result("node", "# tests 45\n# pass 45\n# fail 0", node=True)["success"])
        for output, node in [("Ran 0 tests in 0.1s\n\nOK", False), ("# tests 45\n# pass 44\n# fail 0", True), ("No tests", True)]:
            with self.assertRaises(ValueError):
                release.test_result("invalid", output, node=node)

    def test_archive_is_reproducible_and_has_only_explicit_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            first, second = Path(directory) / "one.zip", Path(directory) / "two.zip"
            entries = {"runtime/__init__.py": b"", "runtime/test.py": b"value=1\n"}
            a, b = release.deterministic_zip(first, entries), release.deterministic_zip(second, entries)
            self.assertEqual(a, b)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as package:
                self.assertEqual(set(package.namelist()), set(entries))

    def test_archive_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                release.deterministic_zip(Path(directory) / "bad.zip", {"../private.json": b"secret"})

    def test_release_rejects_runtime_source_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            artifacts = directory / "release"
            artifacts.mkdir()
            (directory / "runtime").mkdir()
            (directory / "runtime/a.py").write_bytes(b"safe")
            for name in ["runtime.zip", "dashboard.zip"]:
                (artifacts / name).write_bytes(name.encode())
            manifest = {"validation": "passed", "account_neutral": True, "contains_workload": False,
                "artifacts": {name: {"sha256": install.sha(artifacts / name)[0]} for name in ["runtime.zip", "dashboard.zip"]},
                "templates": {}, "source_files": {"runtime/a.py": install.sha(directory / "runtime/a.py")[0]}}
            (artifacts / "manifest.json").write_text(json.dumps(manifest))
            (directory / "runtime/a.py").write_bytes(b"changed")
            with patch.object(install, "ROOT", directory), patch.object(install, "RELEASE", artifacts):
                with self.assertRaisesRegex(install.InstallError, "SOURCE_CHANGED"):
                    install.verified_release()


class SlackSecretEncryptionTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((ROOT / "service-onboarding/installation.example.json").read_text())
        self.args = argparse.Namespace(region="ap-northeast-2", profile="company", enable_enforcement=False,
            slack_secret_arn="arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:security-slack-AbCdEf",
            slack_channel_id="C0123456789", model_arn=None, admin_email=None, timeout=30, validation_only=True)
        self.identity = {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:role/CompanyInstaller"}
        self.key_id = "12345678-1234-1234-1234-123456789abc"
        self.key_arn = "arn:aws:kms:ap-northeast-2:123456789012:key/" + self.key_id
        self.secret = {"ARN": self.args.slack_secret_arn, "KmsKeyId": "alias/company-slack"}
        self.key = {"Arn": self.key_arn, "KeyId": self.key_id, "AWSAccountId": "123456789012", "Enabled": True,
            "KeyState": "Enabled", "KeyUsage": "ENCRYPT_DECRYPT", "KeySpec": "SYMMETRIC_DEFAULT", "KeyManager": "CUSTOMER"}
        self.calls = []

    def call(self, *arguments, **kwargs):
        self.calls.append((arguments, kwargs))
        if arguments[:2] == ("sts", "get-caller-identity"):
            return self.identity
        if arguments[:2] == ("secretsmanager", "describe-secret"):
            return self.secret
        if arguments[:2] == ("kms", "describe-key"):
            return {"KeyMetadata": self.key}
        raise AssertionError("Secret values and AWS mutations must not be requested")

    def instance(self):
        return install.Installer(self.config, self.args, {"release_id": "test"}, call=self.call)

    def test_default_secretsmanager_key_requires_only_secret_metadata(self):
        self.secret.pop("KmsKeyId")
        self.assertEqual(self.instance().slack_secret_key_arn, "")
        self.assertEqual([row[0][:2] for row in self.calls], [("sts", "get-caller-identity"), ("secretsmanager", "describe-secret")])

    def test_customer_alias_resolves_exact_enabled_local_key_without_reading_token(self):
        self.assertEqual(self.instance().slack_secret_key_arn, self.key_arn)
        self.assertEqual(self.calls[-1][0], ("kms", "describe-key", "--key-id", "alias/company-slack"))
        self.assertTrue(all(row[1]["region"] == self.args.region for row in self.calls))
        self.assertNotIn("get-secret-value", [row[0][1] for row in self.calls])

    def test_exact_key_id_key_arn_and_multi_region_local_replica_are_supported(self):
        for key_id in [self.key_id, self.key_arn]:
            with self.subTest(key_id=key_id):
                self.secret["KmsKeyId"] = key_id
                self.assertEqual(self.instance().slack_secret_key_arn, self.key_arn)
        self.key_id = "mrk-" + "a" * 32
        self.key_arn = "arn:aws:kms:ap-northeast-2:123456789012:key/" + self.key_id
        self.key.update(KeyId=self.key_id, Arn=self.key_arn)
        self.secret["KmsKeyId"] = self.key_id
        self.assertEqual(self.instance().slack_secret_key_arn, self.key_arn)

    def test_explicit_aws_managed_key_does_not_add_customer_key_grant(self):
        self.secret["KmsKeyId"] = "alias/aws/secretsmanager"
        self.key["KeyManager"] = "AWS"
        self.assertEqual(self.instance().slack_secret_key_arn, "")

    def test_foreign_region_account_wildcard_and_empty_key_reference_fail_before_kms_read(self):
        for reference in [self.key_arn.replace("ap-northeast-2", "us-east-1"),
                          self.key_arn.replace("123456789012", "999999999999"), "alias/*", ""]:
            with self.subTest(reference=reference):
                self.calls.clear()
                self.secret["KmsKeyId"] = reference
                with self.assertRaisesRegex(install.InstallError, "KEY_SCOPE_REVIEW_REQUIRED"):
                    self.instance()
                self.assertEqual(len(self.calls), 2)

    def test_disabled_foreign_asymmetric_and_non_encryption_keys_are_rejected(self):
        original = self.key.copy()
        for fields in [{"Arn": self.key_arn.replace("ap-northeast-2", "us-east-1")},
                       {"AWSAccountId": "999999999999"}, {"Enabled": False}, {"KeyState": "PendingDeletion"},
                       {"KeyUsage": "SIGN_VERIFY"}, {"KeySpec": "RSA_2048"}, {"KeyId": "different"}, {"KeyManager": "UNKNOWN"}]:
            with self.subTest(fields=fields):
                self.key = {**original, **fields}
                with self.assertRaisesRegex(install.InstallError, "KEY_METADATA_REVIEW_REQUIRED"):
                    self.instance()

    def test_key_id_mismatch_deleted_secret_or_different_returned_secret_is_rejected(self):
        for secret in [{**self.secret, "KmsKeyId": self.key_id.replace("abc", "def")},
                       {**self.secret, "DeletedDate": 123}, {**self.secret, "ARN": "different"}]:
            with self.subTest(secret=secret):
                self.secret = secret
                with self.assertRaisesRegex(install.InstallError, "METADATA_REVIEW_REQUIRED"):
                    self.instance()

    def test_customer_key_is_forwarded_to_governance_parameters(self):
        instance = self.instance()
        runtime = {"bucket": "private-artifacts", "key": "runtime.zip", "version": "immutable", "code_sha256": "hash"}
        instance.artifacts = {region: {"runtime": runtime} for region in [self.args.region, "us-east-1"]}
        fields = ["RegistryTableName", "RegistryTableArn", "ExpectedActivityTableName", "ExpectedActivityTableArn",
            "CasesTableName", "CasesTableArn", "SecurityEventBusArn", "AuditBucketName", "AuditBucketArn", "AuditKeyArn", "LeaseTableName", "LeaseTableArn"]
        foundation = {field: field for field in fields}
        foundation.update(SecurityLogIngressArn="ingress", DiscoveryFunctionArn="discovery", DashboardUrl="https://dashboard.example",
                          InstallationId=self.config["installation_id"], OpsKeyArn="ops-key",
                          DiscoveryScheduleRuleArn="arn:aws:events:ap-northeast-2:123456789012:rule/owned-schedule",
                          DiscoveryResourceEventRuleArn="arn:aws:events:ap-northeast-2:123456789012:rule/owned-resources")
        recorded = {}
        def stack(name, filename, parameters, region):
            if filename == "control_plane.template.json":
                recorded.update(parameters)
                return {"ApprovalFunctionArn": "approval-alias", "OpsEventBridgeRuleArns": "arn:aws:events:ap-northeast-2:123456789012:rule/owned-rule"}
            return foundation
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            (temporary / "infrastructure").mkdir()
            (temporary / "infrastructure/control_plane.template.json").write_bytes((ROOT / "infrastructure/control_plane.template.json").read_bytes())
            with patch.object(install, "ROOT", temporary), patch.object(instance, "prepare_artifacts"), \
                 patch.object(instance, "foundation_parameters", return_value={}), patch.object(instance, "existing_ops_event_sources", return_value=""), patch.object(instance, "stack", side_effect=stack), \
                 patch.object(instance, "verify", return_value={}), patch.object(instance, "invoke_discovery", return_value={"resources": []}):
                instance.apply()
        self.assertEqual(recorded["SlackSecretKeyArn"], self.key_arn)
        self.assertEqual(recorded["SlackSecretArn"], self.args.slack_secret_arn)
        self.assertEqual(recorded["SlackChannelId"], self.args.slack_channel_id)
        self.assertEqual(recorded["InstallationId"], self.config["installation_id"])
        self.assertEqual(recorded["OpsKeyArn"], "ops-key")
        self.assertEqual(set(recorded["IngressAlarmNames"].split(",")), {
            self.config["installation_id"] + "-" + region + "-log-ingress-" + suffix
            for region in [self.args.region, "us-east-1"]
            for suffix in ["errors", "async-dropped", "destination-failures", "dlq-depth"]})
        self.assertRegex(recorded["RuntimeConfigRevision"], r"^[0-9a-f]{64}$")


class PermissionRefreshBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.original = {"Resources": {
            "Function": {"Type": "AWS::Lambda::Function", "Properties": {"Code": {"S3Key": "old.zip"}, "Handler": "runtime.discovery.handler"}},
            "Rule": {"Type": "AWS::Events::Rule", "Properties": {"State": "DISABLED", "Targets": [{"Id": "Reconcile", "Arn": {"Fn::GetAtt": ["Function", "Arn"]}}]}},
            "Permission": {"Type": "AWS::Lambda::Permission", "Properties": {"Action": "lambda:InvokeFunction", "Principal": "events.amazonaws.com",
                "SourceAccount": {"Ref": "AWS::AccountId"}, "FunctionName": {"Ref": "Function"}, "SourceArn": {"Fn::GetAtt": ["Rule", "Arn"]}}}
        }}
        self.current = copy.deepcopy(self.original)
        self.current["Resources"]["Function"]["Properties"]["Code"]["S3Key"] = "new.zip"
        self.parents = {
            "Function": {"LogicalResourceId": "Function", "ResourceType": "AWS::Lambda::Function", "Action": "Modify", "Replacement": "False", "Details": [{"Target": {"Attribute": "Properties", "Name": "Code"}}]},
            "Rule": {"LogicalResourceId": "Rule", "ResourceType": "AWS::Events::Rule", "Action": "Modify", "Replacement": "False", "Details": [{"Target": {"Attribute": "Properties", "Name": "Targets"}}]},
        }
        self.permission = {"LogicalResourceId": "Permission", "ResourceType": "AWS::Lambda::Permission", "Action": "Modify", "Replacement": "Conditional", "Details": [
            {"Target": {"Attribute": "Properties", "Name": "SourceArn", "RequiresRecreation": "Always"}, "Evaluation": "Dynamic", "ChangeSource": "ResourceAttribute", "CausingEntity": "Rule.Arn"}]}

    def check(self):
        return install.safe_permission_refresh(self.permission, self.current, self.original, self.parents)

    def test_actual_unchanged_event_rule_grant_with_code_only_dependency_is_allowed(self):
        self.assertTrue(self.check())

    def test_dynamic_function_ref_refresh_is_allowed_with_same_physical_name(self):
        self.permission["Details"] = [{"Target": {"Attribute": "Properties", "Name": "FunctionName", "RequiresRecreation": "Always"},
            "Evaluation": "Dynamic", "ChangeSource": "ResourceReference", "CausingEntity": "Function"}]
        self.assertTrue(self.check())

    def test_reviewed_function_description_preserves_permission_identity(self):
        self.permission["Details"] = [{"Target": {"Attribute": "Properties", "Name": "FunctionName", "RequiresRecreation": "Always"},
            "Evaluation": "Dynamic", "ChangeSource": "ResourceReference", "CausingEntity": "Function"}]
        self.current["Resources"]["Function"]["Properties"]["Description"] = "Reviewed configuration revision fixture"
        self.parents["Function"]["Details"].append({"Target": {"Attribute": "Properties", "Name": "Description"}})
        self.assertTrue(self.check())
        self.current["Resources"]["Function"]["Properties"]["FunctionName"] = "another-function"
        self.assertFalse(self.check())

    def test_static_changes_and_changed_principal_account_or_source_are_rejected(self):
        for field, value in [("Principal", "*"), ("SourceAccount", "999999999999"), ("SourceArn", "arn:aws:events:*:*:rule/*"), ("Action", "lambda:*")]:
            current = copy.deepcopy(self.current)
            current["Resources"]["Permission"]["Properties"][field] = value
            self.assertFalse(install.safe_permission_refresh(self.permission, current, self.original, self.parents))
        self.permission["Details"][0]["Evaluation"] = "Static"
        self.assertFalse(self.check())

    def test_identity_changing_parent_changes_and_unknown_grant_evidence_are_rejected(self):
        self.current["Resources"]["Rule"]["Properties"]["EventBusName"] = "another-bus"
        self.assertFalse(self.check())
        self.current = copy.deepcopy(self.original)
        self.parents["Rule"]["Replacement"] = "True"
        self.assertFalse(self.check())
        self.parents["Rule"]["Replacement"] = "False"
        self.permission["Details"][0]["ChangeSource"] = "ParameterReference"
        self.assertFalse(self.check())

    def test_alias_version_refresh_preserves_qualified_arn_only_if_name_and_function_unchanged(self):
        alias = {"Type": "AWS::Lambda::Alias", "Properties": {"Name": "live", "FunctionName": {"Ref": "Function"}, "FunctionVersion": "1"}}
        self.original["Resources"]["Alias"] = copy.deepcopy(alias)
        self.current["Resources"]["Alias"] = copy.deepcopy(alias)
        self.current["Resources"]["Alias"]["Properties"]["FunctionVersion"] = "2"
        self.parents["Alias"] = {"Action": "Modify", "Replacement": "False", "Details": [{"Target": {"Attribute": "Properties", "Name": "FunctionVersion"}}]}
        for template in [self.original, self.current]:
            template["Resources"]["Permission"]["Properties"]["FunctionName"] = {"Ref": "Alias"}
        self.permission["Details"] = [{"Target": {"Attribute": "Properties", "Name": "FunctionName"}, "Evaluation": "Dynamic", "ChangeSource": "ResourceReference", "CausingEntity": "Alias"}]
        self.assertTrue(self.check())
        self.current["Resources"]["Alias"]["Properties"]["Name"] = "other"
        self.assertFalse(self.check())

    def test_true_permission_replacement_and_removal_are_never_accepted(self):
        for patch in [{"Replacement": "True"}, {"Action": "Remove"}, {"Details": []}]:
            changed = {**self.permission, **patch}
            self.assertFalse(install.safe_permission_refresh(changed, self.current, self.original, self.parents))


class EventSourceRefreshBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.original = {"Resources": {
            "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"SqsManagedSseEnabled": True, "MaximumMessageSize": 262144,
                "VisibilityTimeout": 360, "MessageRetentionPeriod": 1209600}},
            "Mapping": {"Type": "AWS::Lambda::EventSourceMapping", "Properties": {"FunctionName": "unchanged-alias-arn",
                "EventSourceArn": {"Fn::GetAtt": ["Queue", "Arn"]}, "BatchSize": 5}}}}
        self.current = copy.deepcopy(self.original)
        props = self.current["Resources"]["Queue"]["Properties"]
        props.pop("SqsManagedSseEnabled")
        props.update(KmsMasterKeyId="exact-owned-key-arn", MaximumMessageSize=1048576)
        self.parents = {"Queue": {"Action": "Modify", "Replacement": "False", "Details": [{"Target": {
            "Attribute": "Properties", "Name": name, "RequiresRecreation": "Never"}} for name in ["KmsMasterKeyId", "SqsManagedSseEnabled", "MaximumMessageSize"]]}}
        self.mapping = {"LogicalResourceId": "Mapping", "ResourceType": "AWS::Lambda::EventSourceMapping", "Action": "Modify", "Replacement": "Conditional", "Details": [{
            "Target": {"Attribute": "Properties", "Name": "EventSourceArn", "RequiresRecreation": "Always"},
            "Evaluation": "Dynamic", "ChangeSource": "ResourceAttribute", "CausingEntity": "Queue.Arn"}]}

    def check(self):
        return install.safe_event_source_refresh(self.mapping, self.current, self.original, self.parents)

    def test_actual_encryption_and_size_change_with_identical_mapping_is_allowed(self):
        self.assertTrue(self.check())

    def test_mapping_function_source_or_enabled_scope_changes_are_rejected(self):
        for name, value in [("FunctionName", "foreign-alias"), ("EventSourceArn", "foreign-queue"), ("Enabled", True), ("BatchSize", 10)]:
            current = copy.deepcopy(self.current)
            current["Resources"]["Mapping"]["Properties"][name] = value
            self.assertFalse(install.safe_event_source_refresh(self.mapping, current, self.original, self.parents))

    def test_static_parameter_unknown_attribute_or_true_replacement_is_rejected(self):
        for patch in [{"Evaluation": "Static"}, {"ChangeSource": "ParameterReference"}, {"CausingEntity": "Queue.QueueName"},
                      {"Target": {"Attribute": "Properties", "Name": "FunctionName"}}]:
            changed = {**self.mapping, "Details": [{**self.mapping["Details"][0], **patch}]}
            self.assertFalse(install.safe_event_source_refresh(changed, self.current, self.original, self.parents))
        for patch in [{"Replacement": "True"}, {"Action": "Remove"}, {"Details": []}]:
            self.assertFalse(install.safe_event_source_refresh({**self.mapping, **patch}, self.current, self.original, self.parents))

    def test_queue_identity_replacement_and_unrelated_parent_changes_are_rejected(self):
        for name, value in [("QueueName", "different"), ("FifoQueue", True), ("RedrivePolicy", {"maxReceiveCount": 100}), ("VisibilityTimeout", 60)]:
            current = copy.deepcopy(self.current)
            current["Resources"]["Queue"]["Properties"][name] = value
            self.assertFalse(install.safe_event_source_refresh(self.mapping, current, self.original, self.parents))
        self.parents["Queue"]["Replacement"] = "True"
        self.assertFalse(self.check())
        self.parents["Queue"]["Replacement"] = "False"
        self.parents["Queue"]["Details"].append({"Target": {"Attribute": "Properties", "Name": "QueueName", "RequiresRecreation": "Always"}})
        self.assertFalse(self.check())

    def with_redrive_dependency(self):
        redrive = {"deadLetterTargetArn": {"Fn::GetAtt": ["Dlq", "Arn"]}, "maxReceiveCount": 5}
        for template in [self.original, self.current]:
            template["Resources"]["Queue"]["Properties"]["RedrivePolicy"] = copy.deepcopy(redrive)
        self.original["Resources"]["Dlq"] = {"Type": "AWS::SQS::Queue", "Properties": {"SqsManagedSseEnabled": True, "MessageRetentionPeriod": 1209600}}
        self.current["Resources"]["Dlq"] = {"Type": "AWS::SQS::Queue", "Properties": {"KmsMasterKeyId": "exact-owned-key-arn", "MaximumMessageSize": 1048576, "MessageRetentionPeriod": 1209600}}
        self.parents["Dlq"] = copy.deepcopy(self.parents["Queue"])
        self.parents["Queue"]["Details"].append({"Target": {"Attribute": "Properties", "Name": "RedrivePolicy", "RequiresRecreation": "Never"},
            "Evaluation": "Dynamic", "ChangeSource": "ResourceAttribute", "CausingEntity": "Dlq.Arn"})

    def test_actual_unchanged_redrive_arn_recalculation_for_encrypted_child_dlq_is_allowed(self):
        self.with_redrive_dependency()
        self.assertTrue(self.check())

    def test_static_redrive_different_dlq_and_child_identity_changes_are_rejected(self):
        self.with_redrive_dependency()
        baseline_current, baseline_parents = copy.deepcopy(self.current), copy.deepcopy(self.parents)
        for patch in [{"Evaluation": "Static"}, {"ChangeSource": "ParameterReference"}, {"CausingEntity": "DifferentDlq.Arn"}]:
            self.parents = copy.deepcopy(baseline_parents)
            self.parents["Queue"]["Details"][-1].update(patch)
            self.assertFalse(self.check())
        self.parents = copy.deepcopy(baseline_parents)
        for field, value in [("QueueName", "changed-dlq"), ("FifoQueue", True), ("MessageRetentionPeriod", 60), ("RedrivePolicy", {"maxReceiveCount": 20})]:
            self.current = copy.deepcopy(baseline_current)
            self.current["Resources"]["Dlq"]["Properties"][field] = value
            self.assertFalse(self.check())
        self.current = copy.deepcopy(baseline_current)
        self.current["Resources"]["Queue"]["Properties"]["RedrivePolicy"]["maxReceiveCount"] = 20
        self.assertFalse(self.check())
        self.current = copy.deepcopy(baseline_current)
        self.parents["Dlq"]["Replacement"] = "True"
        self.assertFalse(self.check())


if __name__ == "__main__":
    unittest.main()
