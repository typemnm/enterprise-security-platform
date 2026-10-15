"""Local policy plan and offline AWS CLI/real SDK boundary tests."""
import argparse
import copy
from decimal import Decimal
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("enterprise_service_policy", ROOT / "service-onboarding/policy.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

ACCOUNT, REGION, INSTALLATION = "123456789012", "ap-northeast-2", "company-security"
SERVICE, TABLE = "checkout-prod", "company-security-ServiceRegistry-AbCd12"


def monitor():
    return {"service_id": SERVICE, "response_mode": "observe", "manual_block_enabled": False,
            "auto_block_policy": {"enabled": False}, "protected_cidrs": []}


def enforced():
    return {**monitor(), "response_mode": "enforce", "manual_block_enabled": True,
            "auto_block_policy": {"enabled": True, "signal_types": ["WAF_PATTERN"], "rule_ids": ["CompanyReviewedRule"],
                                  "window_seconds": 300, "min_requests": 20}}


def registered():
    item = {"service_id": SERVICE, "environment": "prod", "account_id": ACCOUNT, "region": REGION, "enabled": True,
            "response_mode": "observe", "manual_block_enabled": False, "allowed_actions": ["monitor", "block_ip"],
            "protected_cidrs": [], "isolation_target_ids": [], "nacl_enabled": False,
            "waf_ipset_arn": f"arn:aws:wafv2:{REGION}:{ACCOUNT}:regional/ipset/security-checkout-prod-ipv4/" + "a" * 36,
            "waf_ipv6_ipset_arn": f"arn:aws:wafv2:{REGION}:{ACCOUNT}:regional/ipset/security-checkout-prod-ipv6/" + "b" * 36,
            "waf_scope": "REGIONAL", "web_acl_arn": f"arn:aws:wafv2:{REGION}:{ACCOUNT}:regional/webacl/security-checkout-prod/" + "c" * 36,
            "resource_arns": [f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/company/abcdef1234567890"],
            "resource_type": "ALB", "audit_bucket": "company-security-audit", "report_bucket": "company-security-audit",
            "logging_state": "INTEGRATED", "log_group_name": "aws-waf-logs-company", "log_region": REGION,
            "allowed_admin_groups": ["security-admins"], "allowed_reader_groups": ["security-readers"], "updated_at": 10}
    item["revision"] = policy.revision_for(item)
    return item


class LocalPolicyTests(unittest.TestCase):
    def test_plan_loads_no_boto_or_aws_cli(self):
        with patch.dict(sys.modules, {"boto3": None}), patch.object(policy, "_installer", side_effect=AssertionError("No AWS helper in plan")):
            result = policy.plan(monitor())
        self.assertEqual(result["aws_calls"], 0)
        self.assertEqual(result["policy"]["auto_block_policy"], {"enabled": False})
        self.assertFalse(result["resource_inputs_accepted"])

    def test_cli_plan_returns_json_without_aws(self):
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / "policy.json"
            filename.write_text(json.dumps(monitor()), encoding="utf-8")
            with patch.object(policy, "_installer", side_effect=AssertionError("No AWS")), patch("sys.stdout", new_callable=io.StringIO) as output:
                status = policy.main(["--plan", "--config", str(filename)])
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(output.getvalue())["status"], "PLAN")

    def test_all_resource_and_account_inputs_are_rejected(self):
        for name in ("account_id", "resource_arns", "waf_ipset_arn", "web_acl_arn", "nacl_id", "targets", "audit_bucket", "registry_table"):
            with self.subTest(name=name), self.assertRaisesRegex(policy.PolicyError, "INVALID_POLICY_FIELDS"):
                policy.validate({**monitor(), name: "untrusted"})

    def test_bool_strings_fractions_missing_fields_and_unknown_actions_fail_closed(self):
        invalid = [{**monitor(), "manual_block_enabled": "true"}, {**monitor(), "response_mode": []},
                   {**monitor(), "allowed_actions": ["isolate_instance"]}, {**monitor(), "allowed_actions": []},
                   {**monitor(), "service_id": "../../other"}, {"service_id": SERVICE}]
        for name, value in (("window_seconds", True), ("window_seconds", 59), ("min_requests", 1), ("min_requests", 2.5)):
            item = enforced()
            item["auto_block_policy"][name] = value
            invalid.append(item)
        for item in invalid:
            with self.subTest(item=item), self.assertRaises(policy.PolicyError):
                policy.validate(item)

    def test_automatic_rule_allowlist_is_exact_and_requires_company_policy(self):
        for name, value in (("signal_types", ["CLOUDTRAIL_REVIEW"]), ("rule_ids", ["*"]),
                            ("rule_ids", ["arn:evil"]), ("rule_ids", []), ("signal_types", []),
                            ("rule_ids", ["SameRule", "SameRule"]), ("rule_ids", ["xoxb-private-token"])):
            item = enforced()
            item["auto_block_policy"][name] = value
            with self.subTest(name=name, value=value), self.assertRaises(policy.PolicyError):
                policy.validate(item)
        item = enforced()
        item["auto_block_policy"]["rule_ids"] = ["security-" + "a" * 40 + "-common"]
        self.assertEqual(policy.validate(item)["auto_block_policy"]["rule_ids"], item["auto_block_policy"]["rule_ids"])

    def test_protected_cidrs_reject_host_bits_and_normalize_ipv6(self):
        valid = {**monitor(), "protected_cidrs": ["10.0.0.0/8", "2001:0DB8:0000::/48", "2001:4860:4860::8888/128"]}
        self.assertIn("2001:db8::/48", policy.validate(valid)["protected_cidrs"])
        for values in (["10.0.0.1/24"], ["2001:db8::1/48"], ["10.0.0.1"], ["2001:db8::/48", "2001:0db8::/48"]):
            with self.subTest(values=values), self.assertRaises(policy.PolicyError):
                policy.validate({**monitor(), "protected_cidrs": values})

    def test_groups_are_selected_and_omitted_groups_are_preserved(self):
        item = monitor()
        item["allowed_reader_groups"] = ["ops-readers", "security-readers"]
        changes, revision = policy.policy_changes(policy.validate(item), registered(), ["monitor", "block_ip"])
        self.assertNotIn("allowed_admin_groups", changes)
        self.assertEqual(changes["allowed_reader_groups"], ["ops-readers", "security-readers"])
        self.assertEqual(revision, policy.revision_for({**registered(), **changes}))
        with self.assertRaises(policy.PolicyError):
            policy.validate({**monitor(), "allowed_admin_groups": ["group\nheader"]})

    def test_installation_and_existing_service_are_both_action_ceilings(self):
        for service_actions, installation_actions in ((["monitor"], ["monitor", "block_ip"]), (["monitor", "block_ip"], ["monitor"])):
            item = registered()
            item["allowed_actions"] = service_actions
            with self.assertRaisesRegex(policy.PolicyError, "CEILING_DENIED"):
                policy.policy_changes({**monitor(), "allowed_actions": ["monitor", "block_ip"]}, item, installation_actions)
        changes, _ = policy.policy_changes({**monitor(), "allowed_actions": ["monitor"]}, registered(), ["monitor", "block_ip"])
        self.assertEqual(changes["allowed_actions"], ["monitor"])
        with self.assertRaisesRegex(policy.PolicyError, "BLOCK_ACTION_NOT_ALLOWED"):
            policy.policy_changes({**enforced(), "allowed_actions": ["monitor"]}, registered(), ["monitor", "block_ip"])

    def test_shared_revision_matches_sdk_decimal_and_python_integer(self):
        integer = {**registered(), "auto_block_policy": enforced()["auto_block_policy"], "rate_limit": 1000}
        decimal = copy.deepcopy(integer)
        decimal["rate_limit"] = Decimal("1000")
        decimal["updated_at"] = Decimal("999")
        decimal["auto_block_policy"]["window_seconds"] = Decimal("300")
        decimal["auto_block_policy"]["min_requests"] = Decimal("20")
        self.assertEqual(policy.revision_for(integer), policy.revision_for(decimal))
        # Periodic discovery reuses this shared function over preserved policy.
        changes, revision = policy.policy_changes(policy.validate(enforced()), decimal, ["monitor", "block_ip"])
        reconciled = {**decimal, **changes, "updated_at": 1000}
        self.assertEqual(revision, policy.revision_for(reconciled))

    def test_duplicate_json_fields_do_not_hide_conflicting_plan(self):
        with self.assertRaisesRegex(policy.PolicyError, "DUPLICATE_JSON_FIELD"):
            json.loads('{"service_id":"first","service_id":"second"}', object_pairs_hook=policy._strict_object)

    def test_disabled_optional_thresholds_cannot_be_null_or_boolean(self):
        for name, value in (("window_seconds", None), ("min_requests", None), ("window_seconds", True)):
            item = monitor()
            item["auto_block_policy"][name] = value
            with self.subTest(name=name, value=value), self.assertRaisesRegex(policy.PolicyError, "INVALID_AUTOMATIC_THRESHOLD"):
                policy.validate(item)


class AwsError(RuntimeError):
    def __init__(self, code):
        self.code = code


class Cli:
    def __init__(self):
        from boto3.dynamodb.types import TypeSerializer, TypeDeserializer
        self.serializer, self.deserializer = TypeSerializer(), TypeDeserializer()
        self.calls, self.updates = [], []
        self.item, self.account, self.conflict, self.lost_ack = registered(), ACCOUNT, False, False
        self.stack = {"StackName": INSTALLATION, "StackId": f"arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/{INSTALLATION}/unique-id",
                      "StackStatus": "UPDATE_COMPLETE", "Tags": [{"Key": "ManagedBy", "Value": "enterprise-security"}, {"Key": "InstallationId", "Value": INSTALLATION}],
                      "Outputs": [{"OutputKey": "InstallationId", "OutputValue": INSTALLATION}, {"OutputKey": "RegistryTableName", "OutputValue": TABLE},
                                  {"OutputKey": "RegistryTableArn", "OutputValue": f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{TABLE}"}],
                      "Parameters": [{"ParameterKey": "AllowedActions", "ParameterValue": "monitor,block_ip"}]}

    def encode(self, values):
        return {name: self.serializer.serialize(value) for name, value in values.items()}

    def __call__(self, *arguments, **kwargs):
        self.calls.append((arguments, kwargs))
        if arguments[:2] == ("sts", "get-caller-identity"):
            return {"Account": self.account, "Arn": f"arn:aws:iam::{self.account}:role/CompanyOperator"}
        if arguments[:2] == ("cloudformation", "describe-stacks"):
            return {"Stacks": [copy.deepcopy(self.stack)]}
        if arguments[:2] == ("dynamodb", "get-item"):
            if "--consistent-read" not in arguments:
                raise AssertionError("Strong registry read required")
            return {"Item": self.encode(self.item)}
        if arguments[:2] == ("dynamodb", "update-item"):
            select = lambda name: arguments[arguments.index(name) + 1]
            names = json.loads(select("--expression-attribute-names"))
            raw_values = json.loads(select("--expression-attribute-values"))
            values = {name: self.deserializer.deserialize(value) for name, value in raw_values.items()}
            request = {"TableName": select("--table-name"), "Key": json.loads(select("--key")),
                       "UpdateExpression": select("--update-expression"), "ConditionExpression": select("--condition-expression"),
                       "ExpressionAttributeNames": names, "ExpressionAttributeValues": raw_values}
            from botocore.session import Session
            from botocore.validate import validate_parameters
            validate_parameters(request, Session().get_service_model("dynamodb").operation_model("UpdateItem").input_shape)
            if self.conflict or values[":old"] != self.item["revision"]:
                raise AwsError("ConditionalCheckFailedException")
            if self.lost_ack == "uncommitted":
                raise AwsError("UnknownAcknowledgement")
            assignments = select("--update-expression")[4:].split(", ")
            for expression in assignments:
                alias, token = expression.split(" = ")
                self.item[names[alias]] = values[token]
            self.updates.append(request)
            if self.lost_ack == "committed":
                raise AwsError("UnknownAcknowledgement")
            return {}
        raise AssertionError("Unexpected operation: " + str(arguments[:2]))


@unittest.skipUnless(importlib.util.find_spec("boto3"), "Pinned boto3 test dependencies are required for real SDK schema tests")
class AppliedPolicyTests(unittest.TestCase):
    def setUp(self):
        self.cli = Cli()

    def apply(self, document=None, **overrides):
        args = {"installation_id": INSTALLATION, "profile": "company", "region": REGION, "call": self.cli, **overrides}
        return policy.apply(document or enforced(), **args)

    def test_apply_preserves_all_immutable_bindings_and_uses_cas(self):
        before = copy.deepcopy(self.cli.item)
        result = self.apply(enable_enforcement=True)
        self.assertEqual(result["status"], "APPLIED")
        for field in set(before) - policy.POLICY_FIELDS - {"revision"}:
            self.assertEqual(self.cli.item[field], before[field])
        self.assertEqual(self.cli.item["revision"], policy.revision_for(self.cli.item))
        request = self.cli.updates[0]
        self.assertIn("#revision = :old", request["ConditionExpression"])
        self.assertIn("#account = :account", request["ConditionExpression"])
        self.assertIn("#enabled = :enabled", request["ConditionExpression"])
        self.assertTrue(all(row[1] == {"profile": "company", "region": REGION} for row in self.cli.calls))

    def test_repeat_same_policy_is_unchanged_without_write(self):
        self.apply(enable_enforcement=True)
        self.assertEqual(self.apply(enable_enforcement=True)["status"], "UNCHANGED")
        self.assertEqual(len(self.cli.updates), 1)

    def test_enforcement_without_explicit_flag_is_rejected_before_aws(self):
        with self.assertRaisesRegex(policy.PolicyError, "ENABLE_ENFORCEMENT_REQUIRED"):
            self.apply()
        self.assertEqual(self.cli.calls, [])

    def test_foreign_account_stack_or_table_cannot_write(self):
        for mutate in (lambda cli: setattr(cli, "account", "999999999999"),
                       lambda cli: cli.stack.update(Tags=[]),
                       lambda cli: cli.stack.update(StackStatus="UPDATE_IN_PROGRESS"),
                       lambda cli: cli.stack["Outputs"][2].update(OutputValue=f"arn:aws:dynamodb:{REGION}:999999999999:table/{TABLE}")):
            with self.subTest(mutate=mutate):
                self.cli = Cli()
                mutate(self.cli)
                with self.assertRaises(policy.PolicyError):
                    self.apply(enable_enforcement=True)
                self.assertEqual(self.cli.updates, [])

    def test_disabled_foreign_service_and_missing_revision_fail_closed(self):
        for field, value in (("enabled", False), ("account_id", "999999999999"), ("service_id", "another-service"), ("revision", None)):
            self.cli = Cli()
            self.cli.item[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(policy.PolicyError, "SERVICE_NOT_REGISTERED"):
                self.apply(enable_enforcement=True)
            self.assertEqual(self.cli.updates, [])

    def test_conflict_requires_review_and_never_overwrites(self):
        self.cli.conflict = True
        before = copy.deepcopy(self.cli.item)
        result = self.apply(enable_enforcement=True)
        self.assertEqual(result, {"status": "REVIEW_REQUIRED", "reason_code": "REGISTRY_CHANGED", "service_id": SERVICE, "mutation": "NOT_APPLIED"})
        self.assertEqual(self.cli.item, before)
        self.assertEqual(sum(row[0][:2] == ("dynamodb", "update-item") for row in self.cli.calls), 1)

    def test_lost_ack_proves_commit_or_reports_unknown_without_retry(self):
        self.cli.lost_ack = "committed"
        result = self.apply(enable_enforcement=True)
        self.assertEqual(result["acknowledgement"], "VERIFIED_BY_STRONG_READ")
        self.cli = Cli()
        self.cli.lost_ack = "uncommitted"
        result = self.apply(enable_enforcement=True)
        self.assertEqual(result["mutation"], "UNKNOWN")
        self.assertEqual(sum(row[0][:2] == ("dynamodb", "update-item") for row in self.cli.calls), 1)

    def test_observe_and_disabled_automatic_policy_schema_are_valid(self):
        from jsonschema import Draft202012Validator
        self.apply(monitor())
        schema = json.loads((ROOT / "service-onboarding/registry.schema.json").read_text())
        native = json.loads(json.dumps(self.cli.item, default=lambda item: int(item)))
        # Test fixture IPSet IDs are valid-shaped hex UUID-length placeholders.
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(native)), [])

    def test_optional_groups_apply_and_explicit_manual_observe_remains_allowed(self):
        document = {**monitor(), "manual_block_enabled": True, "allowed_reader_groups": ["auditors"]}
        self.apply(document)
        self.assertTrue(self.cli.item["manual_block_enabled"])
        self.assertEqual(self.cli.item["allowed_reader_groups"], ["auditors"])
        self.assertEqual(self.cli.item["allowed_admin_groups"], ["security-admins"])

    def test_terraform_policy_apply_keeps_bindings_and_cas_without_cloudformation(self):
        sys.path.insert(0, str(ROOT / "service-onboarding"))
        outputs = {row["OutputKey"]: row["OutputValue"] for row in self.cli.stack["Outputs"]}
        verified = argparse.Namespace(outputs=outputs, foundation_parameters={"AllowedActions": "monitor,block_ip"})
        before = copy.deepcopy(self.cli.item)
        with patch("deployment_contract.resolve_terraform", return_value=verified) as resolver:
            result = self.apply(enable_enforcement=True, deployment_outputs="external-company-output.json")
        self.assertEqual(result["status"], "APPLIED")
        self.assertFalse(any(row[0][0] == "cloudformation" for row in self.cli.calls))
        resolver.assert_called_once_with("external-company-output.json", installation_id=INSTALLATION, account_id=ACCOUNT,
                                         profile="company", region=REGION, call=self.cli)
        self.assertIn("#revision = :old", self.cli.updates[0]["ConditionExpression"])
        for field in set(before) - policy.POLICY_FIELDS - {"revision"}:
            self.assertEqual(self.cli.item[field], before[field])

    def test_unverified_terraform_deployment_never_reads_or_writes_registry(self):
        sys.path.insert(0, str(ROOT / "service-onboarding"))
        from deployment_contract import DeploymentError
        with patch("deployment_contract.resolve_terraform", side_effect=DeploymentError("DEPLOYMENT_RESOURCE_OWNERSHIP_MISMATCH")):
            with self.assertRaisesRegex(policy.PolicyError, "OWNERSHIP_MISMATCH"):
                self.apply(enable_enforcement=True, deployment_outputs="external-company-output.json")
        self.assertEqual(self.cli.updates, [])
        self.assertEqual([row[0][:2] for row in self.cli.calls], [("sts", "get-caller-identity")])


if __name__ == "__main__":
    unittest.main()
