"""Region-aware import IDs must never resolve a foreign regional resource."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("terraform_imports_tests", ROOT / "tools/terraform_imports.py")
imports = importlib.util.module_from_spec(spec)
spec.loader.exec_module(imports)


class RegionImportTests(unittest.TestCase):
    def test_all_reviewed_regional_types_receive_explicit_region(self):
        for kind in imports.REGIONAL_IMPORT_TYPES:
            with self.subTest(kind=kind):
                self.assertEqual(imports.regional_import_id(kind, "synthetic-resource", "us-east-1"), "synthetic-resource@us-east-1")

    def test_iam_global_ids_remain_unchanged_including_legal_at_character(self):
        for kind in imports.GLOBAL_IMPORT_TYPES:
            with self.subTest(kind=kind):
                self.assertEqual(imports.regional_import_id(kind, "role@example:policy", "ap-northeast-2"), "role@example:policy")

    def test_compound_ids_and_arn_ids_keep_exact_original_identity(self):
        for kind, original in (("aws_cloudwatch_event_target", "bus/rule/target"), ("aws_lambda_permission", "worker:live/owned-statement"),
                               ("aws_apigatewayv2_stage", "synthetic-api/$default"), ("aws_sfn_state_machine", "arn:aws:states:us-east-1:123456789012:stateMachine:synthetic")):
            with self.subTest(kind=kind):
                self.assertEqual(imports.regional_import_id(kind, original, "us-east-1"), original + "@us-east-1")

    def test_same_suffix_is_idempotent_and_foreign_suffix_fails_closed(self):
        self.assertEqual(imports.regional_import_id("aws_s3_bucket", "synthetic-bucket@us-east-1", "us-east-1"), "synthetic-bucket@us-east-1")
        with self.assertRaisesRegex(imports.ImportSpecError, "SUFFIX_MISMATCH"):
            imports.regional_import_id("aws_s3_bucket", "synthetic-bucket@us-west-2", "us-east-1")

    def test_unknown_scope_and_invalid_region_are_not_guessed(self):
        for kind, region in (("aws_unknown_service", "us-east-1"), ("aws_s3_bucket", "us-east-1@elsewhere")):
            with self.subTest(kind=kind), self.assertRaises(imports.ImportSpecError):
                imports.regional_import_id(kind, "synthetic-resource", region)

    def test_manifest_build_qualifies_regional_only_and_preserves_names(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            mapping = {"provider": "hashicorp/aws", "provider_version": "6.69.0", "modules": {}}
            for module, region, logical, cfn_type, native, physical in (
                    ("foundation", "ap-northeast-2", "AuditBucket", "AWS::S3::Bucket", "aws_s3_bucket", "synthetic-audit-bucket"),
                    ("governance", "ap-northeast-2", "WorkerRole", "AWS::IAM::Role", "aws_iam_role", "synthetic-worker-role"),
                    ("ingress", "us-east-1", "Ingress", "AWS::Lambda::Function", "aws_lambda_function", "synthetic-ingress")):
                name = "example-security" + ("" if module == "foundation" else "-" + module)
                snapshot = {"stack": {"Stacks": [{"StackName": name, "StackId": f"arn:aws:cloudformation:{region}:123456789012:stack/{name}/synthetic",
                    "StackStatus": "UPDATE_COMPLETE", "Tags": [{"Key": "ManagedBy", "Value": "enterprise-security"}, {"Key": "InstallationId", "Value": "example-security"}]}]},
                    "template": {"TemplateBody": {"Resources": {logical: {"Type": cfn_type, "Properties": {}}}}},
                    "resources": {"StackResourceSummaries": [{"LogicalResourceId": logical, "PhysicalResourceId": physical, "ResourceType": cfn_type, "ResourceStatus": "CREATE_COMPLETE"}]}}
                (source / (module + "-snapshot.json")).write_text(json.dumps(snapshot), encoding="utf-8")
                mapping["modules"][module] = {logical: {"cfn_type": cfn_type, "physical_name_override": True,
                    "terraform_imports": [{"address": native + "." + logical, "type": native}]}}
            map_path = source / "map.json"
            map_path.write_text(json.dumps(mapping), encoding="utf-8")
            calls = []
            def call(*args, **kwargs):
                calls.append(args)
                if args == ("sts", "get-caller-identity"): return {"Account": "123456789012"}
                raise AssertionError("No additional AWS reads or writes needed")
            result = imports.build(source, resource_map=map_path, call=call)
            rows = {row["logical"]: row for row in result["imports"]}
            self.assertEqual(rows["AuditBucket"]["id"], "synthetic-audit-bucket@ap-northeast-2")
            self.assertEqual(rows["WorkerRole"]["id"], "synthetic-worker-role")
            self.assertEqual(rows["Ingress"]["id"], "synthetic-ingress@us-east-1")
            self.assertEqual(rows["Ingress"]["address"], 'module.ingress["us-east-1"].aws_lambda_function.Ingress')
            self.assertEqual(result["physical_names"]["foundation"]["AuditBucket"], "synthetic-audit-bucket")
            self.assertEqual(calls, [("sts", "get-caller-identity")])


if __name__ == "__main__":
    unittest.main()
