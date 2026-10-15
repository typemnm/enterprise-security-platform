"""No AWS, Terraform or network: adversarial plan and CFN-retention fixtures."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest

import terraform_migration_guard as guard

ADDRESS = 'module.governance.aws_lambda_function.Publication'


def change(actions=None, address=ADDRESS, importing=None):
    result = {"address": address, "mode": "managed", "change": {"actions": actions or ["no-op"]}}
    if importing is not None:
        result["change"]["importing"] = importing
    return result


def plan(*changes):
    return {"format_version": "1.2", "terraform_version": "1.16.3", "complete": True,
            "errored": False, "applyable": True, "resource_changes": list(changes),
            "checks": [{"status": "pass", "address": {"kind": "output_value", "to_display": "output.deployment"},
                        "instances": [{"status": "pass"}]}]}


def retained(**extra):
    return {"Type": "AWS::DynamoDB::Table", "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain", **extra}


class MigrationPlanTests(unittest.TestCase):
    def passed(self, value):
        self.assertEqual(value["status"], "PASSED", value)

    def failed(self, value, code=None):
        self.assertEqual(value["status"], "FAILED", value)
        if code:
            self.assertIn(code, {row["code"] for row in value["findings"]})

    def test_import_no_op_with_import_id_and_data_read_are_allowed(self):
        row = change(["read"], 'module.foundation.data.aws_partition.current')
        row["mode"] = "data"
        value = guard.validate_plan(plan(change(importing={"id": "private-import-identifier"}), row))
        self.passed(value)
        self.assertEqual(value["resources"][0], {"address": ADDRESS, "actions": ["no-op"]})
        self.assertNotIn("private-import-identifier", json.dumps(value))

    def test_import_rejects_every_mutation_even_if_create_is_allowlisted(self):
        for actions in [["create"], ["update"], ["delete"], ["forget"], ["delete", "create"], ["create", "delete"]]:
            with self.subTest(actions=actions):
                self.failed(guard.validate_plan(plan(change(actions))))
        self.failed(guard.validate_plan(plan(change(["create"])), allow_create_addresses=[ADDRESS]), "IMPORT_CREATE_ALLOWLIST_FORBIDDEN")

    def test_adoption_updates_and_only_exact_allowlisted_creates_are_allowed(self):
        self.passed(guard.validate_plan(plan(change(["update"])), "adoption"))
        self.failed(guard.validate_plan(plan(change(["create"])), "adoption"), "CREATE_ADDRESS_NOT_ALLOWED")
        self.passed(guard.validate_plan(plan(change(["create"])), "adoption", [ADDRESS]))
        self.failed(guard.validate_plan(plan(change(["create"], ADDRESS + "Copy")), "adoption", [ADDRESS]), "CREATE_ADDRESS_NOT_ALLOWED")
        for pattern in ["*", "module.governance.*", "module.governance.aws_lambda_function.Publication[*]"]:
            with self.subTest(pattern=pattern):
                self.failed(guard.validate_plan(plan(change()), "adoption", [pattern]), "CREATE_ALLOWLIST_INVALID")

    def test_adoption_never_allows_delete_replace_or_forget(self):
        for actions in [["delete"], ["forget"], ["replace"], ["delete", "create"], ["create", "delete"], ["create", "forget"]]:
            with self.subTest(actions=actions):
                self.failed(guard.validate_plan(plan(change(actions)), "adoption", [ADDRESS]))
        row = change(["update"])
        row["change"]["replace_paths"] = [["name"]]
        self.failed(guard.validate_plan(plan(row), "adoption"), "REPLACEMENT_NOT_ALLOWED")

    def test_unknown_empty_wrong_type_and_multi_actions_fail_closed(self):
        for actions in [[], None, "no-op", ["future-action"], [True], [{"secret": "private"}], ["no-op", "read"]]:
            with self.subTest(actions=actions):
                row = change()
                row["change"]["actions"] = actions
                self.failed(guard.validate_plan(plan(row), "adoption"))

    def test_incomplete_errored_deferred_and_unsupported_plans_are_rejected(self):
        for field, value in [("complete", False), ("complete", "true"), ("complete", None),
                             ("errored", True), ("errored", None), ("errored", "false"),
                             ("format_version", "2.0"), ("format_version", None),
                             ("applyable", "true"), ("deferred_changes", [{}])]:
            with self.subTest(field=field, value=value):
                candidate = plan(change())
                candidate[field] = value
                self.failed(guard.validate_plan(candidate))
        for field in ["complete", "errored", "resource_changes"]:
            candidate = plan(change())
            del candidate[field]
            self.failed(guard.validate_plan(candidate))

    def test_checks_and_raw_check_results_require_every_instance_to_pass(self):
        for key in ["checks", "check_results"]:
            for status in ["fail", "failed", "error", "unknown", False, None, "future-status"]:
                with self.subTest(key=key, status=status):
                    candidate = plan(change())
                    candidate[key] = [{"status": status, "failure_messages": ["private-message"]}]
                    value = guard.validate_plan(candidate)
                    self.failed(value, "CHECK_NOT_PASSED")
                    self.assertNotIn("private-message", json.dumps(value))
            for children in ["instances", "objects"]:
                candidate = plan(change())
                candidate[key] = [{"status": "pass", children: [{"status": "unknown"}]}]
                self.failed(guard.validate_plan(candidate), "CHECK_NOT_PASSED")
                candidate[key][0][children][0]["status"] = "pass"
                self.passed(guard.validate_plan(candidate))
        candidate = plan(change())
        candidate["checks"] = None
        self.failed(guard.validate_plan(candidate), "CHECK_RESULTS_INVALID")

    def test_duplicate_deposed_invalid_mode_and_import_without_known_id_fail(self):
        self.failed(guard.validate_plan(plan(change(), change())), "DUPLICATE_RESOURCE_ADDRESS")
        row = change()
        row["deposed"] = "private-old-object"
        self.failed(guard.validate_plan(plan(row)), "DEPOSED_RESOURCE_REVIEW_REQUIRED")
        row = change()
        row["mode"] = []
        self.failed(guard.validate_plan(plan(row)), "RESOURCE_MODE_INVALID")
        for importing in [{}, {"id": None}, {"id": ""}, {"id": "   "}, {"unknown": True}, "private"]:
            self.failed(guard.validate_plan(plan(change(importing=importing))), "IMPORT_ID_UNKNOWN_OR_INVALID")
        self.failed(guard.validate_plan(plan(change(["update"], importing={"id": "private"})), "adoption"), "IMPORT_MUST_BE_NO_OP")

    def test_addresses_support_exact_module_instances_but_never_echo_invalid_input(self):
        address = 'module.ingress["us-east-1"].module.nested[0].aws_lambda_function.Ingest[0]'
        self.passed(guard.validate_plan(plan(change(address=address))))
        for address in ["private-value", ADDRESS + "\nprivate", 'aws_lambda_function.Test["xoxb-' + "Z" * 25 + '"]']:
            value = guard.validate_plan(plan(change(address=address)))
            self.failed(value, "RESOURCE_ADDRESS_INVALID")
            self.assertNotIn(address, json.dumps(value))

    def test_plan_summary_never_contains_values_ids_diagnostic_or_sensitive_messages(self):
        marker = "private-plan-material"
        candidate = plan(change(importing={"id": marker}))
        candidate.update(variables={"token": {"value": marker}}, planned_values={"outputs": {"secret": {"value": marker}}},
                         prior_state={"values": marker}, diagnostics=[{"severity": "warning", "detail": marker}])
        candidate["resource_changes"][0]["change"].update(before={"password": marker}, after={"password": marker})
        value = guard.validate_plan(candidate)
        self.passed(value)
        self.assertNotIn(marker, json.dumps(value))
        candidate["diagnostics"][0]["severity"] = "error"
        value = guard.validate_plan(candidate)
        self.failed(value, "PLAN_DIAGNOSTIC_ERROR_OR_UNKNOWN")
        self.assertNotIn(marker, json.dumps(value))

    def test_malformed_top_level_and_phase_are_safe_failures(self):
        for candidate in [None, [], "private", 1]:
            self.failed(guard.validate_plan(candidate))
        self.failed(guard.validate_plan(plan(change()), phase={"private": "value"}), "PHASE_INVALID")


class RetentionTests(unittest.TestCase):
    def test_same_actual_resource_set_requires_both_exact_retain_policies(self):
        template = {"Resources": {"CasesTable": retained(), "AuditBucket": retained()}}
        self.assertEqual(guard.verify_retention(template, {"CasesTable", "AuditBucket"})["status"], "PASSED")
        for field in ["DeletionPolicy", "UpdateReplacePolicy"]:
            for value in [None, "Delete", "Snapshot", "RetainExceptOnCreate", {"Fn::If": ["Flag", "Retain", "Delete"]}]:
                with self.subTest(field=field, value=value):
                    candidate = copy.deepcopy(template)
                    candidate["Resources"]["CasesTable"][field] = value
                    self.assertEqual(guard.verify_retention(candidate, set(template["Resources"]))["status"], "FAILED")

    def test_missing_and_extra_actual_resources_cannot_be_hidden(self):
        template = {"Resources": {"CasesTable": retained(), "AuditBucket": retained()}}
        for actual in [{"CasesTable"}, {"CasesTable", "AuditBucket", "ForeignTable"}, ["CasesTable", "CasesTable"], []]:
            with self.subTest(actual=actual):
                self.assertEqual(guard.verify_retention(template, actual)["status"], "FAILED")

    def test_only_a_declared_independently_confirmed_false_condition_may_be_absent(self):
        template = {"Conditions": {"SlackEnabled": {"Fn::Equals": ["", "configured"]}},
                    "Resources": {"CasesTable": retained(), "OptionalQueue": {"Type": "AWS::SQS::Queue", "Condition": "SlackEnabled"}}}
        self.assertEqual(guard.verify_retention(template, {"CasesTable"}, {"SlackEnabled": False})["status"], "PASSED")
        for conditions in [None, {}, {"SlackEnabled": True}, {"SlackEnabled": 0}, {"SlackEnabled": "false"}]:
            self.assertEqual(guard.verify_retention(template, {"CasesTable"}, conditions)["status"], "FAILED")
        self.assertEqual(guard.verify_retention(template, {"CasesTable", "OptionalQueue"}, {"SlackEnabled": False})["status"], "FAILED")
        del template["Conditions"]
        self.assertEqual(guard.verify_retention(template, {"CasesTable"}, {"SlackEnabled": False})["status"], "FAILED")

    def test_incomplete_or_malformed_snapshot_never_looks_retained(self):
        for template, actual in [(None, {"CasesTable"}), ({"Resources": {}}, []),
                                 ({"Resources": {"CasesTable": None}}, {"CasesTable"}),
                                 ({"Resources": {"CasesTable": retained()}}, "CasesTable")]:
            self.assertEqual(guard.verify_retention(template, actual)["status"], "FAILED")


class GuardCliTests(unittest.TestCase):
    def temporary(self):
        workspace = Path(__file__).resolve().parents[1] / "build/migration-guard-tests"
        workspace.mkdir(parents=True, exist_ok=True)
        return tempfile.TemporaryDirectory(dir=workspace)

    def invoke(self, args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = guard.main(args)
        return code, json.loads(output.getvalue())

    def test_cli_plan_and_retention_inputs_are_offline_and_machine_readable(self):
        with self.temporary() as directory:
            root = Path(directory)
            candidate = root / "plan.json"
            candidate.write_text(json.dumps(plan(change())), encoding="utf-8-sig")
            code, value = self.invoke(["--plan-json", str(candidate), "--phase", "import"])
            self.assertEqual((code, value["status"]), (0, "PASSED"))
            template, actual = root / "template.json", root / "actual.json"
            template.write_text(json.dumps({"Resources": {"CasesTable": retained()}}), encoding="utf-8")
            actual.write_text('["CasesTable"]', encoding="utf-8")
            code, value = self.invoke(["--template-json", str(template), "--actual-resource-ids-json", str(actual)])
            self.assertEqual((code, value["status"]), (0, "PASSED"))

    def test_duplicate_json_nonstandard_numbers_and_bad_documents_leak_no_payload(self):
        with self.temporary() as directory:
            path = Path(directory) / "private.json"
            for body in ['{"complete":true,"complete":false,"token":"private-material"}', '{"token":NaN}', '{"token":"private-material"']:
                with self.subTest(body=body):
                    path.write_text(body, encoding="utf-8")
                    code, value = self.invoke(["--plan-json", str(path)])
                    self.assertEqual(code, 1)
                    self.assertEqual(value["status"], "FAILED")
                    self.assertNotIn("private-material", json.dumps(value))

    def test_argument_errors_do_not_echo_unknown_values_or_paths(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as caught:
            guard.main(["--phase", "private-material"])
        self.assertEqual(caught.exception.code, 2)
        self.assertNotIn("private-material", output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["status"], "FAILED")


if __name__ == "__main__":
    unittest.main()
