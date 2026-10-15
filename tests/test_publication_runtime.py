"""Offline failure, race, partial-response and tenant-boundary checks."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime"))
from case_pipeline import finalize
from outcome_metadata import block_result, error_fields
from publication import CasePublicationStore, PublicationBusy, PublicationCoordinator, make_job
from publication_events import make_outbox
from publication_reconciler import reconcile, emit_metrics
from outbox_delivery import project, publish_outbox, publish_case, refresh_marker, stream_needs_delivery
from terminal import identify, normalize_eventbridge, terminate
from workflow_builder import build_workflow
from runtime_fakes import FakeEvents, FakeS3, MemoryTable, ClientError

CASE = "inv-" + "a" * 32
SERVICE = "orders-prod"
ACCOUNT = "123456789012"
REGION = "ap-northeast-2"
MACHINE = f"arn:aws:states:{REGION}:{ACCOUNT}:stateMachine:security-pipeline"
EXECUTION = MACHINE.replace(":stateMachine:", ":execution:") + ":" + CASE
BUCKET = "test-reports-bucket"
KEY = SERVICE + "/" + CASE + ".md"
STAMP = "2026-10-14T00:00:00Z"
BODY = "# 리포트\n## 요약\n시도 42회가 확인됐습니다.\n## 판단 근거\nprivate raw evidence\n"


class KeyedReadTable:
    """Private registry/operation fixtures contain no deployed resources."""
    def __init__(self, key, rows):
        self.key, self.rows, self.calls = key, copy.deepcopy(rows), []

    def get_item(self, **kwargs):
        self.calls.append(copy.deepcopy(kwargs))
        return {"Item": copy.deepcopy(self.rows.get(kwargs["Key"][self.key], {}))}


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000
        self.registry = KeyedReadTable("service_id", {SERVICE: {"service_id": SERVICE, "account_id": ACCOUNT,
            "region": REGION, "enabled": True, "response_mode": "observe", "audit_bucket": BUCKET,
            "resource_arns": [f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/orders/abcdef"],
            "allowed_actions": ["monitor", "block_ip"], "waf_scope": "REGIONAL",
            "waf_ipset_arn": f"arn:aws:wafv2:{REGION}:{ACCOUNT}:regional/ipset/security-orders/012345ab-cdef", "revision": "7"}})
        self.table = MemoryTable({CASE: {"case_id": CASE, "service_id": SERVICE, "status": "TRIAGED", "tier": 1,
            "dashboard_bucket": BUCKET, "dashboard_key": KEY, "report_md": BODY,
            "workflow_execution_arn": EXECUTION, "dry_run": False,
            "recommended_action": "block_ip", "target": {"source_ip": "8.8.8.8"}, "task_token": "must-not-leave-case"}})
        self.store, self.s3, self.events = CasePublicationStore(self.table), FakeS3(), FakeEvents()
        self.coordinator = PublicationCoordinator(self.store, self.s3, clock=lambda: self.now, retry_delay=10)

    def job(self, state="AUTO_BLOCK_FAILED", phase="OUTCOME", response=None):
        outbox = make_outbox(CASE, SERVICE, state, 1, BUCKET, KEY, STAMP, phase=phase,
                             summary="시도 42회", recommended_action="block_ip", response=response)
        attribute = "dashboard_notification_hotl" if phase == "INITIAL" else "dashboard_notification_outcome"
        return make_job(CASE, SERVICE, BUCKET, KEY, BODY, phase, attribute, outbox, self.now)

    def response(self, status="APPLIED", waf="APPLIED", nacl="NOT_REQUIRED", required=None, service=SERVICE, case_id=CASE):
        return {"schema_version": "1.0", "service_id": service, "case_id": case_id, "operation_id": "operation-123",
                "status": status, "required_components": required or ["waf"],
                "components": {"waf": {"status": waf}, "nacl": {"status": nacl, "error_code": "AccessDenied"} if nacl == "FAILED" else {"status": nacl}}}

    def test_actual_required_waf_and_optional_nacl_are_reported_separately(self):
        applied = block_result({"block": {"result": self.response()}}, "AUTO_BLOCK_RESULT", SERVICE, case_id=CASE)
        self.assertEqual(applied["outcome"], "AUTO_BLOCKED")
        self.assertEqual(applied["components"]["nacl"]["status"], "NOT_REQUIRED")
        partial = block_result({"block": {"result": self.response("PARTIAL", nacl="FAILED", required=["waf", "nacl"])}}, "AUTO_BLOCK_RESULT", SERVICE, case_id=CASE)
        self.assertEqual(partial["outcome"], "AUTO_BLOCK_PARTIAL")
        self.assertEqual(partial["components"]["waf"]["status"], "APPLIED")
        self.assertEqual(partial["components"]["nacl"]["error_code"], "AccessDenied")

    def test_missing_scope_or_required_evidence_never_becomes_applied(self):
        for value in (self.response(service="other-service"), self.response(case_id="inv-" + "b" * 32),
                      {**self.response(), "components": {}}, {**self.response(), "required_components": ["database"]}):
            with self.subTest(response=value):
                self.assertEqual(block_result({"block": {"result": value}}, "AUTO_BLOCKED", SERVICE, case_id=CASE)["outcome"], "AUTO_BLOCK_UNVERIFIED")
        self.assertEqual(block_result({"block": {"status_code": 200}}, "AUTO_BLOCKED", SERVICE)["outcome"], "AUTO_BLOCK_UNVERIFIED")

    def test_error_selection_never_exports_cause_tokens_or_arbitrary_text(self):
        selected = error_fields({"block_error": {"Error": "AccessDeniedException", "Cause": "raw TaskToken=secret"},
                                 "isolation_error": {"Error": "xoxb-private-secret", "Cause": "private"}})
        self.assertEqual(selected["block_error"], {"Error": "AccessDeniedException"})
        self.assertEqual(selected["isolation_error"]["Error"], "UNCLASSIFIED_ERROR")
        self.assertNotIn("secret", json.dumps(selected))

    def test_s3_failure_records_business_outcome_and_journal_before_outbox(self):
        self.s3.fail = True
        result = self.coordinator.submit(self.job(), {"status": "AUTO_BLOCK_FAILED"})
        case = self.table.items[CASE]
        self.assertEqual(result["state"], "PENDING")
        self.assertEqual(case["status"], "AUTO_BLOCK_FAILED")
        self.assertEqual(case["dashboard_publication"]["body"], BODY)
        self.assertEqual(case["dashboard_publication"]["last_error_code"], "AccessDenied")
        self.assertNotIn("dashboard_notification_outcome", case)

    def test_reconciler_recovers_s3_failure_and_emits_outbox_once(self):
        self.s3.fail = True
        self.coordinator.submit(self.job(), {"status": "AUTO_BLOCK_FAILED"})
        self.s3.fail, self.now = False, 1011
        result = reconcile(self.table, self.s3, self.events, "notifications", clock=lambda: self.now)
        self.assertEqual(result["published"], 1)
        self.assertEqual(len(self.events.calls), 1)
        self.assertEqual(self.table.items[CASE]["dashboard_notification_outcome"]["status"], "EMITTED")
        self.assertNotIn("body", self.table.items[CASE]["dashboard_publication"])
        reconcile(self.table, self.s3, self.events, "notifications", clock=lambda: self.now)
        self.assertEqual(len(self.events.calls), 1)

    def test_active_lease_blocks_concurrent_publication_and_superseding_write(self):
        job = self.job()
        self.store.prepare(job, {"status": "AUTO_BLOCK_FAILED"}, self.now)
        self.assertTrue(self.store.claim(CASE, job["revision"], SERVICE, "first-owner", self.now, 60))
        self.assertFalse(self.store.claim(CASE, job["revision"], SERVICE, "second-owner", self.now, 60))
        with self.assertRaises(PublicationBusy):
            self.store.prepare(self.job("AUTO_BLOCK_PARTIAL"), {"status": "AUTO_BLOCK_PARTIAL"}, self.now)
        self.assertFalse(self.s3.calls)

    def test_expired_lease_can_be_recovered_but_stale_owner_cannot_commit(self):
        job = self.job()
        self.store.prepare(job, {"status": "AUTO_BLOCK_FAILED"}, self.now)
        self.store.claim(CASE, job["revision"], SERVICE, "stale-owner", self.now, 60)
        self.now = 1061
        self.assertEqual(self.coordinator.deliver(CASE)["state"], "PUBLISHED")
        with self.assertRaises(ClientError):
            self.store.complete(job, "stale-owner", self.now)

    def test_ambiguous_complete_that_already_committed_does_not_republish(self):
        self.table.complete_then_raise = True
        self.assertEqual(self.coordinator.submit(self.job(), {"status": "AUTO_BLOCK_FAILED"})["state"], "PUBLISHED")
        self.assertEqual(self.coordinator.deliver(CASE)["state"], "PUBLISHED")
        self.assertEqual(len(self.s3.calls), 1)

    def test_failed_complete_after_s3_remains_retryable(self):
        self.table.fail_complete = True
        self.assertEqual(self.coordinator.submit(self.job(), {"status": "AUTO_BLOCK_FAILED"})["state"], "PENDING")
        self.assertNotIn("dashboard_notification_outcome", self.table.items[CASE])
        self.table.fail_complete, self.now = False, 1011
        self.assertEqual(self.coordinator.deliver(CASE)["state"], "PUBLISHED")

    def test_same_revision_replay_preserves_emitted_receipt(self):
        job = self.job()
        self.coordinator.submit(job, {"status": "AUTO_BLOCK_FAILED"})
        publish_outbox(CASE, "dashboard_notification_outcome", self.table, self.events, "notifications", clock=lambda: self.now)
        self.coordinator.submit(job, {"status": "AUTO_BLOCK_FAILED"})
        self.assertEqual(len(self.s3.calls), 1)
        self.assertEqual(self.table.items[CASE]["dashboard_notification_outcome"]["status"], "EMITTED")
        self.assertEqual(publish_outbox(CASE, "dashboard_notification_outcome", self.table, self.events, "notifications", clock=lambda: self.now), "DUPLICATE")
        self.assertEqual(len(self.events.calls), 1)

    def test_eventbridge_failed_delivery_can_retry_same_stable_revision(self):
        self.coordinator.submit(self.job(), {"status": "AUTO_BLOCK_FAILED"})
        self.events.fail = True
        with self.assertRaises(RuntimeError):
            publish_outbox(CASE, "dashboard_notification_outcome", self.table, self.events, "notifications", clock=lambda: self.now)
        self.events.fail, self.now = False, 1031
        self.assertEqual(publish_outbox(CASE, "dashboard_notification_outcome", self.table, self.events, "notifications", clock=lambda: self.now), "EMITTED")
        self.assertEqual(self.events.calls[0]["Entries"][0]["Detail"], self.events.calls[1]["Entries"][0]["Detail"])

    def test_skipped_unknown_component_is_unverified_instead_of_exempt(self):
        response = self.response("SKIPPED", waf="UNKNOWN")
        response["error_code"] = "PREVIOUS_RESPONSE_INDETERMINATE"
        facts = block_result({"response": response}, "AUTO_BLOCK_RESULT", SERVICE, case_id=CASE)
        self.assertEqual(facts["outcome"], "AUTO_BLOCK_UNVERIFIED")
        self.assertEqual(facts["components"]["waf"]["status"], "UNKNOWN")

    def test_stream_own_writes_and_emitted_replays_do_not_create_feedback(self):
        self.coordinator.submit(self.job(), {"status": "AUTO_BLOCK_FAILED"})
        publish_case(CASE, self.table, self.events, "notifications", clock=lambda: self.now)
        mutations = len([call for call in self.table.calls if call[0] == "update_item"])
        publish_case(CASE, self.table, self.events, "notifications", clock=lambda: self.now + 99)
        self.assertEqual(len([call for call in self.table.calls if call[0] == "update_item"]), mutations)
        typed = lambda status: {"dashboard_notification_outcome": {"M": {"status": {"S": status}, "event_id": {"S": "a" * 64}}}}
        self.assertTrue(stream_needs_delivery({"dynamodb": {"NewImage": typed("PENDING")}}, self.now))
        for status in ("EMITTING", "EMITTED"):
            self.assertFalse(stream_needs_delivery({"dynamodb": {"NewImage": typed(status), "OldImage": typed("PENDING")}}, self.now))
        self.assertFalse(stream_needs_delivery({"dynamodb": {"NewImage": typed("PENDING"), "OldImage": typed("PENDING")}}, self.now))

    def test_marker_preserves_backoff_instead_of_retrying_a_stream_loop(self):
        self.coordinator.submit(self.job(), {"status": "AUTO_BLOCK_FAILED"})
        self.events.fail = True
        with self.assertRaises(RuntimeError):
            publish_outbox(CASE, "dashboard_notification_outcome", self.table, self.events, "notifications", clock=lambda: self.now)
        refresh_marker(self.table, CASE, self.now + 1)
        self.assertEqual(self.table.items[CASE]["notification_retry_at"], self.now + 30)

    def test_revision_changes_for_visible_summary_but_not_retry_timestamp(self):
        first = make_outbox(CASE, SERVICE, "TRIAGED", 1, BUCKET, KEY, STAMP, phase="INITIAL", summary="first", recommended_action="monitor")
        retry = make_outbox(CASE, SERVICE, "TRIAGED", 1, BUCKET, KEY, "2026-10-14T00:01:00Z", phase="INITIAL", summary="first", recommended_action="monitor")
        changed = make_outbox(CASE, SERVICE, "TRIAGED", 1, BUCKET, KEY, STAMP, phase="INITIAL", summary="second", recommended_action="monitor")
        self.assertEqual(first["event_id"], retry["event_id"])
        self.assertNotEqual(first["event_id"], changed["event_id"])

    def test_recovery_metrics_contain_only_bounded_counts_and_clear_after_success(self):
        class Metrics:
            def __init__(inner):
                inner.calls = []
            def put_metric_data(inner, **kw):
                inner.calls.append(kw)
        metrics = Metrics()
        emit_metrics(metrics, {"publication_pending": 2, "notification_pending": 1, "errors": 1, "raw": "TaskToken=secret"}, "security-reconciler")
        self.assertEqual([row["Value"] for row in metrics.calls[0]["MetricData"]], [3, 1])
        self.assertNotIn("TaskToken", json.dumps(metrics.calls))
        emit_metrics(metrics, {"publication_pending": 0, "notification_pending": 0, "errors": 0}, "security-reconciler")
        self.assertEqual([row["Value"] for row in metrics.calls[1]["MetricData"]], [0, 0])

    def test_outbox_metadata_is_bounded_and_drops_report_and_tokens(self):
        job = self.job()
        job["outbox"]["detail"].update(TaskToken="secret", report_md=BODY, evidence={"raw": "secret"})
        detail = project(job["outbox"], expected_case=CASE, expected_service=SERVICE)
        self.assertNotIn("secret", json.dumps(detail))
        self.assertNotIn("private raw evidence", json.dumps(detail))
        with self.assertRaises(ValueError):
            project(job["outbox"], expected_case=CASE, expected_service="other-service")

    def test_flat_legacy_report_key_is_denied_to_other_services(self):
        job = self.job()
        with self.assertRaisesRegex(ValueError, "KEY"):
            make_job(CASE, "checkout-prod", BUCKET, CASE + ".md", BODY, "OUTCOME", "dashboard_notification_outcome", job["outbox"], self.now)

    def test_record_publishes_private_journal_partial_truth_and_ignores_caller_errors(self):
        response = {**self.response("PARTIAL", nacl="FAILED", required=["waf", "nacl"]), "operation_id": EXECUTION}
        operation_key = "block#" + hashlib.sha256((SERVICE + ":" + CASE + ":" + EXECUTION).encode()).hexdigest()
        operations = KeyedReadTable("lease_id", {operation_key: {"service_id": SERVICE, "case_id": CASE, "result": response}})
        result = finalize({"case_id": CASE, "service_id": SERVICE, "execution_arn": EXECUTION, "outcome": "AUTO_BLOCK_RESULT",
            "response": {**response, "status": "APPLIED"}, "block_error": {"Error": "AccessDeniedException", "Cause": "TaskToken=secret"}},
            self.table, self.registry, self.s3, account=ACCOUNT, operations=operations, clock=lambda: self.now)
        self.assertEqual(result["recorded"], "AUTO_BLOCK_PARTIAL")
        self.assertEqual(operations.calls[0], {"Key": {"lease_id": operation_key}, "ConsistentRead": True})
        case = self.table.items[CASE]
        self.assertNotIn("block_error", case)
        self.assertEqual(case["block_response"]["components"]["nacl"]["error_code"], "AccessDenied")
        outbox = self.table.items[CASE]["dashboard_notification_outcome"]
        self.assertEqual(outbox["detail"]["actual_outcomes"]["waf"]["status"], "APPLIED")
        self.assertEqual(outbox["detail"]["actual_outcomes"]["nacl"], {"status": "FAILED", "error_code": "AccessDenied"})
        self.assertEqual(outbox["detail"]["service_id"], SERVICE)
        self.assertEqual(outbox["detail"]["result"]["key"], KEY)
        self.assertNotIn("TaskToken", json.dumps(outbox))
        self.assertNotIn("must-not-leave-case", json.dumps(outbox))

    def test_terminal_failure_is_idempotent_and_does_not_overwrite_final_response(self):
        event = {"stage": "AI1", "case_id": CASE, "service_id": SERVICE, "execution_arn": EXECUTION,
                 "failure": {"Error": "Lambda.Unknown", "Cause": "private"}}
        first = terminate(event, self.table, self.s3, registry=self.registry, account=ACCOUNT, machine_arn=MACHINE, clock=lambda: self.now)
        second = terminate(event, self.table, self.s3, registry=self.registry, account=ACCOUNT, machine_arn=MACHINE, clock=lambda: self.now + 20)
        self.assertEqual(first["revision"], second["revision"])
        self.assertEqual(len(self.s3.calls), 1)
        self.assertEqual(self.table.items[CASE]["terminal_error_code"], "Lambda.Unknown")
        self.table.items[CASE]["status"] = "AUTO_BLOCK_PARTIAL"
        self.assertEqual(terminate(event, self.table, self.s3, registry=self.registry, account=ACCOUNT, machine_arn=MACHINE)["state"], "SKIPPED")

    def test_terminal_derives_case_without_reading_execution_input(self):
        self.assertEqual(identify({"case_id": CASE}), CASE)
        event = {"source": "aws.states", "detail-type": "Step Functions Execution Status Change", "account": ACCOUNT, "region": REGION,
                 "detail": {"status": "FAILED", "stateMachineArn": MACHINE, "executionArn": EXECUTION,
                            "input": "must-not-read", "cause": "must-not-read"}}
        class Metadata:
            def describe_execution(inner, **kwargs):
                self.assertEqual(kwargs["includedData"], "METADATA_ONLY")
                return {"executionArn": EXECUTION, "stateMachineArn": MACHINE, "status": "FAILED"}
        normalized = normalize_eventbridge(event, machines={"PUBLICATION": MACHINE}, account=ACCOUNT, region=REGION, sfn=Metadata())
        self.assertEqual(normalized["case_id"], CASE)
        self.assertTrue(normalized["require_existing_case"])
        self.assertNotIn("must-not-read", json.dumps(normalized))

    def test_public_workflow_keeps_callback_timeout_terminal_recovery_and_actual_payload(self):
        functions = {name: f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:security-{name}:live" for name in ("pipeline", "blocker", "terminal")}
        before = copy.deepcopy(functions)
        states = build_workflow(functions)["States"]
        self.assertEqual(functions, before)
        self.assertEqual(states["PublishAndWait"]["Resource"], "arn:aws:states:::lambda:invoke.waitForTaskToken")
        self.assertEqual(states["PublishAndWait"]["TimeoutSeconds"], 14400)
        self.assertEqual(states["PublishAndWait"]["Catch"][0], {"ErrorEquals": ["States.Timeout"], "ResultPath": "$.failure", "Next": "RecordTimedOut"})
        self.assertEqual(states["PublishAndWait"]["Catch"][-1]["ErrorEquals"], ["States.ALL"])
        self.assertEqual(states["PublishAndWait"]["Catch"][-1]["Next"], "ApprovalFailed")
        for name in ("AutomaticBlock", "ApprovedBlock"):
            self.assertEqual(states[name]["ResultSelector"], {"result.$": "$.Payload"})
            self.assertEqual(states[name]["Parameters"]["Payload"]["operation_id.$"], "$$.Execution.Id")
        for name in ("RecordAutomaticResult", "RecordApprovedResult"):
            self.assertEqual(states[name]["Parameters"]["Payload"]["response.$"], "$.block.result")
            self.assertEqual(states[name]["Catch"][-1]["Next"], "PublicationFailed")
        self.assertEqual(states["PrepareCase"]["Catch"][-1]["Next"], "PreparationFailed")
        for name in ("PreparationFailed", "ApprovalFailed", "PublicationFailed"):
            self.assertEqual(states[name]["Parameters"]["FunctionName"], functions["terminal"])
            self.assertEqual(states[name]["Parameters"]["Payload"]["execution_arn.$"], "$$.Execution.Id")
            self.assertTrue(states[name]["End"])


if __name__ == "__main__":
    unittest.main()
