import copy
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
from approval import handle, parse_key
from case_pipeline import prepare, wait_approval, approval_ready, finalize, normalize_signal, automatic_policy, journal_response, start_signal
from runtime_fakes import MemoryTable, FakeS3, ClientError
from terminal import terminate, normalize_eventbridge
from workflow_builder import build_workflow, cfn_workflow
from counter_evidence import counter_identity

ACCOUNT, REGION, NOW = "123456789012", "ap-northeast-2", 1791950000
SERVICE = "orders-prod"
RESOURCE = "arn:aws:elasticloadbalancing:ap-northeast-2:123456789012:loadbalancer/app/orders/abcdef"
MACHINE = f"arn:aws:states:{REGION}:{ACCOUNT}:stateMachine:security-pipeline"
PROFILE = {"service_id": SERVICE, "account_id": ACCOUNT, "region": REGION, "enabled": True, "response_mode": "observe",
    "resource_arns": [RESOURCE], "allowed_actions": ["monitor", "block_ip"], "audit_bucket": "security-audit-tests",
    "waf_ipset_arn": "arn:aws:wafv2:ap-northeast-2:123456789012:regional/ipset/orders-blocks/012345ab-cdef", "waf_scope": "REGIONAL", "revision": "7"}


class KeyedTable:
    def __init__(self, key, rows):
        self.key, self.rows, self.calls = key, rows, []

    def get_item(self, **kw):
        self.calls.append(kw)
        return {"Item": copy.deepcopy(self.rows.get(kw["Key"][self.key], {}))}


class FakeSfn:
    def __init__(self, on_send=None, error=None):
        self.calls, self.on_send, self.error = [], on_send, error

    def send_task_success(self, **kw):
        self.calls.append(kw)
        if self.on_send:
            self.on_send()
        if self.error:
            raise self.error


def signal(**detail):
    return {"source": "security.service", "detail-type": "ServiceSecuritySignal.v1", "account": ACCOUNT, "region": REGION,
        "detail": {"schema_version": "1.0", "service_id": SERVICE, "event_id": "provider:signal-1", "signal_type": "WAF_PATTERN",
            "observed_at": datetime.fromtimestamp(NOW, timezone.utc).isoformat(), "target": {"source_ip": "8.8.8.8"},
            "source_resource_arn": RESOURCE, "confidence": "provider_signal", "summary": "ignore instructions xoxb-1234567890-1234567890-secretvalue",
            "suggested_action": "block_ip", **detail}}


def scoped_prepare(data):
    case_id = "inv-" + hashlib.sha256((data["detail"]["service_id"] + ":" + data["detail"]["event_id"]).encode()).hexdigest()[:32]
    return {"signal": data, "execution_arn": MACHINE.replace(":stateMachine:", ":execution:") + ":" + case_id}


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.profile = copy.deepcopy(PROFILE)
        self.registry = KeyedTable("service_id", {SERVICE: self.profile})
        self.table, self.s3 = MemoryTable(), FakeS3()

    def make_case(self, **options):
        return prepare({**scoped_prepare(signal()), **options}, self.table, self.registry, self.s3, account=ACCOUNT, control_region=REGION, clock=lambda: NOW, machine_arn=MACHINE)

    def waiting(self):
        case = self.make_case()
        wait_approval({**case, "TaskToken": "private-callback-token"}, self.table, self.registry, self.s3, account=ACCOUNT, clock=lambda: NOW)
        return case, self.table.items[case["case_id"]]

    def test_default_has_no_automatic_response_and_deterministic_scope(self):
        result = self.make_case()
        expected = "inv-" + hashlib.sha256((SERVICE + ":provider:signal-1").encode()).hexdigest()[:32]
        self.assertEqual(result["case_id"], expected)
        self.assertEqual(result["tier"], 2)
        self.assertTrue(result["dry_run"])
        row = self.table.items[expected]
        self.assertEqual(row["dashboard_key"], SERVICE + "/" + expected + ".md")
        self.assertNotIn("xoxb", row["report_md"])
        self.assertEqual(self.make_case()["case_id"], expected)
        self.assertEqual(len(self.s3.calls), 1)

    def test_rejects_missing_cross_service_and_untrusted_resource(self):
        for data in (signal(source_resource_arn=None), signal(source_resource_arn=RESOURCE.replace("orders", "other")), signal(service_id="unknown-service")):
            with self.assertRaises(ValueError):
                normalize_signal(data, self.registry, account=ACCOUNT, control_region=REGION, now=NOW)
        self.assertFalse(self.table.items)

    def test_auto_requires_validated_policy_proof_and_enforce(self):
        selected, _ = normalize_signal(signal(), self.registry, account=ACCOUNT, control_region=REGION, now=NOW)
        self.profile.update(response_mode="enforce", auto_block_policy={"enabled": True, "signal_types": ["WAF_PATTERN"], "rule_ids": ["rate-rule"], "min_requests": 100, "window_seconds": 300})
        self.assertFalse(automatic_policy(selected, self.profile, now=NOW))
        selected["policy_evidence"] = {"rule_id": "rate-rule", "matched_requests": 101, "threshold": 100, "window_seconds": 300, "policy_revision": "7"}
        self.assertTrue(automatic_policy(selected, self.profile, now=NOW))
        self.profile["auto_block_policy"].update(min_requests=Decimal("100"), window_seconds=Decimal("300"))
        self.assertTrue(automatic_policy(selected, self.profile, now=NOW))
        self.assertFalse(automatic_policy(selected, self.profile, now=NOW + 301))
        self.assertFalse(automatic_policy(selected, self.profile, now=NOW - 1))
        selected["observed_at"] = datetime.fromtimestamp(NOW + 0.5, timezone.utc).isoformat()
        self.assertTrue(automatic_policy(selected, self.profile, now=NOW))
        selected["observed_at"] = datetime.fromtimestamp(NOW + 1.001, timezone.utc).isoformat()
        self.assertFalse(automatic_policy(selected, self.profile, now=NOW))
        selected["observed_at"] = datetime.fromtimestamp(NOW, timezone.utc).isoformat()
        selected["policy_evidence"]["policy_revision"] = "6"
        self.assertFalse(automatic_policy(selected, self.profile, now=NOW))
        selected["policy_evidence"].update(policy_revision="7", matched_requests=True)
        self.assertFalse(automatic_policy(selected, self.profile, now=NOW))

    def test_prepared_automatic_case_retains_only_validated_policy_proof(self):
        self.profile.update(response_mode="enforce", auto_block_policy={"enabled": True, "signal_types": ["WAF_PATTERN"], "rule_ids": ["rate-rule"], "min_requests": 100, "window_seconds": 300})
        proof = {"rule_id": "rate-rule", "matched_requests": 100, "threshold": 100, "window_seconds": 300, "policy_revision": "7", "raw": "TaskToken=do-not-store"}
        stamp = datetime.fromtimestamp(NOW, timezone.utc).isoformat()
        identity = counter_identity(SERVICE, "8.8.8.8", "7", "rate-rule", 300, stamp)
        row = {"lease_id": identity["key"], "phase": "OBSERVATION_COUNT", "service_id": SERVICE, "source_ip": "8.8.8.8", "rule_id": "rate-rule",
            "policy_revision": "7", "window_start": identity["window_start"], "window_seconds": 300, "threshold": 100, "count": 100,
            "verified_latest_observation": stamp, "source_validation_version": "STORED_CLOUDWATCH_V1"}
        result = prepare(scoped_prepare(signal(policy_evidence=proof, event_id=identity["aggregate_event_id"])), self.table, self.registry, self.s3,
            account=ACCOUNT, control_region=REGION, clock=lambda: NOW, leases=KeyedTable("lease_id", {identity["key"]: row}), machine_arn=MACHINE)
        self.assertEqual(result["tier"], 1)
        stored = self.table.items[result["case_id"]]["policy_evidence"]
        self.assertEqual(set(stored), {"rule_id", "matched_requests", "threshold", "window_seconds", "policy_revision"})
        self.assertNotIn("raw", stored)

    def test_wait_token_remains_private_and_approval_commits_before_block(self):
        case, row = self.waiting()
        public = json.dumps(row["dashboard_notification_hitl"])
        self.assertNotIn("TaskToken", public)
        self.assertNotIn("private-callback-token", public)
        during = []
        sfn = FakeSfn(on_send=lambda: during.append(approval_ready(case, self.table, self.registry, account=ACCOUNT, clock=lambda: NOW)))
        response = handle({"key": row["dashboard_key"], "decision": "approve", "user": "admin@example.com", "reason": "reviewed"}, self.table, self.registry, sfn, account=ACCOUNT, clock=lambda: NOW)
        self.assertEqual(during[0], {"ready": False, "keep_waiting": True, "approved_action": "block_ip"})
        self.assertTrue(approval_ready(case, self.table, self.registry, account=ACCOUNT, clock=lambda: NOW)["ready"])
        self.assertEqual(response["callback_status"], "SENT")
        self.assertEqual(response["tier"], 2)
        self.assertEqual(response["decided_by"], "admin@example.com")
        self.assertEqual(response["decision_reason"], "reviewed")
        self.assertEqual(response["approved_action"], "block_ip")
        self.assertFalse(response["pending"])
        self.assertFalse(response["can_retry_reject"])
        self.assertNotIn("task_token", row)
        self.assertNotIn("private-callback-token", json.dumps(response))
        repeated = handle({"key": row["dashboard_key"], "decision": "reject", "user": "second"}, self.table, self.registry, sfn, account=ACCOUNT, clock=lambda: NOW)
        self.assertFalse(repeated["ok"])
        self.assertEqual(row["decided_by"], "admin@example.com")
        self.assertEqual(len(sfn.calls), 1)

    def test_callback_ambiguous_preserves_actor_and_disables_replay(self):
        case, row = self.waiting()
        sfn = FakeSfn(error=TimeoutError("secret must not be copied"))
        request = {"key": row["dashboard_key"], "decision": "approve", "user": "first"}
        response = handle(request, self.table, self.registry, sfn, account=ACCOUNT, clock=lambda: NOW)
        self.assertEqual(response["callback_status"], "UNKNOWN")
        self.assertFalse(response["can_retry"])
        self.assertNotIn("secret", json.dumps(response))
        self.assertFalse(approval_ready(case, self.table, self.registry, account=ACCOUNT, clock=lambda: NOW)["ready"])
        handle({**request, "user": "second"}, self.table, self.registry, sfn, account=ACCOUNT, clock=lambda: NOW)
        self.assertEqual(row["decided_by"], "first")
        self.assertEqual(len(sfn.calls), 1)

    def test_approval_expiration_and_service_key_scope(self):
        case, row = self.waiting()
        result = handle({"operation": "status", "key": row["dashboard_key"]}, self.table, self.registry, FakeSfn(), account=ACCOUNT, clock=lambda: NOW + 14400)
        self.assertFalse(result["can_approve"])
        with self.assertRaises(ValueError):
            parse_key(case["case_id"] + ".md")
        with self.assertRaises(ValueError):
            handle({"key": row["dashboard_key"], "decision": {}, "user": "first"}, self.table, self.registry, FakeSfn(), account=ACCOUNT, clock=lambda: NOW)

    def test_partial_response_has_exact_components_and_no_false_success(self):
        case = self.make_case()
        response = {"schema_version": "1.0", "service_id": SERVICE, "case_id": case["case_id"], "status": "PARTIAL", "required_components": ["waf", "nacl"],
            "components": {"waf": {"status": "APPLIED"}, "nacl": {"status": "FAILED", "error_code": "AccessDenied"}}}
        self.table.items[case["case_id"]].update(dry_run=False, decision="approve", callback_status="SENT", approved_action="block_ip", status="DECIDED_APPROVE")
        response["operation_id"] = case["execution_arn"]
        key = "block#" + hashlib.sha256((SERVICE + ":" + case["case_id"] + ":" + case["execution_arn"]).encode()).hexdigest()
        ops = KeyedTable("lease_id", {key: {"service_id": SERVICE, "case_id": case["case_id"], "result": response}})
        final = finalize({**case, "outcome": "BLOCK_RESULT", "mode": "HOTL", "response": dict(response, status="APPLIED")}, self.table, self.registry, self.s3, account=ACCOUNT, operations=ops, clock=lambda: NOW + 1)
        self.assertEqual(final["recorded"], "BLOCK_PARTIAL")
        row = self.table.items[case["case_id"]]
        self.assertEqual(row["dashboard_notification_outcome"]["detail"]["actual_outcomes"]["waf"]["status"], "APPLIED")

    def test_timeout_recovers_waf_commit_journal_without_reblocking(self):
        case = self.make_case()
        self.table.items[case["case_id"]].update(tier=1, dry_run=False)
        execution = case["execution_arn"]
        key = "block#" + hashlib.sha256((SERVICE + ":" + case["case_id"] + ":" + execution).encode()).hexdigest()
        operations = KeyedTable("lease_id", {key: {"service_id": SERVICE, "case_id": case["case_id"], "components": {"waf": {"status": "APPLIED"}}}})
        self.profile["nacl_enabled"] = True
        final = finalize({**case, "outcome": "AUTO_BLOCK_FAILED", "execution_arn": execution, "failure": {"Error": "States.Timeout", "Cause": "private"}},
            self.table, self.registry, self.s3, account=ACCOUNT, operations=operations, clock=lambda: NOW + 1)
        self.assertEqual(final["recorded"], "AUTO_BLOCK_UNVERIFIED")
        row = self.table.items[case["case_id"]]
        self.assertEqual(row["block_response"]["components"]["waf"]["status"], "APPLIED")
        self.assertNotIn("private", json.dumps(row["dashboard_notification_outcome"]))

    def test_publication_failure_preserves_recoverable_job(self):
        self.s3.fail = True
        case = self.make_case()
        row = self.table.items[case["case_id"]]
        self.assertEqual(case["publication"], "PENDING")
        self.assertEqual(row["publication_state"], "PENDING")
        self.assertNotIn("dashboard_notification_hitl", row)

    def test_pipeline_terminal_missing_case_never_uses_legacy_resources(self):
        machine = "arn:aws:states:ap-northeast-2:123456789012:stateMachine:security-pipeline"
        case = "inv-" + "a" * 32
        event = {"source": "aws.states", "detail-type": "Step Functions Execution Status Change", "account": ACCOUNT, "region": REGION,
            "detail": {"stateMachineArn": machine, "executionArn": machine.replace(":stateMachine:", ":execution:") + ":" + case, "status": "FAILED", "input": "private"}}
        class Metadata:
            def describe_execution(inner, **kwargs):
                self.assertEqual(kwargs["includedData"], "METADATA_ONLY")
                return {"executionArn": event["detail"]["executionArn"], "stateMachineArn": machine, "status": "FAILED"}
        normalized = normalize_eventbridge(event, machines={"PUBLICATION": machine}, account=ACCOUNT, region=REGION, sfn=Metadata())
        result = terminate(normalized, self.table, self.s3, default_service_id="legacy-whs", default_bucket="legacy-bucket", clock=lambda: NOW)
        self.assertEqual(result["reason"], "SCOPED_CASE_NOT_CREATED")
        self.assertFalse(self.s3.calls)
        self.assertFalse(self.table.items)

    def test_forged_proof_without_counter_stays_manual_and_input_false_cannot_disable_dry_run(self):
        self.profile.update(response_mode="enforce", auto_block_policy={"enabled": True, "signal_types": ["WAF_PATTERN"], "rule_ids": ["rate-rule"], "min_requests": 100, "window_seconds": 300})
        proof = {"rule_id": "rate-rule", "matched_requests": 100, "threshold": 100, "window_seconds": 300, "policy_revision": "7"}
        identity = counter_identity(SERVICE, "8.8.8.8", "7", "rate-rule", 300, datetime.fromtimestamp(NOW, timezone.utc).isoformat())
        result = prepare({**scoped_prepare(signal(policy_evidence=proof, event_id=identity["aggregate_event_id"])), "dry_run": False}, self.table, self.registry, self.s3,
            account=ACCOUNT, control_region=REGION, clock=lambda: NOW, leases=KeyedTable("lease_id", {}), machine_arn=MACHINE)
        self.assertEqual(result["tier"], 2); self.assertTrue(result["dry_run"])
        self.assertNotIn("policy_evidence", self.table.items[result["case_id"]])
    def test_final_outcomes_require_execution_private_decisions_and_authoritative_journal(self):
        case = self.make_case()
        for kind in ("REJECTED", "NO_ACTION", "AUTO_DRY_RUN", "AUTO_BLOCK_RESULT", "TIMED_OUT", "APPROVAL_FAILED"):
            with self.assertRaises(ValueError):
                finalize({**case, "outcome": kind}, self.table, self.registry, self.s3, account=ACCOUNT, clock=lambda: NOW)
        with self.assertRaisesRegex(ValueError, "WORKFLOW_EXECUTION"):
            finalize({**case, "outcome": "NO_ACTION", "execution_arn": case["execution_arn"] + "different"}, self.table, self.registry, self.s3, account=ACCOUNT)
        self.table.items[case["case_id"]].update(dry_run=False, decision="approve", callback_status="SENT", approved_action="block_ip", status="DECIDED_APPROVE")
        forged = {"schema_version": "1.0", "service_id": SERVICE, "case_id": case["case_id"], "status": "APPLIED", "required_components": ["waf"], "components": {"waf": {"status": "APPLIED"}}}
        result = finalize({**case, "outcome": "BLOCK_RESULT", "response": forged}, self.table, self.registry, self.s3, account=ACCOUNT, operations=KeyedTable("lease_id", {}))
        self.assertEqual(result["recorded"], "BLOCK_UNVERIFIED")
    def test_finalize_retry_preserves_body_publication_revision_and_outbox_bytes(self):
        case, row = self.waiting()
        handle({"key": row["dashboard_key"], "decision": "reject", "user": "first"}, self.table, self.registry, FakeSfn(), account=ACCOUNT, clock=lambda: NOW)
        event = {**case, "outcome": "REJECTED"}
        finalize(event, self.table, self.registry, self.s3, account=ACCOUNT, clock=lambda: NOW)
        before = copy.deepcopy(row)
        calls = len(self.s3.calls)
        finalize(event, self.table, self.registry, self.s3, account=ACCOUNT, clock=lambda: NOW + 1)
        for field in ("report_md", "publication_revision", "record_revision", "dashboard_notification_outcome"):
            self.assertEqual(row[field], before[field])
        self.assertEqual(row["report_md"].count("## 처리 결과"), 1)
        self.assertEqual(len(self.s3.calls), calls)
    def test_terminal_rejects_forged_status_and_cross_execution_without_private_mutation(self):
        case = self.make_case()
        event = {"source": "aws.states", "detail-type": "Step Functions Execution Status Change", "account": ACCOUNT, "region": REGION,
            "detail": {"stateMachineArn": MACHINE, "executionArn": case["execution_arn"], "status": "FAILED"}}
        class Metadata:
            def describe_execution(inner, **kwargs): return {"executionArn": case["execution_arn"], "stateMachineArn": MACHINE, "status": "RUNNING"}
        with self.assertRaisesRegex(ValueError, "STATUS_NOT_VERIFIED"):
            normalize_eventbridge(event, machines={"PUBLICATION": MACHINE}, account=ACCOUNT, region=REGION, sfn=Metadata())
        with self.assertRaisesRegex(ValueError, "WORKFLOW_EXECUTION"):
            terminate({**case, "stage": "PUBLICATION", "execution_arn": case["execution_arn"] + "x"}, self.table, self.s3, registry=self.registry, account=ACCOUNT, machine_arn=MACHINE)
        self.assertEqual(self.table.items[case["case_id"]]["status"], "TRIAGED")

    def test_workflow_is_case_bound_and_waits_for_callback_commit(self):
        aliases = {key: "arn:aws:lambda:ap-northeast-2:123456789012:function:" + key + ":live" for key in ("pipeline", "blocker", "terminal")}
        workflow = build_workflow(aliases)
        states = workflow["States"]
        self.assertEqual(states["PublishAndWait"]["TimeoutSeconds"], 14400)
        self.assertEqual(states["AutomaticBlock"]["Parameters"]["Payload"]["operation_id.$"], "$$.Execution.Id")
        self.assertTrue(states["ApprovedBlock"]["Parameters"]["Payload"]["human_approved"])
        self.assertEqual(states["Decision"]["Choices"][1]["Next"], "VerifyApprovalCommit")
        for key, state in states.items():
            if "Next" in state:
                self.assertIn(state["Next"], states)
            for catch in state.get("Catch", []):
                self.assertIn(catch["Next"], states)
        with self.assertRaises(ValueError):
            build_workflow({**aliases, "pipeline": "stub"})
        self.assertEqual(cfn_workflow()["States"]["PrepareCase"]["Parameters"]["Payload"]["dry_run.$"], "$.dry_run")

    def test_starter_projects_stable_input_and_checks_duplicate_bytes(self):
        machine = "arn:aws:states:ap-northeast-2:123456789012:stateMachine:security-pipeline"
        class Starter:
            def start_execution(inner, **kw):
                inner.call = kw
                if getattr(inner, "duplicate", False):
                    raise ClientError("ExecutionAlreadyExists")
                return {"executionArn": machine.replace(":stateMachine:", ":execution:") + ":" + kw["name"]}
            def describe_execution(inner, **kw):
                return {"stateMachineArn": machine, "input": inner.previous}
        sfn = Starter()
        event = signal(raw_event={"TaskToken": "do-not-copy"})
        result = start_signal(event, self.registry, sfn, machine_arn=machine, account=ACCOUNT, control_region=REGION, clock=lambda: NOW)
        self.assertEqual(sfn.call["name"], result["case_id"])
        self.assertNotIn("TaskToken", sfn.call["input"])
        self.assertTrue(json.loads(sfn.call["input"])["dry_run"])
        sfn.previous, sfn.duplicate = sfn.call["input"], True
        self.assertEqual(start_signal(event, self.registry, sfn, machine_arn=machine, account=ACCOUNT, control_region=REGION, clock=lambda: NOW)["state"], "DUPLICATE")
        self.profile["response_mode"] = "enforce"
        with self.assertRaisesRegex(ValueError, "IDENTITY_CONFLICT"):
            start_signal(event, self.registry, sfn, machine_arn=machine, account=ACCOUNT, control_region=REGION, default_dry_run=False, clock=lambda: NOW)


if __name__ == "__main__":
    unittest.main()
