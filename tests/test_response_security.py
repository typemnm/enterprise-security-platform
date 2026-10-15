import copy
import importlib
from pathlib import Path
import sys
import unittest
import time
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
from runtime import blocker, discovery, expected_activity
from runtime.counter_evidence import counter_identity

ACCOUNT = "123456789012"
IPSET = f"arn:aws:wafv2:us-east-1:{ACCOUNT}:global/ipset/security-shop-ipv4/0000-1111"
RESOURCE = f"arn:aws:cloudfront::{ACCOUNT}:distribution/DIST123"
FUNCTION = f"arn:aws:lambda:ap-northeast-2:{ACCOUNT}:function:security-notifier"
SECRET = f"arn:aws:secretsmanager:ap-northeast-2:{ACCOUNT}:secret:slack-token-AbCdEf"


class Error(Exception):
    def __init__(self, name): self.response = {"Error": {"Code": name}}


class Table:
    def __init__(self, key, values=()): self.key = key; self.items = {item[key]: copy.deepcopy(item) for item in values}
    def get_item(self, Key, **kwargs): return {"Item": copy.deepcopy(self.items.get(Key[self.key], {}))}
    def put_item(self, Item, **kwargs):
        key = Item[self.key]
        if "attribute_not_exists" in kwargs.get("ConditionExpression", "") and key in self.items:
            raise Error("ConditionalCheckFailedException")
        self.items[key] = copy.deepcopy(Item)
    def update_item(self, Key, ExpressionAttributeValues, **kwargs):
        item = self.items[Key[self.key]]
        if item.get("owner") != ExpressionAttributeValues[":owner"]: raise Error("ConditionalCheckFailedException")
        if ":result" in ExpressionAttributeValues:
            item.update(result=copy.deepcopy(ExpressionAttributeValues[":result"]), phase="COMPLETED")
        else:
            item.update(components=copy.deepcopy(ExpressionAttributeValues[":components"]), phase=ExpressionAttributeValues[":phase"])
    def delete_item(self, Key, ExpressionAttributeValues, **kwargs):
        key = Key[self.key]
        if self.items[key]["owner"] != ExpressionAttributeValues[":owner"]: raise Error("ConditionalCheckFailedException")
        del self.items[key]


class WAF:
    def __init__(self): self.addresses = ["1.1.1.1/32"]; self.updated = []; self.conflicts = 0
    def get_ip_set(self, **kwargs):
        return {"IPSet": {"ARN": IPSET, "IPAddressVersion": "IPV4", "Addresses": self.addresses[:], "Description": "operator description"}, "LockToken": "fresh"}
    def update_ip_set(self, **kwargs):
        if self.conflicts:
            self.conflicts -= 1; self.addresses.append("9.9.9.9/32"); raise Error("WAFOptimisticLockException")
        self.updated.append(kwargs); self.addresses = kwargs["Addresses"][:]


def service(**changes):
    value = {"service_id": "shop-api", "account_id": ACCOUNT, "region": "ap-northeast-2", "enabled": True,
             "response_mode": "enforce", "allowed_actions": ["block_ip", "monitor"], "waf_ipset_arn": IPSET,
             "waf_scope": "CLOUDFRONT", "resource_arns": [RESOURCE], "revision": "r1",
             "auto_block_policy": {"enabled": True, "signal_types": ["WAF_PATTERN"], "rule_ids": ["UnitRule"], "window_seconds": 300, "min_requests": 2}}
    return dict(value, **changes)


class ResponseTests(unittest.TestCase):
    def setUp(self):
        self.registry = Table("service_id", [service()]); self.cases = Table("case_id", [{"case_id": "inv-unit",
            "service_id": "shop-api", "tier": 1, "recommended_action": "block_ip", "target": {"source_ip": "8.8.8.8"},
            "registry_revision": "r1", "signal_type": "WAF_PATTERN", "observed_at": datetime.now(timezone.utc).isoformat(),
            "policy_evidence": {"rule_id": "UnitRule", "matched_requests": 2, "threshold": 2, "window_seconds": 300, "policy_revision": "r1"}}])
        self.operations = Table("lease_id"); self.leases = Table("lease_id"); self.waf = WAF()
        case = self.cases.items["inv-unit"]
        case["dry_run"] = False
        identity = counter_identity("shop-api", "8.8.8.8", "r1", "UnitRule", 300, case["observed_at"])
        case["source_event_id"] = identity["aggregate_event_id"]
        self.leases.items[identity["key"]] = {"lease_id": identity["key"], "phase": "OBSERVATION_COUNT",
            "source_validation_version": "STORED_CLOUDWATCH_V1",
            "service_id": "shop-api", "source_ip": "8.8.8.8", "rule_id": "UnitRule", "policy_revision": "r1",
            "window_start": identity["window_start"], "window_seconds": 300, "threshold": 2, "count": 2,
            "verified_latest_observation": case["observed_at"]}
        execution = f"arn:aws:states:ap-northeast-2:{ACCOUNT}:execution:company-pipeline:inv-unit"
        case["workflow_execution_arn"] = execution
        self.event = {"service_id": "shop-api", "case_id": "inv-unit", "attacker_ip": "8.8.8.8", "dry_run": False, "operation_id": execution}
    def run_response(self, event=None, default_dry_run=False):
        return blocker.run(event or self.event, registry=self.registry, cases=self.cases, operations=self.operations,
            leases=self.leases, waf_factory=lambda region: self.waf, ec2_factory=lambda region: object(), account=ACCOUNT, default_dry_run=default_dry_run)
    def test_preserves_other_ip_and_description(self):
        result = self.run_response(); self.assertEqual(result["status"], "APPLIED")
        self.assertEqual(self.waf.addresses, ["1.1.1.1/32", "8.8.8.8/32"])
        self.assertEqual(self.waf.updated[0]["Description"], "operator description")
    def test_conflict_refresh_preserves_concurrent_writer(self):
        self.waf.conflicts = 1; self.run_response(); self.assertIn("9.9.9.9/32", self.waf.addresses)
    def test_retry_never_reblocks_after_rollback(self):
        first = self.run_response(); self.waf.addresses.remove("8.8.8.8/32")
        self.assertEqual(self.run_response(), first); self.assertNotIn("8.8.8.8/32", self.waf.addresses)
    def test_default_dry_run(self):
        event = dict(self.event); event.pop("dry_run"); self.assertEqual(self.run_response(event)["status"], "DRY_RUN"); self.assertFalse(self.waf.updated)
    def test_observe_mode_ignores_enforce_request(self):
        self.registry.items["shop-api"]["response_mode"] = "observe"
        self.assertEqual(self.run_response()["status"], "DRY_RUN"); self.assertFalse(self.waf.updated)
    def test_case_and_client_ip_mismatch_denied(self):
        with self.assertRaisesRegex(ValueError, "CASE_TARGET_MISMATCH"): self.run_response(dict(self.event, attacker_ip="4.4.4.4"))
    def test_unknown_service_denied(self):
        with self.assertRaisesRegex(ValueError, "SERVICE_NOT_REGISTERED"): self.run_response(dict(self.event, service_id="other-api"))
    def test_private_ip_denied(self):
        with self.assertRaisesRegex(ValueError, "NON_PUBLIC"): self.run_response(dict(self.event, attacker_ip="10.0.0.1"))
    def test_ambiguous_prior_operation_holds(self):
        self.run_response(); key = next(iter(self.operations.items)); self.operations.items[key].pop("result")
        self.waf.addresses.remove("8.8.8.8/32"); result = self.run_response()
        self.assertEqual(result["status"], "SKIPPED"); self.assertNotIn("8.8.8.8/32", self.waf.addresses)
    def test_nacl_failure_preserves_truthful_waf_success(self):
        self.registry.items["shop-api"].update(nacl_enabled=True, nacl_id="acl-123", nacl_slots=[1], vpc_id="vpc-123")
        result = self.run_response(); self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["components"]["waf"]["status"], "APPLIED"); self.assertEqual(result["components"]["nacl"]["status"], "FAILED")
    def test_lost_waf_ack_verified_by_current_address(self):
        original = self.waf.update_ip_set
        def uncertain(**kwargs): original(**kwargs); raise TimeoutError()
        self.waf.update_ip_set = uncertain
        self.assertEqual(self.run_response()["status"], "APPLIED")
    def test_lost_waf_ack_without_proof_is_unknown(self):
        def uncertain(**kwargs): raise TimeoutError()
        self.waf.update_ip_set = uncertain
        result = self.run_response()
        self.assertEqual(result["status"], "UNVERIFIED")
        self.assertEqual(result["components"]["waf"]["status"], "UNKNOWN")
    def test_current_binding_failure_prevents_any_write(self):
        def changed(service): raise ValueError("RESPONSE_SHARED_WEBACL_DENIED")
        with self.assertRaisesRegex(ValueError, "SHARED_WEBACL"):
            blocker.run(self.event, registry=self.registry, cases=self.cases, operations=self.operations, leases=self.leases,
                waf_factory=lambda region: self.waf, ec2_factory=lambda region: object(), account=ACCOUNT, binding_validator=changed, default_dry_run=False)
        self.assertFalse(self.waf.updated); self.assertFalse(self.operations.items)
    def test_ipv6_protected_cidr_cannot_be_blocked(self):
        self.registry.items["shop-api"].update(waf_ipv6_ipset_arn=IPSET.replace("ipv4", "ipv6"), protected_cidrs=["2001:4860::/32"])
        self.cases.items["inv-unit"]["target"]["source_ip"] = "2001:4860:4860::8888"
        with self.assertRaisesRegex(ValueError, "PROTECTED_IP_DENIED"):
            self.run_response(dict(self.event, attacker_ip="2001:4860:4860::8888"))
    def test_policy_revision_change_prevents_stale_automatic_action(self):
        self.registry.items["shop-api"]["revision"] = "r2"
        with self.assertRaisesRegex(ValueError, "POLICY_REVISION_CHANGED"): self.run_response()
        self.assertFalse(self.waf.updated)
    def test_removed_threshold_policy_prevents_stale_tier_one(self):
        self.registry.items["shop-api"]["auto_block_policy"]["enabled"] = False
        with self.assertRaisesRegex(ValueError, "EVIDENCE_EXPIRED_OR_CHANGED"): self.run_response()
        self.assertFalse(self.waf.updated)
    def test_input_proof_without_authoritative_observations_never_writes(self):
        self.leases.items.clear()
        with self.assertRaisesRegex(ValueError, "COUNTER_JOURNAL_MISMATCH"):
            self.run_response()
        self.assertFalse(self.waf.updated); self.assertFalse(self.operations.items)
    def test_new_operation_cannot_reblock_same_case_after_rollback(self):
        self.run_response(); self.waf.addresses.remove("8.8.8.8/32")
        count = len(self.waf.updated)
        with self.assertRaisesRegex(ValueError, "WORKFLOW_EXECUTION_MISMATCH"):
            self.run_response(dict(self.event, operation_id="another-operation"))
        self.assertEqual(len(self.waf.updated), count); self.assertNotIn("8.8.8.8/32", self.waf.addresses)
    def test_stored_or_global_dry_run_cannot_be_overridden_by_input_false(self):
        self.cases.items["inv-unit"]["dry_run"] = True
        self.assertEqual(self.run_response()["status"], "DRY_RUN")
        self.assertEqual(self.waf.updated, []); self.assertEqual(self.operations.items, {})
        self.cases.items["inv-unit"]["dry_run"] = False
        self.assertEqual(self.run_response(default_dry_run=True)["status"], "DRY_RUN")
        self.assertEqual(self.waf.updated, []); self.assertEqual(self.operations.items, {})
        self.cases.items["inv-unit"].pop("dry_run")
        self.assertEqual(self.run_response()["status"], "DRY_RUN")
        self.cases.items["inv-unit"]["dry_run"] = "false"
        with self.assertRaisesRegex(ValueError, "DRY_RUN_MUST_BE_BOOLEAN"): self.run_response()
        self.assertEqual(self.waf.updated, [])
    def test_changed_count_ip_rule_and_aggregate_identity_never_write(self):
        for field, value in (("count", 1), ("source_ip", "4.4.4.4"), ("rule_id", "AnotherRule"),
                             ("verified_latest_observation", "2020-01-01T00:00:00Z")):
            self.setUp()
            next(iter(self.leases.items.values()))[field] = value
            with self.assertRaises(ValueError): self.run_response()
            self.assertFalse(self.waf.updated); self.assertFalse(self.operations.items)
        self.setUp(); self.cases.items["inv-unit"]["source_event_id"] = "forged-new-case"
        with self.assertRaisesRegex(ValueError, "AGGREGATE_IDENTITY_MISMATCH"): self.run_response()
        self.assertFalse(self.waf.updated)


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.table = Table("activity_id")
        self.event = {"account": ACCOUNT, "region": "ap-northeast-2", "source": "aws.secretsmanager", "detail-type": "AWS API Call via CloudTrail",
            "detail": {"eventName": "GetSecretValue", "eventSource": "secretsmanager.amazonaws.com", "awsRegion": "ap-northeast-2", "recipientAccountId": ACCOUNT,
                "requestID": "aws-request-1234", "requestParameters": {"secretId": SECRET},
                "userIdentity": {"type": "AssumedRole", "accountId": ACCOUNT, "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/NotifierRole/security-notifier"}}}
    def check(self): return expected_activity.expected(self.event, self.table, account=ACCOUNT, region="ap-northeast-2", allowed_functions=[FUNCTION], allowed_resources=[SECRET], now=1000)
    def attest(self): expected_activity.record(self.table, account=ACCOUNT, region="ap-northeast-2", request_id="aws-request-1234", function_arn=FUNCTION, execution_id="lambda-request-123", resource_arn=SECRET, observed_at=900)
    def test_role_or_public_ip_alone_never_proves_normal(self): self.assertFalse(self.check())
    def test_exact_receipt_recognized(self): self.attest(); self.assertTrue(self.check())
    def test_failed_call_never_suppressed(self): self.attest(); self.event["detail"]["errorCode"] = "AccessDenied"; self.assertFalse(self.check())
    def test_different_secret_and_request_id_rejected(self):
        self.attest(); self.event["detail"]["requestID"] = "different-request"; self.assertFalse(self.check())
    def test_contradictory_lambda_origin_rejected(self):
        self.attest(); self.event["detail"]["userIdentity"]["inScopeOf"] = {"issuerType": "AWS::Lambda::Function", "credentialsIssuedTo": FUNCTION + "evil"}; self.assertFalse(self.check())
    def test_receipt_has_no_credential_value(self):
        self.attest(); self.assertNotIn("SecretString", next(iter(self.table.items.values())))


class DiscoveryTests(unittest.TestCase):
    def test_unknown_asset_stable_identity(self):
        item = {"arn": RESOURCE, "type": "CLOUDFRONT", "public": True, "tags": {}}
        self.assertEqual(discovery.service_identity(item), discovery.service_identity(item))
        self.assertFalse(discovery.selected(item, "tagged")); self.assertTrue(discovery.selected(item, "all-supported"))
    def test_opt_out_applies_to_all_supported(self):
        self.assertFalse(discovery.selected({"type": "ALB", "public": True, "tags": {"security:managed": "false"}}, "all-supported"))
    def test_existing_rules_priority_action_and_order_preserved(self):
        old = [{"Name": "company-rule", "Priority": 100, "Action": {"Block": {}}, "Statement": {"ByteMatchStatement": {"SearchString": "preserve"}}}]
        desired = discovery.managed_rules("shop-api", IPSET, IPSET.replace("ipv4", "ipv6"))
        merged = discovery.merge_rules(old, desired); self.assertEqual(merged[0], old[0]); self.assertEqual(merged[1]["Priority"], 101)
        self.assertEqual(discovery.merge_rules(merged, desired), merged)
    def test_managed_rule_operator_change_is_never_overwritten(self):
        desired = discovery.managed_rules("shop-api", IPSET, IPSET.replace("ipv4", "ipv6"))
        old = discovery.merge_rules([], desired); old[0]["Action"] = {"Count": {}}
        with self.assertRaisesRegex(ValueError, "REVIEW_REQUIRED"): discovery.merge_rules(old, desired)


if __name__ == "__main__": unittest.main()
