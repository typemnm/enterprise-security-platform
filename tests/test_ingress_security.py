"""Provider source binding and crash recovery across event publication."""
import copy
from decimal import Decimal
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
from runtime import ingest, ops, discovery, service_scope
from test_response_security import ACCOUNT, RESOURCE, service, Table, Error

NOW = 1800000000
ACL = f"arn:aws:wafv2:us-east-1:{ACCOUNT}:global/webacl/shop/1111"


class Journal:
    name = "LeaseTable"
    def __init__(self): self.items = {}; self.reads = 0
    def get_item(self, Key, **kwargs):
        self.reads += 1
        return {"Item": copy.deepcopy(self.items.get(Key["lease_id"], {}))}
    def update_item(self, Key, UpdateExpression, ExpressionAttributeValues, **kwargs):
        item = self.items[Key["lease_id"]]
        if "publication" in UpdateExpression:
            if "publication" in item: raise Error("ConditionalCheckFailedException")
            item["publication"] = ExpressionAttributeValues[":p"]
        elif "verified_latest_observation" in UpdateExpression:
            values = ExpressionAttributeValues
            if item.get("verified_latest_observation", "") >= values[":latest"]: raise Error("ConditionalCheckFailedException")
            item.setdefault("source_ip", values[":ip"])
            item["verified_latest_observation"] = values[":latest"]
        else: item["phase"] = ExpressionAttributeValues[":done"]


class Transactions:
    shapes = None
    def __init__(self, journal):
        from botocore.session import Session
        if Transactions.shapes is None:
            model = Session().get_service_model("dynamodb")
            Transactions.shapes = {name: model.operation_model(name).input_shape for name in ("TransactWriteItems", "BatchGetItem")}
        self.shape = Transactions.shapes["TransactWriteItems"]
        self.journal = journal; self.calls = 0; self.attempts = 0; self.batches = 0
        self.max_transaction_items = 0; self.before_commit = None; self.timeout_after_commit = False
    def transact_write_items(self, TransactItems):
        self.attempts += 1
        from boto3.dynamodb.types import TypeDeserializer
        from botocore.validate import validate_parameters
        # Verify the actual SDK request shape, not a document-API approximation.
        validate_parameters({"TransactItems": TransactItems}, self.shape)
        self.max_transaction_items = max(self.max_transaction_items, len(TransactItems))
        if self.before_commit:
            callback, self.before_commit = self.before_commit, None
            callback(TransactItems)
        decoder = TypeDeserializer()
        decode = lambda fields: {key: decoder.deserialize(value) for key, value in fields.items()}
        reasons = []
        for row in TransactItems:
            failed = False
            if "Put" in row:
                failed = decode(row["Put"]["Item"])["lease_id"] in self.journal.items
            else:
                update = row["Update"]
                values = decode(update["ExpressionAttributeValues"])
                key = decode(update["Key"])["lease_id"]
                if ":limit" in values: failed = self.journal.items.get(key, {}).get("count", 0) >= values[":limit"]
                if ":validation" in values and key in self.journal.items:
                    failed = self.journal.items[key].get("source_validation_version") != values[":validation"]
            reasons.append({"Code": "ConditionalCheckFailed" if failed else "None"})
        if any(row["Code"] != "None" for row in reasons):
            error = Error("TransactionCanceledException")
            error.response["CancellationReasons"] = reasons
            raise error
        self.calls += 1
        for row in TransactItems:
            if "Put" in row:
                new = decode(row["Put"]["Item"])
                self.journal.items[new["lease_id"]] = new
            else:
                update = row["Update"]
                key = decode(update["Key"])["lease_id"]
                values = decode(update["ExpressionAttributeValues"])
                item = self.journal.items.setdefault(key, {"lease_id": key, "count": Decimal(0)})
                item["count"] += values.get(":delta", values.get(":one", 0))
                if ":phase" in values: item["phase"] = values[":phase"]
                for field, alias in (("expires_at", ":ttl"), ("service_id", ":service"), ("rule_id", ":rule"),
                                     ("policy_revision", ":revision"), ("window_start", ":start"), ("window_seconds", ":window"), ("threshold", ":threshold"), ("source_ip", ":ip"), ("source_validation_version", ":validation")):
                    if alias in values: item[field] = values[alias]
                if ":latest" in values: item.setdefault("verified_latest_observation", values[":latest"])
        if self.timeout_after_commit:
            self.timeout_after_commit = False
            raise TimeoutError()
    def batch_get_item(self, RequestItems):
        self.batches += 1
        from boto3.dynamodb.types import TypeSerializer
        from botocore.validate import validate_parameters
        validate_parameters({"RequestItems": RequestItems}, Transactions.shapes["BatchGetItem"])
        serializer = TypeSerializer()
        rows = []
        aliases = RequestItems[self.journal.name].get("ExpressionAttributeNames", {})
        fields = [aliases.get(name, name) for name in RequestItems[self.journal.name]["ProjectionExpression"].replace(" ", "").split(",")]
        for key in RequestItems[self.journal.name]["Keys"]:
            value = self.journal.items.get(key["lease_id"]["S"])
            if value: rows.append({field: serializer.serialize(value[field]) for field in fields if field in value})
        return {"Responses": {self.journal.name: rows}}


class Events:
    def __init__(self): self.entries = []; self.fail = False
    def put_events(self, Entries):
        self.entries.extend(Entries)
        return {"FailedEntryCount": 1 if self.fail else 0}


class StoredLogs:
    shape = None
    def __init__(self, payload):
        self.payload, self.calls = copy.deepcopy(payload), []
    def filter_log_events(self, **kwargs):
        from botocore.session import Session
        from botocore.validate import validate_parameters
        if StoredLogs.shape is None: StoredLogs.shape = Session().get_service_model("logs").operation_model("FilterLogEvents").input_shape
        validate_parameters(kwargs, StoredLogs.shape)
        self.calls.append(kwargs)
        if kwargs["logGroupName"] != self.payload["logGroup"] or kwargs["logStreamNames"] != [self.payload["logStream"]]: return {"events": []}
        return {"events": [{"eventId": row["id"], "timestamp": row["timestamp"], "message": row["message"], "logStreamName": self.payload["logStream"]}
            for row in self.payload["logEvents"] if kwargs["startTime"] <= row["timestamp"] < kwargs["endTime"]]}


def record(request="req-one"):
    return {"webaclId": ACL, "httpSourceId": "DIST123", "httpSourceName": "CF", "timestamp": NOW * 1000,
            "action": "COUNT", "nonTerminatingMatchingRules": [{"ruleId": "SQLi_BODY"}],
            "httpRequest": {"requestId": request, "clientIp": "8.8.8.8", "headers": [{"name": "authorization", "value": "do-not-copy"}], "args": "secret=do-not-copy"}}


class IngressTests(unittest.TestCase):
    def setUp(self):
        self.service = service(resource_type="CLOUDFRONT", web_acl_arn=ACL, revision="r1")
        self.journal = Journal(); self.ddb = Transactions(self.journal); self.events = Events()
    def emit(self, value=None, limit=30):
        signal = ingest.waf_signal(value or record(), self.service)
        return ingest.emit(signal, self.service, leases=self.journal, ddb=self.ddb, events=self.events, bus="bus", max_cases=limit, now=NOW)
    def policy(self, threshold=100):
        self.service["auto_block_policy"] = {"enabled": True, "signal_types": ["WAF_PATTERN"], "rule_ids": ["SQLi_BODY"], "window_seconds": Decimal(300), "min_requests": Decimal(threshold)}
    def accept(self, records, limit=30):
        class Registry(Table):
            def query(inner, **kwargs): return {"Items": [{"service_id": "shop-api"}]}
        self.service.update(log_group_name="aws-waf-logs-security-shop-api", log_region="us-east-1")
        payload = {"owner": ACCOUNT, "logGroup": self.service["log_group_name"], "logStream": "fixture-stored-stream", "messageType": "DATA_MESSAGE",
                   "logEvents": [{"id": "cw-event-" + str(index), "timestamp": row["timestamp"], "message": json.dumps(row)} for index, row in enumerate(records)]}
        return ingest.accept_waf(payload, registry=Registry("service_id", [self.service]), leases=self.journal, ddb=self.ddb,
            events=self.events, logs=StoredLogs(payload), account=ACCOUNT, bus="bus", source_region="us-east-1", max_cases=limit, clock=lambda: NOW)
    def counters(self):
        return [row for key, row in self.journal.items.items() if key.startswith("threshold#")]
    def test_wrong_distribution_cannot_create_case(self):
        row = record(); row["httpSourceId"] = "ANOTHER_DIST"
        self.assertIsNone(ingest.waf_signal(row, self.service))
    def test_documented_alb_id_is_bound_to_exact_registered_arn(self):
        arn = f"arn:aws:elasticloadbalancing:ap-northeast-2:{ACCOUNT}:loadbalancer/app/company/abcd1234"
        row = dict(record(), httpSourceName="ALB", httpSourceId="abcd1234")
        alb = dict(self.service, resource_type="ALB", resource_arns=[arn])
        self.assertIsNotNone(ingest.waf_signal(row, alb))
        self.assertIsNone(ingest.waf_signal(dict(row, httpSourceId="another-id"), alb))
        self.assertIsNone(ingest.waf_signal(dict(row, httpSourceName="CF"), alb))
    def test_raw_request_content_never_forwarded(self):
        self.emit(); self.assertNotIn("do-not-copy", self.events.entries[0]["Detail"])
        self.assertNotIn("headers", self.events.entries[0]["Detail"])
    def test_duplicate_provider_event_counts_and_emits_once(self):
        self.assertEqual(self.emit(), "EMITTED_NOW"); self.assertEqual(self.emit(), "EMITTED")
        self.assertEqual(self.ddb.calls, 1); self.assertEqual(len(self.events.entries), 1)
    def test_bus_failure_retry_preserves_budget_and_payload(self):
        self.events.fail = True
        with self.assertRaisesRegex(RuntimeError, "SIGNAL_PUBLICATION_FAILED"): self.emit()
        self.events.fail = False; self.emit()
        self.assertEqual(self.ddb.calls, 1)
        self.assertEqual(self.events.entries[0]["Detail"], self.events.entries[1]["Detail"])
    def test_reservation_commit_timeout_preserves_canonical_bytes_and_emits_once(self):
        self.ddb.timeout_after_commit = True
        self.assertEqual(self.emit(), "EMITTED_NOW")
        self.assertEqual(self.emit(), "EMITTED")
        self.assertEqual(len(self.events.entries), 1)
        reservation = next(row for key, row in self.journal.items.items() if key.startswith("signal#"))
        self.assertEqual(reservation["publication"], self.events.entries[0]["Detail"])
    def test_legacy_pending_decimal_proof_without_publication_replays_exact_integer_json(self):
        signal = ingest.waf_signal(record(), self.service)
        signal["policy_evidence"] = {"matched_requests": Decimal(100), "window_seconds": Decimal(300), "threshold": Decimal(100), "rule_id": "SQLi_BODY", "policy_revision": "r1"}
        key = "signal#shop-api#" + signal["event_id"]
        self.journal.items[key] = {"lease_id": key, "phase": "PENDING", "signal": signal, "service_id": "shop-api"}
        self.assertEqual(ingest.emit(signal, self.service, leases=self.journal, ddb=self.ddb, events=self.events, bus="bus", max_cases=30, now=NOW), "EMITTED_NOW")
        self.assertEqual(ingest.emit(signal, self.service, leases=self.journal, ddb=self.ddb, events=self.events, bus="bus", max_cases=30, now=NOW), "EMITTED")
        self.assertEqual(len(self.events.entries), 1)
        self.assertEqual(json.loads(self.events.entries[0]["Detail"])["policy_evidence"]["matched_requests"], 100)
        self.assertEqual(self.journal.items[key]["publication"], self.events.entries[0]["Detail"])
        with self.assertRaisesRegex(TypeError, "EXACT_INTEGER"):
            ingest.canonical_signal({"invalid": Decimal("1.5")})
    def test_limit_does_not_reserve_false_success(self):
        self.emit(limit=1); self.assertEqual(self.emit(record("req-two"), limit=1), "LIMITED")
        self.assertEqual(len(self.events.entries), 1)
    def test_explicit_policy_counts_unique_requests(self):
        self.policy(2)
        self.assertEqual(self.emit(), "OBSERVED"); self.assertEqual(self.emit(), "OBSERVED")
        self.assertEqual(self.emit(record("req-two")), "EMITTED_NOW")
        self.assertEqual(len(self.events.entries), 1)
        event = json.loads(self.events.entries[0]["Detail"])
        self.assertEqual(event["policy_evidence"]["matched_requests"], 2)
        self.assertEqual(event["suggested_action"], "block_ip")
        self.assertEqual(self.counters()[0]["count"], 2)
    def test_100_unique_requests_cross_threshold_without_spending_30_case_slots(self):
        self.policy()
        self.assertEqual(self.accept([record("request-" + str(i)) for i in range(99)]), {"accepted": 0, "budget_limited": 0})
        self.assertFalse(any(key.startswith("case-budget#") for key in self.journal.items))
        self.assertEqual(self.accept([record("request-99")]), {"accepted": 1, "budget_limited": 0})
        self.assertEqual(self.accept([record("request-" + str(i)) for i in range(100)]), {"accepted": 0, "budget_limited": 0})
        self.assertEqual(self.counters()[0]["count"], 100)
        self.assertEqual(len(self.events.entries), 1)
        self.assertEqual(next(row["count"] for key, row in self.journal.items.items() if key.startswith("case-budget#")), 1)
        from runtime.case_pipeline import automatic_policy
        event = json.loads(self.events.entries[0]["Detail"])
        self.assertTrue(automatic_policy(event, self.service, now=NOW))
    def test_overlapping_batches_count_only_unique_observations(self):
        self.policy()
        self.accept([record("request-" + str(i)) for i in range(75)])
        self.accept([record("request-" + str(i)) for i in range(25, 100)])
        self.assertEqual(self.counters()[0]["count"], 100)
        self.assertEqual(len(self.events.entries), 1)
    def test_each_matching_policy_rule_has_its_own_scoped_aggregate(self):
        self.policy(2)
        self.service["auto_block_policy"]["rule_ids"].append("XSS_BODY")
        values = [dict(record(str(index)), nonTerminatingMatchingRules=[{"ruleId": "SQLi_BODY"}, {"ruleId": "XSS_BODY"}]) for index in range(2)]
        self.assertEqual(self.accept(values)["accepted"], 2)
        self.assertEqual({row["rule_id"] for row in self.counters()}, {"SQLi_BODY", "XSS_BODY"})
        self.assertEqual({row["count"] for row in self.counters()}, {2})
        self.assertEqual(len({json.loads(row["Detail"])["event_id"] for row in self.events.entries}), 2)
    def test_overlapping_concurrent_claim_writer_retries_without_double_count(self):
        self.policy()
        def competing_writer(writes):
            competitor = Transactions(self.journal)
            update = copy.deepcopy(writes[-1])
            update["Update"]["ExpressionAttributeValues"][":delta"] = {"N": "20"}
            competitor.transact_write_items(copy.deepcopy(writes[:20]) + [update])
        self.ddb.before_commit = competing_writer
        self.accept([record("request-" + str(i)) for i in range(100)])
        self.assertEqual(self.counters()[0]["count"], 100)
        self.assertEqual(len(self.events.entries), 1)
        self.assertEqual(self.ddb.attempts, 4)
    def test_observation_commit_timeout_recovers_without_counter_inflation(self):
        self.policy(2); self.ddb.timeout_after_commit = True
        self.accept([record("one"), record("two")])
        self.assertEqual(self.counters()[0]["count"], 2)
        self.assertEqual(len(self.events.entries), 1)
    def test_aggregate_bus_retry_keeps_first_json_even_after_more_observations(self):
        self.policy(2); self.events.fail = True
        with self.assertRaisesRegex(RuntimeError, "SIGNAL_PUBLICATION_FAILED"):
            self.accept([record("one"), record("two")])
        self.events.fail = False
        self.accept([record("one"), record("two"), record("three")])
        self.assertEqual(self.counters()[0]["count"], 3)
        self.assertEqual(self.events.entries[0]["Detail"], self.events.entries[1]["Detail"])
        self.assertEqual(json.loads(self.events.entries[-1]["Detail"])["policy_evidence"]["matched_requests"], 2)
        self.assertEqual(next(row["count"] for key, row in self.journal.items.items() if key.startswith("case-budget#")), 1)
    def test_10k_policy_burst_uses_bounded_batches_instead_of_per_request_calls(self):
        self.policy(10000)
        result = self.accept([record("request-" + str(i)) for i in range(10000)])
        self.assertEqual(result, {"accepted": 1, "budget_limited": 0})
        self.assertEqual(self.counters()[0]["count"], 10000)
        self.assertEqual(self.ddb.max_transaction_items, 100)
        self.assertEqual(self.ddb.attempts, 103)
        self.assertEqual(self.ddb.batches, 306)
        self.assertLess(self.journal.reads, 10)
    def test_many_ip_policy_burst_also_packs_counter_updates(self):
        self.policy(2)
        values = [dict(record("request-" + str(i)), httpRequest={"requestId": "request-" + str(i), "clientIp": "8.8." + str(i // 256) + "." + str(i % 256)}) for i in range(1000)]
        result = self.accept(values)
        self.assertEqual(result["accepted"], 0)
        self.assertEqual(len(self.counters()), 1000)
        self.assertEqual(self.ddb.attempts, 20)
        self.assertEqual(self.ddb.batches, 60)
        self.assertEqual(self.journal.reads, 0)
    def test_hour_budget_uses_processing_time_for_delayed_provider_records(self):
        first, second = record("old-one"), record("old-two")
        first["timestamp"], second["timestamp"] = (NOW - 3600) * 1000, (NOW - 7200) * 1000
        self.assertEqual(self.accept([first, second], limit=1), {"accepted": 1, "budget_limited": 1})
        self.assertEqual([key for key in self.journal.items if key.startswith("case-budget#")], ["case-budget#shop-api#" + str(NOW // 3600)])
    def test_large_rule_fanout_publishes_at_100_before_later_timeout_and_retry_deduplicates(self):
        self.policy(100)
        rules = ["rule-" + str(index).zfill(3) for index in range(100)]
        self.service["auto_block_policy"]["rule_ids"] = rules
        values = [dict(record("request-" + str(index)), nonTerminatingMatchingRules=[{"ruleId": rule} for rule in rules]) for index in range(1200)]
        raw = json.dumps({"owner": ACCOUNT, "logGroup": "aws-waf-logs-security-shop-api", "messageType": "DATA_MESSAGE",
            "logEvents": [{"message": json.dumps(row, separators=(",", ":"))} for row in values]}, separators=(",", ":")).encode()
        self.assertLess(len(raw), ingest.MAX_BYTES)
        original_write = self.ddb.transact_write_items
        calls_at_first_post = []
        original_event = self.events.put_events
        def event_at_boundary(Entries):
            calls_at_first_post.append((self.ddb.attempts, self.ddb.batches))
            self.assertEqual(json.loads(Entries[0]["Detail"])["policy_evidence"]["matched_requests"], 100)
            return original_event(Entries)
        self.events.put_events = event_at_boundary
        def timeout_after_first_publication(**kwargs):
            if self.events.entries: raise TimeoutError()
            return original_write(**kwargs)
        self.ddb.transact_write_items = timeout_after_first_publication
        with self.assertRaisesRegex(RuntimeError, "OBSERVATION_CLAIM_RETRY_EXHAUSTED"):
            self.accept(values)
        self.assertEqual(len(self.events.entries), 1)
        self.assertEqual(calls_at_first_post, [(3, 6)])
        original = self.events.entries[0]["Detail"]
        original_event_id = json.loads(original)["event_id"]
        original_counter = next(row for row in self.counters() if row["count"] == 100)
        self.assertEqual(self.journal.items["signal#shop-api#" + original_event_id]["phase"], "EMITTED")
        self.ddb.transact_write_items = original_write
        self.events.put_events = original_event
        result = self.accept(values)
        self.assertEqual(result, {"accepted": 29, "budget_limited": 70})
        self.assertEqual(len(self.counters()), 100)
        self.assertEqual({row["count"] for row in self.counters()}, {1200})
        self.assertEqual(len(self.events.entries), 30)
        self.assertEqual(sum(json.loads(row["Detail"])["event_id"] == original_event_id for row in self.events.entries), 1)
        self.assertEqual(self.journal.items["signal#shop-api#" + original_event_id]["publication"], original)
        self.assertEqual(self.journal.items[original_counter["lease_id"]]["count"], 1200)
    def test_policy_matching_stale_or_future_logs_never_add_automatic_proof(self):
        self.policy(2)
        for offset in (-301, 1):
            values = [dict(record(str(offset) + ":" + str(index)), timestamp=(NOW + offset) * 1000) for index in range(2)]
            self.assertEqual(self.accept(values)["accepted"], 0)
        self.assertFalse(self.counters()); self.assertFalse(self.events.entries)
    def test_existing_manual_pending_replays_unchanged_after_policy_enabled_and_budget_full(self):
        self.events.fail = True
        with self.assertRaises(RuntimeError): self.emit(limit=1)
        original = self.events.entries[0]["Detail"]
        self.policy(2); self.events.fail = False
        self.assertEqual(self.accept([record()], limit=1), {"accepted": 1, "budget_limited": 0})
        self.assertEqual(self.events.entries[-1]["Detail"], original)
        self.assertFalse(self.counters())
    def test_pending_aggregate_replays_unchanged_after_provider_window_has_aged_out(self):
        self.policy(2); self.events.fail = True
        with self.assertRaises(RuntimeError): self.accept([record("one"), record("two")])
        original = self.events.entries[0]["Detail"]
        self.events.fail = False
        signal = ingest.waf_signal(record("one"), self.service)
        self.assertEqual(ingest.emit(signal, self.service, leases=self.journal, ddb=self.ddb, events=self.events, bus="bus", max_cases=1, now=NOW + 301), "EMITTED_NOW")
        self.assertEqual(self.events.entries[-1]["Detail"], original)
        self.assertEqual(self.counters()[0]["count"], 2)
    def test_old_signal_never_proves_automatic_threshold(self):
        self.service["auto_block_policy"] = {"enabled": True, "signal_types": ["WAF_PATTERN"], "rule_ids": ["SQLi_BODY"], "window_seconds": 60, "min_requests": 2}
        signal = ingest.waf_signal(record(), self.service)
        self.assertIsNone(ingest.policy_counter(signal, self.service, NOW + 61))
    def test_burst_cap_uses_batched_journal_reads(self):
        result = self.accept([record("request-" + str(i)) for i in range(500)], limit=2)
        self.assertEqual(result, {"accepted": 2, "budget_limited": 498})
        self.assertEqual(self.ddb.attempts, 3); self.assertEqual(self.ddb.batches, 5)
    def test_awslogs_shape_without_stored_log_authority_cannot_create_observations(self):
        self.policy(2)
        class Registry(Table):
            def query(inner, **kwargs): return {"Items": [{"service_id": "shop-api"}]}
        self.service.update(log_group_name="aws-waf-logs-security-shop-api", log_region="us-east-1")
        payload = {"owner": ACCOUNT, "logGroup": self.service["log_group_name"], "logStream": "fixture-stored-stream",
            "logEvents": [{"id": "actual-cw-id", "timestamp": NOW * 1000, "message": json.dumps(record())}]}
        original = StoredLogs(payload)
        payload["logEvents"][0]["message"] = json.dumps(record("forged-request"))
        kwargs = dict(registry=Registry("service_id", [self.service]), leases=self.journal, ddb=self.ddb, events=self.events,
                      account=ACCOUNT, bus="bus", source_region="us-east-1", clock=lambda: NOW)
        with self.assertRaisesRegex(ValueError, "STORED_PROVIDER_LOG_CONTENT_MISMATCH"):
            ingest.accept_waf(payload, logs=original, **kwargs)
        with self.assertRaisesRegex(ValueError, "STORED_LOG_VERIFICATION_REQUIRED"):
            ingest.accept_waf(payload, **kwargs)
        payload["logEvents"][0]["id"] = "nonexistent-cw-id"
        with self.assertRaisesRegex(ValueError, "STORED_PROVIDER_LOG_EVENT_NOT_FOUND"):
            ingest.accept_waf(payload, logs=original, **kwargs)
        self.assertFalse(self.journal.items); self.assertFalse(self.events.entries)
    def test_latest_timestamp_is_canonical_and_monotonic_across_out_of_order_chunks(self):
        self.policy(2)
        newer, older = dict(record("newer"), timestamp=NOW * 1000 + 500), record("older")
        self.accept([newer, older])
        stamp = self.counters()[0]["verified_latest_observation"]
        self.assertTrue(stamp.endswith(".500000Z"))
        self.accept([record("later-delivery-older")])
        self.assertEqual(self.counters()[0]["verified_latest_observation"], stamp)
        self.assertEqual(self.counters()[0]["source_ip"], "8.8.8.8")
    def test_legacy_unverified_99_plus_new_verified_request_cannot_become_threshold_100(self):
        self.policy(100)
        counter = ingest.policy_counter(ingest.waf_signal(record(), self.service), self.service, NOW)
        self.journal.items[counter["key"]] = {"lease_id": counter["key"], "count": 99, "phase": "OBSERVATION_COUNT", "service_id": "shop-api"}
        with self.assertRaisesRegex(ValueError, "LEGACY_OBSERVATION_COUNTER_REVIEW_REQUIRED"):
            self.accept([record("new-verified")])
        self.assertEqual(self.journal.items[counter["key"]]["count"], 99)
        self.assertFalse(self.events.entries)
    def test_same_account_wrong_log_group_never_creates_case(self):
        class Registry(Table):
            def query(inner, **kwargs): return {"Items": [{"service_id": "shop-api"}]}
        self.service.update(log_group_name="aws-waf-logs-security-shop-api", log_region="us-east-1")
        payload = {"owner": ACCOUNT, "logGroup": "aws-waf-logs-other", "logEvents": [{"message": json.dumps(record())}]}
        result = ingest.accept_waf(payload, registry=Registry("service_id", [self.service]), leases=self.journal, ddb=self.ddb,
            events=self.events, account=ACCOUNT, bus="bus", source_region="us-east-1", clock=lambda: NOW)
        self.assertEqual(result["accepted"], 0); self.assertFalse(self.events.entries)


class ProviderSDKShapeTests(unittest.TestCase):
    def test_webacl_data_protection_api_shape(self):
        from botocore.session import Session
        from botocore.validate import validate_parameters
        request = {"Name": "security-validation", "Scope": "REGIONAL", "DefaultAction": {"Allow": {}}, "Rules": [],
            "DataProtectionConfig": discovery.data_protection(), "VisibilityConfig": {"SampledRequestsEnabled": False,
            "CloudWatchMetricsEnabled": True, "MetricName": "security-validation"}}
        validate_parameters(request, Session().get_service_model("wafv2").operation_model("CreateWebACL").input_shape)
    def test_cloudfront_tenant_sharing_is_included(self):
        class CloudFront:
            def list_distributions_by_web_acl_id(inner, **kwargs): return {"DistributionList": {"Items": [{"ARN": RESOURCE}], "IsTruncated": False}}
            def list_distribution_tenants_by_customization(inner, **kwargs):
                from botocore.session import Session
                from botocore.validate import validate_parameters
                validate_parameters(kwargs, Session().get_service_model("cloudfront").operation_model("ListDistributionTenantsByCustomization").input_shape)
                return {"DistributionTenantList": [{"Arn": "arn:aws:cloudfront::" + ACCOUNT + ":distribution-tenant/TENANT"}]}
        api = object.__new__(discovery.AWS); api.client = lambda *args: CloudFront()
        self.assertEqual(len(api.acl_resources({"type": "CLOUDFRONT"}, ACL)), 2)


class ResponseSDKTests(unittest.TestCase):
    def test_dynamodb_number_accepted_but_bool_fraction_string_denied(self):
        case = {"case_id": "inv-unit", "service_id": "shop-api", "target": {"source_ip": "8.8.8.8"}, "tier": Decimal(1), "recommended_action": "block_ip"}
        self.assertTrue(service_scope.validate_case(case, service(), "8.8.8.8", "inv-unit"))
        for invalid in (True, Decimal("1.5"), "1"):
            with self.assertRaises(ValueError): service_scope.validate_case(dict(case, tier=invalid), service(), "8.8.8.8", "inv-unit")


class OnboardingBoundaryTests(unittest.TestCase):
    class API:
        def __init__(self, shared=False, bad_logging=False): self.shared=shared; self.bad_logging=bad_logging; self.mutations=[]
        def validate_ingress(self, *args): pass
        def current_acl(self, resource): return {"WebACL": {"ARN": ACL, "Rules": []}}
        def acl_resources(self, *args): return {RESOURCE, "other-service"} if self.shared else {RESOURCE}
        def logging_plan(self, *args):
            if self.bad_logging: raise ValueError("EXISTING_LOG_SINK_ADAPTER_REQUIRED")
        def ensure_ipset(self, *args): self.mutations.append("ipset"); raise AssertionError("mutation should not happen")
    def attempt(self, api):
        return discovery.reconcile({"arn": RESOURCE, "type": "CLOUDFRONT", "region": "us-east-1", "public": True, "tags": {}}, api,
            registry=Table("service_id"), leases=Table("lease_id"), scope="all-supported", account=ACCOUNT, audit_bucket="audit")
    def test_shared_acl_rejected_before_any_waf_mutation(self):
        api = self.API(shared=True)
        with self.assertRaisesRegex(ValueError, "SHARED_WEBACL_REVIEW_REQUIRED"): self.attempt(api)
        self.assertFalse(api.mutations)
    def test_unsupported_original_sink_rejected_before_mutation(self):
        api = self.API(bad_logging=True)
        with self.assertRaisesRegex(ValueError, "EXISTING_LOG_SINK_ADAPTER_REQUIRED"): self.attempt(api)
        self.assertFalse(api.mutations)


class OpsTests(unittest.TestCase):
    class Receipt:
        def __init__(self): self.items={}; self.raise_after_commit=False
        def get_item(self, Key, **kwargs): return {"Item": copy.deepcopy(self.items.get(Key["notification_id"], {}))}
        def put_item(self, Item, **kwargs): self.items[Item["notification_id"]] = copy.deepcopy(Item)
        def update_item(self, Key, ExpressionAttributeValues, **kwargs):
            item=self.items[Key["notification_id"]]
            if item.get("owner") != ExpressionAttributeValues[":owner"]: raise Error("ConditionalCheckFailedException")
            item["status"]=ExpressionAttributeValues.get(":sent", "UNKNOWN"); item.pop("owner")
            if ":ts" in ExpressionAttributeValues: item["ts"]=ExpressionAttributeValues[":ts"]
            if self.raise_after_commit: raise TimeoutError()
    class Slack:
        def __init__(self): self.posts=0
        def call(self, method, payload): self.posts+=1; return {"ts":"123.123"}
    def test_ambiguous_ack_observes_committed_success(self):
        table=self.Receipt(); slack=self.Slack(); table.raise_after_commit=True
        self.assertEqual(ops.deliver("test", "safe", table=table, slack=slack, channel="C123"), "POSTED")
        self.assertEqual(ops.deliver("test", "safe", table=table, slack=slack, channel="C123"), "DUPLICATE")
        self.assertEqual(slack.posts, 1)


if __name__ == "__main__": unittest.main()
