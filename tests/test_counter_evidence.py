"""Automatic actions require exact provider counter journal evidence."""
from datetime import datetime, timezone
from decimal import Decimal
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
from runtime.counter_evidence import counter_identity, verify_counter_evidence
from runtime import ingest

NOW = 1800000000
STAMP = datetime.fromtimestamp(NOW, timezone.utc).isoformat().replace("+00:00", "Z")


class Table:
    def __init__(self, row): self.row, self.reads = row, []
    def get_item(self, **kwargs): self.reads.append(kwargs); return {"Item": copy.deepcopy(self.row)}


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.service = {"service_id": "company-api", "revision": "r1", "response_mode": "enforce",
            "auto_block_policy": {"enabled": True, "signal_types": ["WAF_PATTERN"], "rule_ids": ["Rule1"], "window_seconds": 300, "min_requests": 100}}
        self.signal = {"service_id": "company-api", "target": {"source_ip": "8.8.8.8"}, "observed_at": STAMP,
            "signal_type": "WAF_PATTERN", "provider_rule_ids": ["Rule1"],
            "policy_evidence": {"rule_id": "Rule1", "window_seconds": 300, "threshold": 100, "matched_requests": 100, "policy_revision": "r1"}}
        self.identity = counter_identity("company-api", "8.8.8.8", "r1", "Rule1", 300, STAMP)
        self.signal["event_id"] = self.identity["aggregate_event_id"]
        self.row = {"lease_id": self.identity["key"], "phase": "OBSERVATION_COUNT", "service_id": "company-api", "source_ip": "8.8.8.8",
                    "source_validation_version": "STORED_CLOUDWATCH_V1",
                    "rule_id": "Rule1", "policy_revision": "r1", "window_start": self.identity["window_start"], "window_seconds": 300,
                    "threshold": 100, "count": Decimal(100), "verified_latest_observation": STAMP}
    def verify(self): return verify_counter_evidence(self.signal, self.service, Table(self.row), now=NOW)
    def test_existing_counter_key_aggregate_compatibility(self):
        counter = ingest.policy_counter(self.signal, self.service, NOW)
        self.assertEqual(counter["key"], self.identity["key"])
        self.assertEqual(ingest.aggregate_event_id(counter), self.identity["aggregate_event_id"])
    def test_strong_read_valid_decimal_journal(self):
        table = Table(self.row)
        self.assertTrue(verify_counter_evidence(self.signal, self.service, table, now=NOW))
        self.assertEqual(table.reads, [{"Key": {"lease_id": self.identity["key"]}, "ConsistentRead": True}])
    def test_missing_or_insufficient_journal_fails_closed(self):
        for row in ({}, dict(self.row, count=99), dict(self.row, count=True), dict(self.row, count=Decimal("100.1"))):
            self.row = row
            with self.assertRaises(ValueError): self.verify()
    def test_every_journal_scope_and_metadata_field_is_bound(self):
        for field, value in (("phase", "PENDING"), ("service_id", "other-api"), ("source_ip", "1.1.1.1"),
                             ("rule_id", "Rule2"), ("policy_revision", "r2"), ("window_start", 0),
                             ("window_seconds", 60), ("threshold", 2), ("lease_id", "threshold#forged")):
            self.setUp(); self.row[field] = value
            with self.assertRaises(ValueError): self.verify()
    def test_legacy_unverified_count_cannot_be_upgraded_by_one_verified_request(self):
        self.row.pop("source_validation_version")
        self.row["count"] = 100  # old unverified 99 plus an otherwise fresh request
        with self.assertRaisesRegex(ValueError, "COUNTER_JOURNAL_MISMATCH"): self.verify()
    def test_future_old_observation_and_new_fabricated_event_id_denied(self):
        for stamp in ("2020-01-01T00:00:00Z", "2030-01-01T00:00:00Z", "not-time"):
            self.setUp(); self.row["verified_latest_observation"] = stamp
            with self.assertRaises(ValueError): self.verify()
        self.setUp(); self.signal["event_id"] = "new-forged-event"
        with self.assertRaises(ValueError): self.verify()
    def test_ipv6_canonical_identity_and_journal(self):
        self.signal["target"]["source_ip"] = "2001:4860:4860:0:0:0:0:8888"
        identity = counter_identity("company-api", self.signal["target"]["source_ip"], "r1", "Rule1", 300, STAMP)
        self.signal["event_id"] = identity["aggregate_event_id"]
        self.row.update(lease_id=identity["key"], source_ip="2001:4860:4860::8888")
        self.assertTrue(self.verify())


if __name__ == "__main__": unittest.main()
