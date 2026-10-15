"""Offline regression for exact CFN/DescribeRule/metric-name binding."""
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("operations_validation_tests", ROOT / "validate_operations.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RuleIdentityTests(unittest.TestCase):
    def setUp(self):
        self.name, self.bus = "owned-install-ingress-ops", "owned-install-security"
        self.region, self.account = "ap-northeast-2", "123456789012"
        self.metadata = {"Name": self.name, "EventBusName": self.bus, "State": "ENABLED",
            "Arn": f"arn:aws:events:{self.region}:{self.account}:rule/{self.bus}/{self.name}"}
        self.calls = []

    def describe(self, *args):
        self.calls.append(args)
        return self.metadata

    def check(self, physical):
        return module.verified_rule_name(physical, self.name, self.bus, self.region, self.account, self.describe)

    def test_custom_bus_physical_id_resolves_to_actual_rule_metric_name(self):
        name, arn = self.check(self.bus + "|" + self.name)
        self.assertEqual(name, self.name)
        self.assertEqual(arn, self.metadata["Arn"])
        self.assertEqual(self.calls, [(self.name, self.bus, self.region)])

    def test_default_bus_and_direct_name_use_exact_verified_metadata(self):
        self.bus = "default"
        self.metadata.update(EventBusName=self.bus, Arn=f"arn:aws:events:{self.region}:{self.account}:rule/{self.name}")
        self.assertEqual(self.check(self.name)[0], self.name)

    def test_foreign_physical_id_stops_before_describe(self):
        for physical in ["foreign|" + self.name, self.bus + "|foreign-rule", self.metadata["Arn"], "*"]:
            with self.subTest(physical=physical), self.assertRaisesRegex(ValueError, "PHYSICAL_ID_SCOPE"):
                self.check(physical)
        self.assertEqual(self.calls, [])

    def test_describe_name_bus_region_account_state_must_match(self):
        original = dict(self.metadata)
        for patch in [{"Name": "different"}, {"EventBusName": "foreign"}, {"State": "DISABLED"},
                      {"Arn": original["Arn"].replace(self.account, "999999999999")},
                      {"Arn": original["Arn"].replace(self.region, "us-east-1")}]:
            self.metadata = {**original, **patch}
            with self.subTest(patch=patch), self.assertRaisesRegex(ValueError, "METADATA_SCOPE"):
                self.check(self.bus + "|" + self.name)


if __name__ == "__main__":
    unittest.main()
