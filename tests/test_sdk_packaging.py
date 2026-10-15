import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sdk_packaging_tests", ROOT / "sdk_packaging.py")
sdk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sdk)


def shape(**members):
    return SimpleNamespace(members=members)


def models():
    item = shape(Field=shape(FieldType=SimpleNamespace(enum=["SINGLE_HEADER", "BODY", "QUERY_STRING"]), FieldKeys=shape()),
        Action=SimpleNamespace(enum=["SUBSTITUTION"]), ExcludeRuleMatchDetails=shape(), ExcludeRateBasedDetails=shape())
    protection = shape(DataProtections=SimpleNamespace(member=item))
    operations = {
        ("cloudfront", "ListDistributionTenantsByCustomization"): SimpleNamespace(
            input_shape=shape(WebACLArn=shape(), MaxItems=shape(), Marker=shape()),
            output_shape=shape(DistributionTenantList=shape(), NextMarker=shape())),
        ("wafv2", "ListResourcesForWebACL"): SimpleNamespace(input_shape=shape(ResourceType=SimpleNamespace(enum=list(sdk.REQUIRED_RESOURCE_TYPES)))),
        ("wafv2", "CreateWebACL"): SimpleNamespace(input_shape=shape(DataProtectionConfig=protection)),
        ("wafv2", "UpdateWebACL"): SimpleNamespace(input_shape=shape(DataProtectionConfig=protection)),
        ("bedrock-runtime", "Converse"): SimpleNamespace(),
    }
    session = SimpleNamespace(get_service_model=lambda name: SimpleNamespace(operation_model=lambda operation: operations[(name, operation)]))
    return session, operations


class RuntimeSdkBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.wheels = self.root / "wheels"
        self.wheels.mkdir()
        self.paths, self.locked = {}, {}
        for package, namespace in sdk.PACKAGES.items():
            version = sdk.VALIDATED_SDK.get(package, "1.0.0")
            filename = package.replace("-", "_") + "-" + version + "-py3-none-any.whl"
            path = self.wheels / filename
            files = {namespace if namespace.endswith(".py") else namespace + "/__init__.py": b"value = 1\n",
                package.replace("-", "_") + "-" + version + ".dist-info/METADATA": ("Name: " + package + "\nVersion: " + version + "\n").encode()}
            self.write_wheel(path, files)
            self.paths[package] = path
            self.locked[package] = {"version": version, "sha256": sdk.sha(path.read_bytes())}
        self.write_lock()

    def tearDown(self):
        self.temporary.cleanup()

    def write_wheel(self, path, files):
        with zipfile.ZipFile(path, "w") as wheel:
            for name, body in sorted(files.items()):
                wheel.writestr(name, body)

    def write_lock(self):
        (self.root / sdk.LOCK_NAME).write_text("\n".join(name + "==" + item["version"] + " --hash=sha256:" + item["sha256"]
            for name, item in sorted(self.locked.items())) + "\n")

    def manifest(self, entries, wheel_metadata):
        session, _ = models()
        return {"validation": "passed", "lock_file": sdk.LOCK_NAME, "lock_sha256": sdk.sha((self.root / sdk.LOCK_NAME).read_bytes()),
            "versions": {name: item["version"] for name, item in self.locked.items()}, "wheels": wheel_metadata,
            "files": {name: sdk.sha(body) for name, body in entries.items()}, "capabilities": sdk.verify_capabilities(session)}

    def archive(self, entries):
        path = self.root / "runtime.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("runtime/__init__.py", "")
            for name, body in sorted(entries.items()):
                archive.writestr(name, body)
        return path

    def test_complete_lock_rejects_unpinned_missing_duplicate_and_wrong_sdk_versions(self):
        self.assertEqual(sdk.read_lock(self.root / sdk.LOCK_NAME), self.locked)
        original = (self.root / sdk.LOCK_NAME).read_text()
        for body in [original.replace("boto3==1.43.106", "boto3>=1.43.106"), "\n".join(original.splitlines()[1:]),
                     original + original.splitlines()[0] + "\n", original.replace("botocore==1.43.113", "botocore==1.43.1")]:
            (self.root / sdk.LOCK_NAME).write_text(body)
            with self.assertRaises(ValueError):
                sdk.read_lock(self.root / sdk.LOCK_NAME)

    def test_locked_wheel_bytes_have_no_host_package_dependency(self):
        entries, metadata = sdk.wheel_entries(self.wheels, self.locked)
        self.assertEqual(set(metadata), set(sdk.PACKAGES))
        self.assertIn("boto3/__init__.py", entries)
        self.assertIn("botocore/__init__.py", entries)
        self.assertIn("six.py", entries)
        self.assertEqual(entries["six.py"], b"value = 1\n")

    def test_tampered_and_missing_wheels_are_rejected(self):
        self.paths["boto3"].write_bytes(self.paths["boto3"].read_bytes() + b"altered")
        with self.assertRaisesRegex(ValueError, "HASH_OR_VERSION_MISMATCH"):
            sdk.wheel_entries(self.wheels, self.locked)
        self.paths["boto3"].unlink()
        with self.assertRaisesRegex(ValueError, "INCOMPLETE_RUNTIME_SDK_WHEELS"):
            sdk.wheel_entries(self.wheels, self.locked)

    def test_traversal_native_libraries_and_foreign_package_files_are_rejected(self):
        path = self.paths["boto3"]
        for added in ["../private.env", "boto3/native.so", "foreign/__init__.py"]:
            files = {"boto3/__init__.py": b"", "boto3-1.43.106.dist-info/METADATA": b"Name: boto3\nVersion: 1.43.106\n", added: b"unexpected"}
            self.write_wheel(path, files)
            self.locked["boto3"]["sha256"] = sdk.sha(path.read_bytes())
            with self.assertRaises(ValueError):
                sdk.wheel_entries(self.wheels, self.locked)

    def test_sdk_models_require_tenant_inventory_and_all_waf_resource_types(self):
        session, operations = models()
        self.assertTrue(sdk.verify_capabilities(session)["cloudfront_tenants"])
        operations[("cloudfront", "ListDistributionTenantsByCustomization")].output_shape.members.pop("NextMarker")
        with self.assertRaisesRegex(ValueError, "CLOUDFRONT_TENANTS"):
            sdk.verify_capabilities(session)
        session, operations = models()
        operations[("wafv2", "ListResourcesForWebACL")].input_shape.members["ResourceType"].enum.remove("AGENTCORE_GATEWAY")
        with self.assertRaisesRegex(ValueError, "WAF_RESOURCE_TYPES"):
            sdk.verify_capabilities(session)

    def test_sdk_models_require_create_and_update_data_protection(self):
        session, operations = models()
        operations[("wafv2", "UpdateWebACL")].input_shape.members.pop("DataProtectionConfig")
        with self.assertRaisesRegex(ValueError, "WAF_DATA_PROTECTION"):
            sdk.verify_capabilities(session)

    def test_manifest_validates_lock_and_every_packaged_dependency_file(self):
        entries, wheels = sdk.wheel_entries(self.wheels, self.locked)
        metadata = self.manifest(entries, wheels)
        sdk.verify_manifest(self.root, self.archive(entries), metadata)
        changed = {**entries, "boto3/__init__.py": b"tampered"}
        with self.assertRaisesRegex(ValueError, "DEPENDENCY_FILE_HASH_MISMATCH"):
            sdk.verify_manifest(self.root, self.archive(changed), metadata)
        with self.assertRaisesRegex(ValueError, "PACKAGE_INVENTORY_MISMATCH"):
            sdk.verify_manifest(self.root, self.archive({**entries, "botocore/injected.py": b""}), metadata)
        wrong = copy.deepcopy(metadata)
        wrong["lock_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "LOCK_MANIFEST_MISMATCH"):
            sdk.verify_manifest(self.root, self.archive(entries), wrong)
        wrong = copy.deepcopy(metadata)
        wrong["wheels"]["botocore"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "WHEEL_MANIFEST_MISMATCH"):
            sdk.verify_manifest(self.root, self.archive(entries), wrong)

    def test_missing_dependency_or_capability_attestation_is_rejected(self):
        entries, wheels = sdk.wheel_entries(self.wheels, self.locked)
        metadata = self.manifest(entries, wheels)
        wrong = copy.deepcopy(metadata)
        wrong["capabilities"]["cloudfront_tenants"] = False
        with self.assertRaisesRegex(ValueError, "CAPABILITY_VALIDATION_REQUIRED"):
            sdk.verify_manifest(self.root, self.archive(entries), wrong)
        with self.assertRaisesRegex(ValueError, "PACKAGE_INVENTORY_MISMATCH"):
            sdk.verify_manifest(self.root, self.archive({name: body for name, body in entries.items() if name != "six.py"}), metadata)


if __name__ == "__main__":
    unittest.main()
