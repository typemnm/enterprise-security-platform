"""Offline Terraform release integrity and private-input boundary regressions."""
import hashlib
import importlib.util
from pathlib import Path
import re
import shutil
import tempfile
import unittest

import pack_release

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("terraform_release_build", ROOT / "build_release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class TerraformPackagingTests(unittest.TestCase):
    def temporary(self):
        workspace = ROOT / "build/terraform-packaging-tests"
        workspace.mkdir(parents=True, exist_ok=True)
        return tempfile.TemporaryDirectory(dir=workspace)

    def fixture(self, directory):
        root = Path(directory)
        (root / "tools").mkdir()
        shutil.copyfile(ROOT / "tools/publication_check.py", root / "tools/publication_check.py")
        (root / "terraform/modules/foundation").mkdir(parents=True)
        (root / "terraform/main.tf").write_text('terraform {}\n', encoding="utf-8")
        (root / "terraform/.terraform.lock.hcl").write_text('# reviewed checksums\n', encoding="utf-8")
        (root / "terraform/modules/foundation/main.tf.json").write_text('{}\n', encoding="utf-8")
        return root

    def sources(self, root):
        return {path.relative_to(root).as_posix(): path for path in release.terraform_inventory(root)}

    def manifest(self, files):
        return {"source_files": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in files.items()}}

    def test_nested_native_modules_and_lock_are_in_the_source_hash_inventory(self):
        with self.temporary() as directory:
            root = self.fixture(directory)
            files = self.sources(root)
            self.assertEqual(set(files), {"terraform/main.tf", "terraform/.terraform.lock.hcl", "terraform/modules/foundation/main.tf.json"})
            pack_release.verify_terraform_sources(files, self.manifest(files))

    def test_every_published_provider_lock_pins_reviewed_cross_platform_aws_checksums(self):
        locks = {path for path in release.terraform_inventory(ROOT) if path.name == ".terraform.lock.hcl"}
        expected = {ROOT / "terraform/.terraform.lock.hcl", ROOT / "terraform/bootstrap-state/.terraform.lock.hcl",
                    *(ROOT / "terraform/modules" / name / ".terraform.lock.hcl" for name in ("foundation", "ingress", "governance"))}
        self.assertTrue(expected.issubset(locks), "Every independently initialized module needs a committed lock")
        pattern = r'provider\s+"registry\.terraform\.io/hashicorp/aws"\s*\{(.*?)^\}'
        root_text = (ROOT / "terraform/.terraform.lock.hcl").read_text(encoding="utf-8")
        root_block = re.search(pattern, root_text, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(root_block)
        reviewed = set(re.findall(r'"zh:([a-f0-9]{64})"', root_block[1]))
        self.assertGreater(len(reviewed), 1, "The reviewed root lock must contain official cross-platform archive hashes")
        reviewed_h1 = set(re.findall(r'"h1:([A-Za-z0-9+/]{43}=)"', root_block[1]))
        self.assertGreaterEqual(len(reviewed_h1), 2, "The reviewed lock must include unpacked Windows and Linux provider hashes")
        for path in sorted(locks):
            with self.subTest(lock=path.relative_to(ROOT).as_posix()):
                text = path.read_text(encoding="utf-8")
                self.assertEqual(re.findall(r'^provider\s+"([^"]+)"', text, re.MULTILINE), ["registry.terraform.io/hashicorp/aws"])
                block = re.search(pattern, text, re.MULTILINE | re.DOTALL)
                self.assertIsNotNone(block)
                self.assertRegex(block[1], r'\bversion\s*=\s*"6\.69\.0"')
                self.assertEqual(set(re.findall(r'"zh:([a-f0-9]{64})"', block[1])), reviewed,
                                 "Windows-only h1 locks cannot support Linux readonly initialization")
                self.assertEqual(set(re.findall(r'"h1:([A-Za-z0-9+/]{43}=)"', block[1])), reviewed_h1,
                                 "Every published lock must retain the reviewed unpacked cross-platform hashes")

    def test_changed_module_and_provider_lock_are_rejected_by_bundle_verification(self):
        for name in ["terraform/modules/foundation/main.tf.json", "terraform/.terraform.lock.hcl"]:
            with self.subTest(name=name), self.temporary() as directory:
                root = self.fixture(directory)
                files = self.sources(root)
                manifest = self.manifest(files)
                files[name].write_text("changed", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "TERRAFORM_SOURCE_HASH_MISMATCH"):
                    pack_release.verify_terraform_sources(files, manifest)

    def test_added_or_deleted_source_requires_a_new_release_manifest(self):
        with self.temporary() as directory:
            root = self.fixture(directory)
            files = self.sources(root)
            manifest = self.manifest(files)
            added = root / "terraform/outputs.tf"
            added.write_text('output "deployment" { value = {} }', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "TERRAFORM_SOURCE_MANIFEST_REQUIRED"):
                pack_release.verify_terraform_sources(self.sources(root), manifest)
            files.pop("terraform/main.tf")
            with self.assertRaisesRegex(ValueError, "TERRAFORM_SOURCE_MANIFEST_REQUIRED"):
                pack_release.verify_terraform_sources(files, manifest)

    def test_company_state_vars_and_saved_plan_fail_the_release_inventory(self):
        for name in ["company.tfvars", "company.auto.tfvars.json", "terraform.tfstate.backup", "release.tfplan", "backend.prod.hcl"]:
            with self.subTest(name=name), self.temporary() as directory:
                root = self.fixture(directory)
                (root / "terraform" / name).write_text("private", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "UNREVIEWED_TERRAFORM_SOURCE"):
                    self.sources(root)

    def test_provider_initialization_cache_does_not_enter_the_manifest(self):
        with self.temporary() as directory:
            root = self.fixture(directory)
            cache = root / "terraform/.terraform/providers"
            cache.mkdir(parents=True)
            (cache / "provider").write_bytes(b"binary")
            self.assertEqual(len(self.sources(root)), 3)

    def test_unlocked_or_missing_terraform_source_cannot_be_published(self):
        with self.temporary() as directory:
            with self.assertRaisesRegex(ValueError, "TERRAFORM_PROVIDER_LOCK_REQUIRED"):
                release.terraform_inventory(Path(directory))
            root = self.fixture(directory)
            (root / "terraform/.terraform.lock.hcl").unlink()
            with self.assertRaisesRegex(ValueError, "TERRAFORM_PROVIDER_LOCK_REQUIRED"):
                self.sources(root)
            with self.assertRaisesRegex(ValueError, "TERRAFORM_SOURCE_MANIFEST_REQUIRED"):
                pack_release.verify_terraform_sources({}, {"source_files": {}})


if __name__ == "__main__":
    unittest.main()
