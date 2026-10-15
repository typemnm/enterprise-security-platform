"""Offline tests proving the clean Node dependency snapshot stays immutable."""
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("tested_node_packaging", ROOT / "node_packaging.py")
node_packaging = importlib.util.module_from_spec(spec)
spec.loader.exec_module(node_packaging)


def zipped(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, body in entries.items():
            archive.writestr(name, body)
    buffer.seek(0)
    return buffer


class NodePackagingTests(unittest.TestCase):
    def setUp(self):
        directory = ROOT / "build/node-packaging-tests"
        directory.mkdir(parents=True, exist_ok=True)
        self.workspace = tempfile.TemporaryDirectory(dir=directory)
        self.addCleanup(self.workspace.cleanup)
        self.root = Path(self.workspace.name)
        self.dashboard = self.root / "dashboard"
        self.vendor = self.dashboard / "node_modules/library"
        self.vendor.mkdir(parents=True)
        lock = {"lockfileVersion": 3, "packages": {"": {"version": "1.0.0"}, "node_modules/library": {
            "version": "1.0.0", "resolved": "https://registry.npmjs.org/library/-/library-1.0.0.tgz",
            "integrity": "sha512-" + "A" * 86 + "=="}}}
        (self.dashboard / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
        (self.vendor / "LICENSE").write_text("Original public author copyright", encoding="utf-8")
        (self.vendor / "NOTICE").write_text("Original public author notice", encoding="utf-8")

    def entries(self):
        return {path.relative_to(self.dashboard).as_posix(): path.read_bytes()
                for path in self.dashboard.rglob("*") if path.is_file()
                and node_packaging.archive_member(path.relative_to(self.dashboard).as_posix())}

    def test_clean_snapshot_preserves_notices_and_excludes_npm_bookkeeping(self):
        (self.dashboard / "node_modules/.package-lock.json").write_text("bookkeeping")
        bins = self.dashboard / "node_modules/.bin"
        bins.mkdir()
        (bins / "command").write_text("optional CLI shim")
        metadata = node_packaging.capture(self.root)
        self.assertEqual(set(metadata["files"]), {"node_modules/library/LICENSE", "node_modules/library/NOTICE"})
        node_packaging.verify_tree(self.root, metadata)
        node_packaging.verify_manifest(self.root, zipped(self.entries()), metadata)

    def test_tree_snapshot_rejects_file_changes_additions_and_deletions(self):
        metadata = node_packaging.capture(self.root)
        path = self.vendor / "LICENSE"
        original = path.read_bytes()
        for operation in ("change", "add", "delete"):
            with self.subTest(operation=operation):
                if operation == "change": path.write_text("changed")
                elif operation == "add": (self.vendor / "company.json").write_text("private")
                else: path.unlink()
                with self.assertRaisesRegex(ValueError, "NODE_VENDOR_TREE_CHANGED"):
                    node_packaging.verify_tree(self.root, metadata)
                path.write_bytes(original)
                (self.vendor / "company.json").unlink(missing_ok=True)

    def test_archive_verification_rejects_changes_additions_and_deletions(self):
        metadata, clean = node_packaging.capture(self.root), self.entries()
        changed = dict(clean, **{"node_modules/library/LICENSE": b"changed"})
        added = dict(clean, **{"node_modules/library/company.json": b"private"})
        deleted = {name: body for name, body in clean.items() if not name.endswith("/LICENSE")}
        for entries in (changed, added, deleted):
            with self.assertRaises(ValueError):
                node_packaging.verify_manifest(self.root, zipped(entries), metadata)
        hidden = dict(clean, **{"node_modules/.package-lock.json": b"bookkeeping"})
        with self.assertRaisesRegex(ValueError, "UNSAFE_NODE_PACKAGE_INVENTORY"):
            node_packaging.verify_manifest(self.root, zipped(hidden), metadata)

    def test_lock_change_invalidates_dependency_evidence(self):
        metadata = node_packaging.capture(self.root)
        lock = self.dashboard / "package-lock.json"
        body = json.loads(lock.read_text())
        body["packages"]["node_modules/library"]["version"] = "1.0.1"
        lock.write_text(json.dumps(body), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "NODE_DEPENDENCY_MANIFEST_MISMATCH"):
            node_packaging.verify_manifest(self.root, zipped(self.entries()), metadata)

    def test_builder_captures_clean_install_before_tests_and_rejects_test_mutation(self):
        spec = importlib.util.spec_from_file_location("tested_build_release", ROOT / "build_release.py")
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        (self.dashboard / "package.json").write_text('{"dependencies":{"library":"1.0.0"}}')
        (self.dashboard / "lambda.js").write_text("module.exports={};")
        (self.dashboard / "test").mkdir()
        (self.dashboard / "test/example.cjs").write_text("synthetic")
        calls = []
        def fake_run(arguments, **kwargs):
            calls.append(arguments)
            if "--test" in arguments:
                (self.vendor / "LICENSE").write_text("changed by a test")
            return "# tests 1\n# pass 1\n# fail 0"
        with patch.object(builder, "ROOT", self.root), patch.object(builder, "run", fake_run), patch.object(builder.shutil, "which", return_value="node"):
            with self.assertRaisesRegex(ValueError, "NODE_VENDOR_TREE_CHANGED"):
                builder.dashboard_check()
        self.assertTrue(any("ci" in row and "--ignore-scripts" in row for row in calls))


if __name__ == "__main__":
    unittest.main()
