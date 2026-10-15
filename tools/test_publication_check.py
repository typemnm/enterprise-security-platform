"""Publication safety tests with in-memory synthetic inputs only."""
import io
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from publication_check import allowed_source, archive_findings, content_findings, source_inventory
import publication_check


def archive(entries):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as result:
        for name, body in entries.items(): result.writestr(name, body)
    return output.getvalue()


def node_metadata(lock, entries):
    packages = json.loads(lock)["packages"]
    return {"validation": "passed", "lock_file": "dashboard/package-lock.json", "lock_sha256": hashlib.sha256(lock.encode()).hexdigest(),
            "packages": {name: {field: row.get(field) for field in ["version", "resolved", "integrity"]} for name, row in packages.items() if name},
            "files": {name: hashlib.sha256(body.encode() if isinstance(body, str) else body).hexdigest()
                      for name, body in entries.items() if name.startswith("node_modules/")}}


class PublicationTests(unittest.TestCase):
    def parser_fixture(self, body):
        path = "node_modules/jose/dist/webapi/key/import.js"
        lock = json.dumps({"packages": {"node_modules/jose": {"version": "6.2.12"}}})
        entries = {"package-lock.json": lock, path: body}
        return archive(entries), node_metadata(lock, entries)
    def test_public_parser_exception_requires_exact_path_version_and_file_hash(self):
        body = ('const header = "-----BEGIN ' + 'PRIVATE KEY-----";').encode()
        path = "node_modules/jose/dist/webapi/key/import.js"
        expected = {"package": "node_modules/jose", "version": "6.2.12", "sha256": hashlib.sha256(body).hexdigest()}
        with patch.dict(publication_check.PUBLIC_VENDOR_PARSERS, {path: expected}, clear=True):
            payload, metadata = self.parser_fixture(body)
            self.assertEqual(archive_findings(payload, kind="dashboard", node_metadata=metadata), [])
            self.assertTrue(publication_check.public_vendor_parser(path, body, {"node_modules/jose": {"version": "6.2.12"}}))
            self.assertFalse(publication_check.public_vendor_parser(path + ".copy", body, {"node_modules/jose": {"version": "6.2.12"}}))
            self.assertFalse(publication_check.public_vendor_parser(path, body, {"node_modules/jose": {"version": "6.2.13"}}))
    def test_public_parser_exception_rejects_mutation_and_added_private_key_body(self):
        body = ('const header = "-----BEGIN ' + 'PRIVATE KEY-----";').encode()
        path = "node_modules/jose/dist/webapi/key/import.js"
        expected = {"package": "node_modules/jose", "version": "6.2.12", "sha256": hashlib.sha256(body).hexdigest()}
        fake_pem = ('\n-----BEGIN ' + 'PRIVATE KEY-----\n' + 'A' * 100 + '\n-----END ' + 'PRIVATE KEY-----\n').encode()
        with patch.dict(publication_check.PUBLIC_VENDOR_PARSERS, {path: expected}, clear=True):
            for changed in (body + b'\n// changed', body + fake_pem):
                payload, metadata = self.parser_fixture(changed)
                findings = archive_findings(payload, kind="dashboard", node_metadata=metadata)
                self.assertEqual([row["code"] for row in findings], ["PRIVATE_KEY_LITERAL"])
    def test_source_allowlist_never_accepts_generated_or_company_files(self):
        self.assertTrue(allowed_source("runtime/blocker.py"))
        self.assertTrue(allowed_source("service-onboarding/installation.example.json"))
        for name in ("installation.json", ".env", "config/company.json", "build/install-result.json", "dashboard/node_modules/a/index.js", "../runtime.py"):
            self.assertFalse(allowed_source(name))
    def test_findings_never_echo_credentials_account_email_or_endpoint(self):
        values = ["AK" + "IA" + "Z" * 16, "user@" + "customer.company", "https://private." + "internal/dashboard", "arn:aws:iam::" + "2" * 12 + ":role/Company"]
        findings = content_findings("runtime/example.py", ("\n".join(values)).encode())
        self.assertEqual({row["code"] for row in findings}, {"CREDENTIAL_LITERAL", "NON_EXAMPLE_EMAIL", "INSTALLATION_OR_INTERNAL_URL", "NON_EXAMPLE_ACCOUNT_ID"})
        self.assertFalse(any(value in str(findings) for value in values))
    def test_reserved_examples_are_allowed_but_test_file_real_secret_is_not(self):
        self.assertEqual(content_findings("tests/example.py", b'user@example.com arn:aws:iam::123456789012:role/Example https://dashboard.example'), [])
        value = "xoxb-" + "Z" * 30
        self.assertTrue(content_findings("tests/example.py", value.encode()))
    def test_non_example_resource_uuid_is_rejected(self):
        value = "fedcba98-" + "7654-4321-8234-abcdef123456"
        self.assertEqual(content_findings("tests/example.py", value.encode())[0]["code"], "NON_EXAMPLE_RESOURCE_UUID")
    def test_source_scan_skips_generated_dependencies_and_catches_unlisted_upload(self):
        workspace = Path(__file__).resolve().parents[1] / "build/publication-tests"
        workspace.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=workspace) as directory:
            root = Path(directory)
            (root / "build").mkdir(); (root / "build/company.json").write_text("private")
            (root / "README.md").write_text("neutral")
            (root / "evidence.json").write_text("private")
            files, findings = source_inventory(root)
            self.assertEqual(files, ["README.md"])
            self.assertEqual(findings, [{"path": "evidence.json", "code": "SOURCE_PATH_NOT_ALLOWED"}])
    def test_deploy_archive_members_and_nested_project_source_are_checked(self):
        runtime = archive({"runtime/blocker.py": "neutral", "blocker.py": "neutral"})
        lock = '{"packages":{"node_modules/library":{"version":"1.0.0","license":"MIT"}}}'
        entries = {"server.js": "neutral", "package-lock.json": lock, "node_modules/library/LICENSE": "original license"}
        dashboard = archive(entries)
        bundle = archive({"enterprise-security-platform/README.md": "neutral", "enterprise-security-platform/build/release/runtime.zip": runtime,
                          "enterprise-security-platform/build/release/dashboard.zip": dashboard,
                          "enterprise-security-platform/build/release/manifest.json": json.dumps({"node_dependencies": node_metadata(lock, entries)})})
        self.assertEqual(archive_findings(bundle), [])
        bad = archive({"build/release/runtime.zip": archive({"runtime/blocker.py": "AK" + "IA" + "Z" * 16})})
        self.assertEqual(archive_findings(bad)[0]["code"], "CREDENTIAL_LITERAL")
    def test_company_results_and_traversal_are_rejected_in_upload_archive(self):
        for name in ("build/install-result.json", "../README.md", "enterprise-security-platform/config/company.json"):
            self.assertTrue(archive_findings(archive({name: "private"})))
    def test_unexpected_runtime_or_dashboard_members_are_rejected(self):
        self.assertTrue(archive_findings(archive({"company-config.json": "private"}), kind="runtime"))
        self.assertTrue(archive_findings(archive({".env": "private"}), kind="dashboard"))
    def test_vendor_hash_guard_rejects_changed_added_deleted_and_missing_proof(self):
        lock = '{"packages":{"node_modules/library":{"version":"1.0.0"}}}'
        clean = {"package-lock.json": lock, "node_modules/library/LICENSE": "original public author contact"}
        metadata = node_metadata(lock, clean)
        self.assertEqual(archive_findings(archive(clean), kind="dashboard", node_metadata=metadata), [])
        for entries in (dict(clean, **{"node_modules/library/LICENSE": "changed"}),
                        dict(clean, **{"node_modules/library/company.json": "private"}), {"package-lock.json": lock}):
            self.assertTrue(archive_findings(archive(entries), kind="dashboard", node_metadata=metadata))
        self.assertTrue(archive_findings(archive(clean), kind="dashboard"))


if __name__ == "__main__": unittest.main()
