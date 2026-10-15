"""Offline allowlist and sensitive-data checks for public source/deploy uploads.

Findings contain only paths, line numbers and rule codes, never matched values.
This is a release guard, not a claim that every possible secret is detectable.
"""
import argparse
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

TOP_LEVEL = {"README.md", "LICENSE", "NOTICE", "SECURITY.md", "CONTRIBUTING.md", "THIRD_PARTY_NOTICES.md",
             "CODE_OF_CONDUCT.md", "ENTERPRISE_DEPLOYMENT.md", "SERVICE_POLICY.md", ".gitignore", ".gitattributes",
             "build_release.py", "install.py", "sdk_packaging.py", "node_packaging.py", "runtime-requirements.lock.txt"}
GENERATED = {".git", "build", "dist", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
             ".npm-cache", "coverage", "htmlcov"}
PRIVATE_PARTS = {".aws", "private", "config", "configs", "company-security", "credentials", "logs", "evidence", "uploads"}
ARTIFACT_FILES = {"build/release/runtime.zip", "build/release/dashboard.zip", "build/release/manifest.json",
                  "build/test-validation-result.json"}
SDK_ROOTS = {"boto3", "botocore", "jmespath", "dateutil", "s3transfer", "six.py", "urllib3"}
SDK_DISTS = {"boto3", "botocore", "jmespath", "python_dateutil", "s3transfer", "six", "urllib3"}
EXAMPLE_ACCOUNTS = {"123456789012", "999999999999", "111111111111", "000000000000", "111122223333"}
EMAIL = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![A-Za-z0-9.-])")
ACCOUNT = re.compile(r"(?<![A-Za-z0-9])[0-9]{12}(?![A-Za-z0-9])")
UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
EXAMPLE_UUIDS = {"00000000-0000-0000-0000-000000000000", "00000000-0000-4000-8000-aaaaaaaaaaaa",
                 "12345678-1234-1234-1234-123456789abc", "12345678-1234-4234-8234-123456789abc",
                 "abcdef12-1234-4234-8234-123456789abc"}
TOKEN = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b|\bxox[baprs]-[A-Za-z0-9-]{15,}\b|\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----")
SECRET_VALUE = re.compile(r"(?i)\b(?:aws_secret_access_key|client_secret|slack_bot_token|password)\s*[:=]\s*['\"]([^'\"\r\n]{12,})['\"]")
URL = re.compile(r"https?://([A-Za-z0-9.-]+)(?::\d+)?(?:/[^\s\"'<>`{}]*)?")
PERSONAL_PATH = re.compile(r"(?i)(?:[A-Z]:[\\/]+Users[\\/]+[^\s\"']+|/(?:Users|home)/[^\s\"']+)")
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_BYTES = 500 * 1024 * 1024
MAX_MEMBERS = 50000
# This exact public JOSE parser checks a PEM header; it contains no key body.
# An upgrade or any file change requires a fresh review, never a broad skip.
PUBLIC_VENDOR_PARSERS = {
    "node_modules/jose/dist/webapi/key/import.js": {
        "package": "node_modules/jose", "version": "6.2.12",
        "sha256": "ab2f57a9db99e8d48451a8d0a8adf75379381f65b0e3e28ba6c02aa5bb3ee5fa",
    },
}
# This exact SDK example contains a literal placeholder, not private key data.
# Wheel/lock provenance and the individual file hash remain mandatory.
PUBLIC_SDK_EXAMPLES = {
    "botocore/data/iam/2010-05-08/examples-1.json": {
        "package": "botocore", "version": "1.43.113",
        "sha256": "4f912aac51590625652fd76c37e4f90e78a05355273125df555c012b4d005ab5",
    },
}


def safe_relative(name):
    value = PurePosixPath(name)
    return bool(name) and not name.startswith(("/", "\\")) and "\\" not in name and ":" not in name and ".." not in value.parts


def private_path(name):
    path = PurePosixPath(name)
    lower = [part.lower() for part in path.parts]
    filename = lower[-1] if lower else ""
    return (any(part in PRIVATE_PARTS for part in lower) or filename.startswith(".env")
            or filename.endswith((".pem", ".key", ".p12", ".pfx", ".log", ".tfstate"))
            or "result" in filename and name not in ARTIFACT_FILES
            or filename.startswith("installation") and name != "service-onboarding/installation.example.json")


def allowed_source(name):
    """Reusable packer contract: only these source paths may enter an upload."""
    if not safe_relative(name) or private_path(name): return False
    path = PurePosixPath(name)
    if len(path.parts) == 1:
        return name in TOP_LEVEL or re.fullmatch(r"validate_[a-z_]+\.py", name) is not None
    if path.parts[0] == "runtime": return len(path.parts) == 2 and path.suffix == ".py"
    if path.parts[0] in {"infrastructure", "tests"}:
        return len(path.parts) == 2 and path.suffix in {".py", ".json", ".txt"}
    if path.parts[0] == "service-onboarding":
        return len(path.parts) == 2 and path.suffix in {".py", ".json", ".txt"}
    if path.parts[0] == "dashboard":
        return ((len(path.parts) == 2 and path.suffix in {".js", ".json", ".md"})
                or len(path.parts) == 3 and path.parts[1] == "test" and path.suffix == ".cjs"
                or len(path.parts) == 3 and path.parts[1] == "public" and path.suffix in {".css", ".html", ".svg"})
    if path.parts[0] == "tools": return len(path.parts) == 2 and path.suffix == ".py"
    if path.parts[0] == "docs": return path.suffix == ".md"
    return name == ".github/workflows/ci.yml"


def reserved_domain(domain):
    domain = domain.lower().rstrip(".")
    return domain in {"example.com", "example.net", "example.org"} or domain.endswith((".example", ".test", ".invalid", ".example.com", ".example.net", ".example.org"))


def synthetic_token(name, value):
    if not name.startswith(("tests/", "dashboard/test/", "tools/test_")): return False
    # Narrow documented sanitizer fixtures; arbitrary test-file secrets fail.
    return (re.fullmatch(r"xoxb-(?:\d{20}-secret|second-\d{20}|\d{10}-\d{10}-secretvalue)", value) is not None
            or value in {"xoxb-" + "private-callback-token"})


def content_findings(name, body):
    if len(body) > MAX_SOURCE_BYTES: return [{"path": name, "code": "SOURCE_SIZE_LIMIT"}]
    try: text = body.decode("utf-8")
    except UnicodeDecodeError: return [{"path": name, "code": "NON_TEXT_SOURCE"}]
    findings = []
    def record(code, offset):
        findings.append({"path": name, "line": text.count("\n", 0, offset) + 1, "code": code})
    for match in ACCOUNT.finditer(text):
        if match.group() not in EXAMPLE_ACCOUNTS: record("NON_EXAMPLE_ACCOUNT_ID", match.start())
    for match in UUID.finditer(text):
        if match.group().lower() not in EXAMPLE_UUIDS: record("NON_EXAMPLE_RESOURCE_UUID", match.start())
    for match in TOKEN.finditer(text):
        if not synthetic_token(name, match.group()): record("CREDENTIAL_LITERAL", match.start())
    for match in PRIVATE_KEY.finditer(text): record("PRIVATE_KEY_LITERAL", match.start())
    for match in SECRET_VALUE.finditer(text):
        if not reserved_domain(match[1]) and not re.fullmatch(r"(?:example|placeholder|fake|dummy)[A-Za-z0-9_-]*", match[1], re.I):
            record("SECRET_ASSIGNMENT", match.start())
    for match in EMAIL.finditer(text):
        if not reserved_domain(match[1]): record("NON_EXAMPLE_EMAIL", match.start())
    for match in PERSONAL_PATH.finditer(text): record("PERSONAL_ABSOLUTE_PATH", match.start())
    for match in URL.finditer(text):
        host = match[1].lower()
        if reserved_domain(host) or host in {"localhost", "127.0.0.1", "0.0.0.0"}: continue
        try: internal = not ipaddress.ip_address(host).is_global
        except ValueError:
            internal = (host.endswith((".local", ".internal", ".lan", ".corp", ".amazoncognito.com"))
                        or ".execute-api." in host or ".s3." in host or host.endswith(".s3.amazonaws.com"))
        if internal: record("INSTALLATION_OR_INTERNAL_URL", match.start())
    return findings


def source_inventory(root):
    root, findings, files = root.resolve(), [], []
    for directory, folders, names in os.walk(root, followlinks=False):
        base = Path(directory)
        for folder in list(folders):
            path = base / folder
            if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
                findings.append({"path": path.relative_to(root).as_posix(), "code": "SYMLINK_PROHIBITED"})
                folders.remove(folder)
            elif folder in GENERATED: folders.remove(folder)
        for filename in names:
            path = base / filename
            name = path.relative_to(root).as_posix()
            if filename in {".DS_Store", "Thumbs.db"} or filename.endswith((".pyc", ".pyo")): continue
            if path.is_symlink(): findings.append({"path": name, "code": "SYMLINK_PROHIBITED"}); continue
            if not allowed_source(name): findings.append({"path": name, "code": "SOURCE_PATH_NOT_ALLOWED"}); continue
            files.append(name)
            findings.extend(content_findings(name, path.read_bytes()))
    return sorted(files), findings


def vendor_member(name, kind):
    root = PurePosixPath(name).parts[0]
    if kind == "dashboard": return root == "node_modules"
    return root in SDK_ROOTS or any(root.startswith(package + "-") and root.endswith(".dist-info") for package in SDK_DISTS)


def public_vendor_parser(name, body, node_packages):
    expected = PUBLIC_VENDOR_PARSERS.get(name)
    return bool(expected and node_packages.get(expected["package"], {}).get("version") == expected["version"]
                and hashlib.sha256(body).hexdigest() == expected["sha256"])


def public_sdk_example(name, body, sdk_versions):
    expected = PUBLIC_SDK_EXAMPLES.get(name)
    return bool(expected and (sdk_versions or {}).get(expected["package"]) == expected["version"]
                and hashlib.sha256(body).hexdigest() == expected["sha256"])


def archive_findings(body, *, kind="deploy", prefix="", depth=0, sdk_files=None, sdk_versions=None, node_metadata=None):
    findings = []
    if depth > 1: return [{"path": prefix, "code": "NESTED_ARCHIVE_LIMIT"}]
    try:
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            rows = archive.infolist()
            if len(rows) > MAX_MEMBERS or sum(row.file_size for row in rows) > MAX_ARCHIVE_BYTES:
                return [{"path": prefix, "code": "ARCHIVE_SIZE_LIMIT"}]
            seen = set()
            if kind == "deploy":
                manifest_name = next((row.filename for row in rows if row.filename.removeprefix("enterprise-security-platform/") == "build/release/manifest.json"), None)
                if manifest_name:
                    manifest = json.loads(archive.read(manifest_name))
                    sdk_files = manifest.get("runtime_sdk", {}).get("files", {})
                    sdk_versions = manifest.get("runtime_sdk", {}).get("versions", {})
                    node_metadata = manifest.get("node_dependencies", {})
            node_packages = {}
            node_files, found_node_files = {}, set()
            if kind == "dashboard" and "package-lock.json" in archive.namelist():
                lock_body = archive.read("package-lock.json")
                node_packages = json.loads(lock_body).get("packages", {})
                if node_metadata:
                    packages = {name: {field: row.get(field) for field in ["version", "resolved", "integrity"]}
                                for name, row in node_packages.items() if name}
                    if (node_metadata.get("validation") != "passed"
                            or node_metadata.get("lock_file") != "dashboard/package-lock.json"
                            or node_metadata.get("lock_sha256") != hashlib.sha256(lock_body).hexdigest()
                            or node_metadata.get("packages") != packages
                            or not isinstance(node_metadata.get("files"), dict) or not node_metadata.get("files")):
                        findings.append({"path": prefix, "code": "NODE_DEPENDENCY_MANIFEST_MISMATCH"})
                    else:
                        node_files = node_metadata["files"]
            for row in rows:
                name, label = row.filename, prefix + row.filename
                if row.is_dir(): continue
                if not safe_relative(name) or name in seen or stat.S_ISLNK(row.external_attr >> 16):
                    findings.append({"path": label, "code": "UNSAFE_ARCHIVE_MEMBER"}); continue
                seen.add(name)
                if kind == "deploy":
                    if name.startswith("enterprise-security-platform/"):
                        name = name.removeprefix("enterprise-security-platform/")
                    if name not in ARTIFACT_FILES and not allowed_source(name):
                        findings.append({"path": label, "code": "UPLOAD_MEMBER_NOT_ALLOWED"}); continue
                    content = archive.read(row)
                    if name in {"build/release/runtime.zip", "build/release/dashboard.zip"}:
                        findings.extend(archive_findings(content, kind="runtime" if name.endswith("runtime.zip") else "dashboard", prefix=label + "!", depth=depth + 1, sdk_files=sdk_files, sdk_versions=sdk_versions, node_metadata=node_metadata))
                    else: findings.extend(content_findings(name, content))
                elif vendor_member(name, kind):
                    # Original dependency copyrights, author contacts and SDK
                    # examples belong to their pinned packages and are retained.
                    path = PurePosixPath(name)
                    vendor_body = archive.read(row)
                    if (any(part in {".aws", "company-security", "uploads", "evidence"} for part in path.parts)
                            or path.name.startswith(".env") or path.name.startswith("installation") and path.suffix == ".json"):
                        findings.append({"path": label, "code": "PRIVATE_VENDOR_MEMBER"})
                    if kind == "runtime":
                        if not sdk_files or sdk_files.get(name) != hashlib.sha256(vendor_body).hexdigest():
                            findings.append({"path": label, "code": "UNVERIFIED_SDK_VENDOR_FILE"})
                    else:
                        found_node_files.add(name)
                        if not any(name.startswith(package + "/") for package in node_packages if package):
                            findings.append({"path": label, "code": "UNLOCKED_NODE_VENDOR_FILE"})
                        if node_files.get(name) != hashlib.sha256(vendor_body).hexdigest():
                            findings.append({"path": label, "code": "UNVERIFIED_NODE_VENDOR_FILE"})
                    # SDK config/logs models and public CA certificates are
                    # legitimate pinned vendor files, not company configuration.
                    if (PRIVATE_KEY.search(vendor_body.decode("utf-8", errors="ignore"))
                            and not (kind == "dashboard" and public_vendor_parser(name, vendor_body, node_packages))
                            and not (kind == "runtime" and public_sdk_example(name, vendor_body, sdk_versions))):
                        findings.append({"path": label, "code": "PRIVATE_KEY_LITERAL"})
                else:
                    allowed = (kind == "runtime" and (re.fullmatch(r"runtime/[A-Za-z_][A-Za-z0-9_]*\.py", name) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\.py", name))
                               or kind == "dashboard" and allowed_source("dashboard/" + name))
                    if not allowed: findings.append({"path": label, "code": "LAMBDA_MEMBER_NOT_ALLOWED"}); continue
                    findings.extend(content_findings("dashboard/" + name if kind == "dashboard" else name, archive.read(row)))
            if kind == "dashboard" and node_files and found_node_files != set(node_files):
                findings.append({"path": prefix, "code": "NODE_VENDOR_PACKAGE_INVENTORY_MISMATCH"})
    except (zipfile.BadZipFile, OSError, RuntimeError, ValueError):
        findings.append({"path": prefix, "code": "INVALID_ARCHIVE"})
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    if args.archive:
        files, findings = [], archive_findings(args.archive.read_bytes())
    else: files, findings = source_inventory(args.root)
    print(json.dumps({"status": "PUBLICATION_CHECK_FAILED" if findings else "PUBLICATION_CHECK_PASSED",
                      "mode": "archive" if args.archive else "source", "files": files, "findings": findings}, sort_keys=True))
    return 1 if findings else 0


if __name__ == "__main__": raise SystemExit(main())
