"""Bind packaged Node dependencies to a clean, integrity-locked npm install."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

LOCK_NAME = "dashboard/package-lock.json"
EXCLUDED_PARTS = {".git", ".aws", ".env", ".npm-cache", ".bin", "coverage", "test", "tests", "__pycache__"}


def sha(body):
    return hashlib.sha256(body).hexdigest()


def safe_path(name):
    return bool(name) and not name.startswith(("/", "\\")) and "\\" not in name and ":" not in name and ".." not in PurePosixPath(name).parts


def archive_member(name):
    """Shared selection for the clean snapshot and the actual Lambda ZIP."""
    path = PurePosixPath(name)
    return (safe_path(name) and not any(part in EXCLUDED_PARTS for part in path.parts)
            and name != "node_modules/.package-lock.json"
            and not path.name.startswith(".env") and path.suffix != ".log"
            and (path.parts[0] == "node_modules" or path.suffix in {".js", ".json", ".html", ".css", ".svg"}))


def read_lock(root):
    body = (Path(root) / LOCK_NAME).read_bytes()
    lock = json.loads(body)
    if lock.get("lockfileVersion", 0) < 2 or not isinstance(lock.get("packages"), dict):
        raise ValueError("INVALID_NODE_DEPENDENCY_LOCK")
    packages = {}
    for name, row in lock["packages"].items():
        if not name:
            continue
        if (not safe_path(name) or not name.startswith("node_modules/") or not isinstance(row, dict)
                or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", row.get("version", ""))
                or not re.fullmatch(r"sha512-[A-Za-z0-9+/]+={0,2}", row.get("integrity", ""))
                or not row.get("resolved", "").startswith("https://registry.npmjs.org/")):
            raise ValueError("UNPINNED_NODE_DEPENDENCY")
        packages[name] = {field: row[field] for field in ["version", "resolved", "integrity"]}
    if not packages:
        raise ValueError("EMPTY_NODE_DEPENDENCY_LOCK")
    return body, packages


def vendor_path(name, packages):
    return archive_member(name) and name.startswith("node_modules/") and any(name.startswith(package + "/") for package in packages)


def capture(root):
    """Call immediately after npm ci --ignore-scripts, before running tests."""
    root = Path(root)
    lock, packages = read_lock(root)
    directory, files = root / "dashboard", {}
    for path in sorted((directory / "node_modules").rglob("*")):
        name = path.relative_to(directory).as_posix()
        if not archive_member(name):
            continue
        if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
            raise ValueError("NODE_VENDOR_SYMLINK_PROHIBITED")
        if not path.is_file():
            continue
        if not vendor_path(name, packages):
            raise ValueError("UNLOCKED_NODE_VENDOR_FILE")
        files[name] = sha(path.read_bytes())
    if not files:
        raise ValueError("MISSING_NODE_DEPENDENCY_FILES")
    return {"validation": "passed", "lock_file": LOCK_NAME, "lock_sha256": sha(lock), "packages": packages, "files": files}


def verify_tree(root, metadata):
    if capture(root) != metadata:
        raise ValueError("NODE_VENDOR_TREE_CHANGED_AFTER_CLEAN_INSTALL")


def verify_entries(root, entries, metadata):
    lock, packages = read_lock(root)
    files = metadata.get("files", {})
    if (metadata.get("validation") != "passed" or metadata.get("lock_file") != LOCK_NAME
            or metadata.get("lock_sha256") != sha(lock) or metadata.get("packages") != packages
            or not isinstance(files, dict) or not files
            or any(not vendor_path(name, packages) or not re.fullmatch(r"[0-9a-f]{64}", value) for name, value in files.items())):
        raise ValueError("NODE_DEPENDENCY_MANIFEST_MISMATCH")
    actual = {name for name in entries if name.startswith("node_modules/")}
    if actual != set(files):
        raise ValueError("NODE_VENDOR_PACKAGE_INVENTORY_MISMATCH")
    for name, checksum in files.items():
        if sha(entries[name]) != checksum:
            raise ValueError("NODE_VENDOR_FILE_HASH_MISMATCH")
    if entries.get("package-lock.json") != lock:
        raise ValueError("NODE_PACKAGED_LOCK_MISMATCH")


def verify_manifest(root, archive, metadata):
    """Offline installer/packer interface; neither npm nor AWS is contacted."""
    with zipfile.ZipFile(archive) as package:
        names = package.namelist()
        if len(names) != len(set(names)) or any(not archive_member(name) for name in names):
            raise ValueError("UNSAFE_NODE_PACKAGE_INVENTORY")
        if any(stat.S_ISLNK(row.external_attr >> 16) for row in package.infolist()):
            raise ValueError("NODE_VENDOR_SYMLINK_PROHIBITED")
        verify_entries(root, {name: package.read(name) for name in names}, metadata)
