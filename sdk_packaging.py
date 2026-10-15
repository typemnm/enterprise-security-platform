"""Hash-locked pure Python AWS SDK packaging and offline API-model checks."""
import email
import hashlib
import importlib.metadata
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile
import zipfile

LOCK_NAME = "runtime-requirements.lock.txt"
PACKAGES = {"boto3": "boto3", "botocore": "botocore", "jmespath": "jmespath", "python-dateutil": "dateutil",
            "s3transfer": "s3transfer", "six": "six.py", "urllib3": "urllib3"}
VALIDATED_SDK = {"boto3": "1.43.106", "botocore": "1.43.113"}
REQUIRED_RESOURCE_TYPES = {"APPLICATION_LOAD_BALANCER", "API_GATEWAY", "APPSYNC", "COGNITO_USER_POOL",
                           "APP_RUNNER_SERVICE", "VERIFIED_ACCESS_INSTANCE", "AMPLIFY", "AGENTCORE_GATEWAY"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_lock(path):
    locked = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        match = re.fullmatch(r"([a-z0-9-]+)==([0-9][A-Za-z0-9.]*) --hash=sha256:([0-9a-f]{64})", line)
        if not match or match[1] not in PACKAGES or match[1] in locked:
            raise ValueError("INVALID_RUNTIME_SDK_LOCK")
        locked[match[1]] = {"version": match[2], "sha256": match[3]}
    if set(locked) != set(PACKAGES) or any(locked[name]["version"] != version for name, version in VALIDATED_SDK.items()):
        raise ValueError("INCOMPLETE_OR_UNVALIDATED_RUNTIME_SDK_LOCK")
    return locked


def sdk_path(name):
    path = PurePosixPath(name)
    if not name or name.startswith("/") or "\\" in name or ".." in path.parts:
        return False
    root = path.parts[0]
    return root in PACKAGES.values() or any(root.startswith(package.replace("-", "_") + "-") and root.endswith(".dist-info") for package in PACKAGES)


def wheel_entries(directory, locked):
    """Only exact universal wheel bytes enter the ZIP; host packages never do."""
    entries, metadata = {}, {}
    for path in sorted(directory.glob("*.whl")):
        body = path.read_bytes()
        if not path.name.endswith("-none-any.whl"):
            raise ValueError("RUNTIME_SDK_REQUIRES_UNIVERSAL_WHEELS")
        with zipfile.ZipFile(path) as wheel:
            names = wheel.namelist()
            if len(names) != len(set(names)):
                raise ValueError("DUPLICATE_RUNTIME_SDK_WHEEL_PATH")
            descriptions = [name for name in names if name.endswith(".dist-info/METADATA")]
            if len(descriptions) != 1:
                raise ValueError("INVALID_RUNTIME_SDK_WHEEL_METADATA")
            description = email.message_from_bytes(wheel.read(descriptions[0]))
            package = description["Name"].lower().replace("_", "-")
            if (package not in locked or package in metadata or description["Version"] != locked[package]["version"]
                    or sha(body) != locked[package]["sha256"]):
                raise ValueError("RUNTIME_SDK_WHEEL_HASH_OR_VERSION_MISMATCH")
            metadata[package] = {"filename": path.name, **locked[package]}
            package_root = PACKAGES[package]
            dist_info = descriptions[0].split("/", 1)[0]
            for info in wheel.infolist():
                name = info.filename
                if info.is_dir():
                    continue
                parts = PurePosixPath(name).parts
                if not name or name.startswith("/") or "\\" in name or ".." in parts:
                    raise ValueError("UNSAFE_RUNTIME_SDK_WHEEL_PATH")
                if ((info.external_attr >> 16) & 0o170000) == 0o120000:
                    raise ValueError("RUNTIME_SDK_WHEEL_SYMLINK_PROHIBITED")
                # Optional dependency CLI scripts are not Lambda runtime files.
                if parts[0].endswith(".data"):
                    continue
                if (parts[0] not in {package_root, dist_info} or name in entries
                        or name.endswith((".so", ".pyd", ".dll", ".exe", ".pyc"))):
                    raise ValueError("UNEXPECTED_RUNTIME_SDK_WHEEL_FILE")
                entries[name] = wheel.read(info)
    if set(metadata) != set(locked):
        raise ValueError("INCOMPLETE_RUNTIME_SDK_WHEELS")
    return entries, metadata


def verify_capabilities(session):
    """Inspect local service-model schemas without credentials or AWS requests."""
    cloudfront = session.get_service_model("cloudfront")
    operation = cloudfront.operation_model("ListDistributionTenantsByCustomization")
    if (not {"WebACLArn", "MaxItems", "Marker"} <= operation.input_shape.members.keys()
            or not {"DistributionTenantList", "NextMarker"} <= operation.output_shape.members.keys()):
        raise ValueError("UNSUPPORTED_DEPLOYED_SDK_CLOUDFRONT_TENANTS")
    waf = session.get_service_model("wafv2")
    types = set(waf.operation_model("ListResourcesForWebACL").input_shape.members["ResourceType"].enum)
    if not REQUIRED_RESOURCE_TYPES <= types:
        raise ValueError("UNSUPPORTED_DEPLOYED_SDK_WAF_RESOURCE_TYPES")
    for action in ["CreateWebACL", "UpdateWebACL"]:
        protection = waf.operation_model(action).input_shape.members.get("DataProtectionConfig")
        if protection is None or "DataProtections" not in protection.members:
            raise ValueError("UNSUPPORTED_DEPLOYED_SDK_WAF_DATA_PROTECTION")
        item = protection.members["DataProtections"].member
        field = item.members.get("Field")
        if (field is None or not {"FieldType", "FieldKeys"} <= field.members.keys()
                or not {"SINGLE_HEADER", "QUERY_STRING", "BODY"} <= set(field.members["FieldType"].enum)
                or "SUBSTITUTION" not in item.members["Action"].enum
                or not {"ExcludeRuleMatchDetails", "ExcludeRateBasedDetails"} <= item.members.keys()):
            raise ValueError("UNSUPPORTED_DEPLOYED_SDK_WAF_DATA_PROTECTION")
    session.get_service_model("bedrock-runtime").operation_model("Converse")
    return {"cloudfront_tenants": True, "waf_data_protection": True, "bedrock_converse": True,
            "waf_resource_types": sorted(REQUIRED_RESOURCE_TYPES)}


PROBE = r'''
import importlib.util,json,pathlib,sys
target=pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0,str(target))
spec=importlib.util.spec_from_file_location("sdk_probe",sys.argv[2])
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
locked=module.read_lock(pathlib.Path(sys.argv[3]))
import boto3,botocore,botocore.session,jmespath,dateutil,s3transfer,six,urllib3
for dependency in [boto3,botocore,jmespath,dateutil,s3transfer,six,urllib3]:
    if target not in pathlib.Path(dependency.__file__).resolve().parents:
        raise ValueError("HOST_SDK_DEPENDENCY_PROHIBITED")
versions={name:module.importlib.metadata.version(name) for name in locked}
if versions != {name:item["version"] for name,item in locked.items()}:
    raise ValueError("INSTALLED_RUNTIME_SDK_VERSION_MISMATCH")
print(json.dumps(module.verify_capabilities(botocore.session.get_session()),sort_keys=True))
'''


def prepare(root, run):
    root = root.resolve()
    lock = root / LOCK_NAME
    locked = read_lock(lock)
    workspace = root / "build/runtime-sdk"
    if root not in workspace.resolve().parents:
        raise ValueError("RUNTIME_SDK_WORKSPACE_ESCAPES_PROJECT")
    workspace.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="validated-", dir=workspace) as directory:
        directory = Path(directory)
        if workspace.resolve() not in directory.resolve().parents:
            raise ValueError("RUNTIME_SDK_TEMPORARY_PATH_ESCAPES_WORKSPACE")
        wheels, target = directory / "wheels", directory / "installed"
        wheels.mkdir()
        run([sys.executable, "-m", "pip", "download", "--disable-pip-version-check", "--no-input", "--only-binary=:all:",
             "--require-hashes", "--no-deps", "--dest", str(wheels), "-r", str(lock)])
        entries, wheel_metadata = wheel_entries(wheels, locked)
        # An offline install also verifies the complete dependency closure.
        run([sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--no-input", "--no-index",
             "--find-links", str(wheels), "--require-hashes", "--only-binary=:all:", "--ignore-installed", "--no-compile",
             "--target", str(target), "-r", str(lock)])
        capabilities = json.loads(run([sys.executable, "-I", "-c", PROBE, str(target), str(root / "sdk_packaging.py"), str(lock)]))
    return entries, {"validation": "passed", "lock_file": LOCK_NAME, "lock_sha256": sha(lock.read_bytes()),
                     "versions": {name: item["version"] for name, item in locked.items()}, "wheels": wheel_metadata,
                     "files": {name: sha(body) for name, body in sorted(entries.items())}, "capabilities": capabilities}


def verify_manifest(root, archive, metadata):
    lock = root / LOCK_NAME
    locked = read_lock(lock)
    if (metadata.get("validation") != "passed" or metadata.get("lock_file") != LOCK_NAME
            or metadata.get("lock_sha256") != sha(lock.read_bytes())
            or metadata.get("versions") != {name: item["version"] for name, item in locked.items()}
            or set(metadata.get("wheels", {})) != set(locked)):
        raise ValueError("RUNTIME_SDK_LOCK_MANIFEST_MISMATCH")
    for name, wheel in metadata["wheels"].items():
        if wheel.get("version") != locked[name]["version"] or wheel.get("sha256") != locked[name]["sha256"]:
            raise ValueError("RUNTIME_SDK_WHEEL_MANIFEST_MISMATCH")
    if (metadata.get("capabilities", {}).get("cloudfront_tenants") is not True
            or metadata.get("capabilities", {}).get("waf_data_protection") is not True
            or metadata.get("capabilities", {}).get("bedrock_converse") is not True
            or set(metadata.get("capabilities", {}).get("waf_resource_types", [])) != REQUIRED_RESOURCE_TYPES):
        raise ValueError("RUNTIME_SDK_CAPABILITY_VALIDATION_REQUIRED")
    files = metadata.get("files", {})
    if not files or any(not sdk_path(name) or not re.fullmatch(r"[0-9a-f]{64}", value) for name, value in files.items()):
        raise ValueError("INVALID_RUNTIME_SDK_FILE_MANIFEST")
    with zipfile.ZipFile(archive) as package:
        names = package.namelist()
        if len(names) != len(set(names)) or {name for name in names if sdk_path(name)} != set(files):
            raise ValueError("RUNTIME_SDK_PACKAGE_INVENTORY_MISMATCH")
        for name, checksum in files.items():
            if sha(package.read(name)) != checksum:
                raise ValueError("RUNTIME_SDK_DEPENDENCY_FILE_HASH_MISMATCH")
