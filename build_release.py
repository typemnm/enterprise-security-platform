"""Build a deterministic account-neutral enterprise release without AWS calls."""
import argparse
import ast
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "build" / "release"
REQUIRED_MODULES = {"discovery", "ingest", "blocker", "approval", "case_pipeline", "publication",
                    "outcome_metadata", "notification_content", "expected_activity", "counter_evidence"}
_sdk_spec = importlib.util.spec_from_file_location("release_sdk_packaging", ROOT / "sdk_packaging.py")
sdk_packaging = importlib.util.module_from_spec(_sdk_spec)
_sdk_spec.loader.exec_module(sdk_packaging)
_node_spec = importlib.util.spec_from_file_location("release_node_packaging", ROOT / "node_packaging.py")
node_packaging = importlib.util.module_from_spec(_node_spec)
_node_spec.loader.exec_module(node_packaging)


def run(arguments, cwd=ROOT, env=None):
    result = subprocess.run(arguments, cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if result.returncode:
        # Local compiler/test/dependency diagnostics contain no AWS environments.
        raise RuntimeError(f"Local validation failed: {arguments[0]}\n" + (result.stdout + result.stderr)[-12000:])
    return (result.stdout + result.stderr).strip()


def digest(data):
    raw = hashlib.sha256(data).digest()
    return {"sha256": raw.hex(), "code_sha256": base64.b64encode(raw).decode(), "size": len(data)}


def test_result(name, output, node=False):
    if node:
        counts = {field: re.search(r"# " + field + r"\s+(\d+)", output) for field in ["tests", "pass", "fail"]}
        if not all(counts.values()):
            raise ValueError("Missing Node test result counters")
        total, passed, failed = [int(counts[field][1]) for field in ["tests", "pass", "fail"]]
        result = {"suite": name, "tests": total, "passed": passed, "failed": failed, "success": total > 0 and total == passed and failed == 0}
    else:
        count = re.search(r"Ran (\d+) tests? in", output)
        result = {"suite": name, "tests": int(count[1]) if count else 0,
                  "success": bool(count and int(count[1]) > 0 and re.search(r"^OK(?:\s|$)", output, flags=re.MULTILINE))}
    if not result["success"]:
        raise ValueError("Local test suite was empty or unsuccessful: " + name)
    return result


def module_inventory():
    paths = sorted((ROOT / "runtime").glob("*.py"))
    names = {p.stem for p in paths}
    missing = REQUIRED_MODULES - names
    if missing:
        raise ValueError("Missing runtime modules: " + ", ".join(sorted(missing)))
    allowed_imports = names | set(sys.stdlib_module_names) | {"boto3", "botocore", "runtime"}
    for path in paths:
        source = path.read_text(encoding="utf-8")
        compile(source, str(path), "exec")
        if re.search(r"(?<![0-9])[0-9]{12}(?![0-9])", source):
            raise ValueError("Account literal prohibited in runtime: " + path.name)
        if re.search(r"\b(?:WHSVulnWeb|WHS-EC2-Standby|Permanent-Blocked-IPSet)\b|xox[baprs]-[A-Za-z0-9-]{8,}", source):
            raise ValueError("Legacy resource or credential literal prohibited: " + path.name)
        tree = ast.parse(source)
        for node in ast.walk(tree):
            imports = []
            if isinstance(node, ast.Import):
                imports = [part.name.split(".")[0] for part in node.names]
            elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
                imports = [node.module.split(".")[0]]
            elif isinstance(node, ast.ImportFrom) and node.level == 1 and node.module and node.module.split(".")[0] not in names:
                raise ValueError("Missing relative runtime module in " + path.name)
            if any(item not in allowed_imports for item in imports):
                raise ValueError("Unpackaged dependency in " + path.name + ": " + ", ".join(imports))
    return paths


def deterministic_zip(target, entries):
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
        for name, body in sorted(entries.items()):
            if name.startswith("/") or ".." in Path(name).parts:
                raise ValueError("Invalid archive path")
            info = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            output.writestr(info, body)
    return digest(target.read_bytes())


def runtime_archive(paths, sdk_entries):
    entries = {"runtime/" + path.name: path.read_bytes() for path in paths}
    for path in paths:
        if path.stem == "__init__":
            continue
        # Shared modules historically import peers by their top-level names.
        # Wrappers keep a single implementation and also support private imports.
        entries[path.name] = (f"from runtime import {path.stem} as _implementation\n"
                              f"from runtime.{path.stem} import *\n"
                              "def __getattr__(name):\n    return getattr(_implementation, name)\n").encode()
    if not sdk_entries or set(entries) & set(sdk_entries):
        raise ValueError("MISSING_OR_COLLIDING_RUNTIME_SDK_PACKAGE")
    entries.update(sdk_entries)
    if sum(map(len, entries.values())) > 250 * 1024 * 1024:
        raise ValueError("LAMBDA_UNCOMPRESSED_PACKAGE_LIMIT_EXCEEDED")
    return deterministic_zip(OUT / "runtime.zip", entries)


def dashboard_check():
    directory = ROOT / "dashboard"
    required = [directory / name for name in ["package.json", "package-lock.json", "lambda.js"]]
    if any(not path.is_file() for path in required):
        raise ValueError("Dashboard requires package.json, package-lock.json and lambda.js")
    package = json.loads(required[0].read_text(encoding="utf-8"))
    lock = json.loads(required[1].read_text(encoding="utf-8"))
    if lock.get("lockfileVersion", 0) < 2:
        raise ValueError("Dashboard dependency lockfile must be v2 or later")
    for name, version in package.get("dependencies", {}).items():
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", version):
            raise ValueError("Dashboard dependency must be pinned: " + name)
    node = shutil.which("node")
    if not node:
        raise ValueError("Node.js is required to validate the dashboard")
    for path in directory.glob("*.js"):
        source = path.read_text(encoding="utf-8")
        if re.search(r"(?<![0-9])[0-9]{12}(?![0-9])", source) or re.search(r"xox[baprs]-[A-Za-z0-9-]{8,}", source):
            raise ValueError("Account or credential literal prohibited in dashboard: " + path.name)
        run([node, "--check", str(path)])
    npm = shutil.which("npm.cmd") or shutil.which("npm")
    if not npm:
        raise ValueError("npm is required to validate locked dashboard dependencies")
    run([npm, "ci", "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=directory)
    node_metadata = node_packaging.capture(ROOT)
    tests = sorted((directory / "test").glob("*.cjs"))
    if not tests:
        raise ValueError("Dashboard security boundary tests are required")
    result = run([node, "--no-experimental-require-module", "--test", "--test-reporter=tap", *map(str, tests)], cwd=directory)
    node_packaging.verify_tree(ROOT, node_metadata)
    return directory, test_result("dashboard-lambda-node24", result, node=True), node_metadata


def dashboard_archive(directory, node_metadata):
    entries = {}
    for path in directory.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(directory)
        if not node_packaging.archive_member(relative.as_posix()):
            continue
        if path.is_symlink():
            continue
        entries[relative.as_posix()] = path.read_bytes()
    node_packaging.verify_entries(ROOT, entries, node_metadata)
    return deterministic_zip(OUT / "dashboard.zip", entries)


def check_templates():
    run([sys.executable, "-B", str(ROOT / "infrastructure/build_templates.py")])
    control_builder = ROOT / "infrastructure/control_plane_builder.py"
    if not control_builder.is_file():
        raise ValueError("Missing complete control-plane builder")
    run([sys.executable, "-B", str(control_builder)])
    templates = sorted((ROOT / "infrastructure").glob("*.template.json"))
    if not any(p.name == "control_plane.template.json" for p in templates):
        raise ValueError("Control-plane template was not generated")
    for path in templates:
        template = json.loads(path.read_text(encoding="utf-8"))
        serialized = json.dumps(template)
        if re.search(r"(?<![0-9])[0-9]{12}(?![0-9])", serialized) or "WHSVulnWeb" in serialized:
            raise ValueError("Nonportable asset in template: " + path.name)
        if any(resource["Type"] in {"AWS::EC2::Instance", "AWS::ECS::Service", "AWS::CloudFront::Distribution"}
               for resource in template["Resources"].values()):
            raise ValueError("New deployment must not provision a workload: " + path.name)
        for resource in template["Resources"].values():
            if resource["Type"] != "AWS::Lambda::Function":
                continue
            handler = resource["Properties"]["Handler"]
            if isinstance(handler, dict) and "Ref" in handler:
                handler = template["Parameters"][handler["Ref"]].get("Default")
            if not isinstance(handler, str):
                raise ValueError("Missing deterministic handler contract: " + path.name)
            module, function = handler.rsplit(".", 1)
            if module.startswith("runtime."):
                code = ROOT / (module.replace(".", "/") + ".py")
                if not code.is_file() or not any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function for node in ast.walk(ast.parse(code.read_text(encoding="utf-8")))):
                    raise ValueError("Unimplemented runtime handler: " + handler)
            elif not (ROOT / "dashboard" / (module + ".js")).is_file():
                raise ValueError("Unimplemented dashboard handler: " + handler)
    lint = "not_available"
    if importlib.util.find_spec("cfnlint"):
        run([sys.executable, "-c", "from cfnlint.runner import main; main()", "--non-zero-exit-code", "error", "-t", *map(str, templates)])
        lint = "passed"
    return templates, lint


def build(build_archives):
    paths = module_inventory()
    sdk_entries, sdk_metadata = sdk_packaging.prepare(ROOT, run)
    dashboard, dashboard_result, node_metadata = dashboard_check()
    templates, lint = check_templates()
    results = [dashboard_result]
    for folder in ["infrastructure", "tests", "tools"]:
        output = run([sys.executable, "-B", "-m", "unittest", "discover", "-s", folder, "-p", "test_*.py"])
        results.append(test_result(folder, output))
    run([sys.executable, "-B", str(ROOT / "service-onboarding/onboard.py"), "--config",
         str(ROOT / "service-onboarding/installation.example.json"), "--validate"])
    manifest = {"schema_version": "1.0", "account_neutral": True, "contains_workload": False,
                "runtime": "python3.13", "dashboard_runtime": "nodejs24.x", "cfn_lint": lint,
                "validation": "passed", "local_test_results": results, "runtime_sdk": sdk_metadata, "node_dependencies": node_metadata,
                "artifacts": {}, "templates": {}, "source_files": {},
                "unsupported": ["WAF Classic", "Firewall Manager ownership", "shared ACL without reviewed isolation",
                                "non-HTTP resources for direct WAF response", "non-commercial AWS partitions"]}
    for path in paths:
        manifest["source_files"]["runtime/" + path.name] = digest(path.read_bytes())["sha256"]
    for path in [ROOT / "build_release.py", ROOT / "install.py", ROOT / "sdk_packaging.py", ROOT / "node_packaging.py", ROOT / sdk_packaging.LOCK_NAME,
                 *(ROOT / "service-onboarding").glob("*"), *dashboard.glob("*")]:
        if path.is_file() and path.suffix in {".py", ".json", ".js", ".txt", ".html", ".css"}:
            manifest["source_files"][path.relative_to(ROOT).as_posix()] = digest(path.read_bytes())["sha256"]
    for path in templates:
        manifest["templates"][path.name] = digest(path.read_bytes())
    if build_archives:
        manifest["artifacts"]["runtime.zip"] = runtime_archive(paths, sdk_entries)
        sdk_packaging.verify_manifest(ROOT, OUT / "runtime.zip", sdk_metadata)
        manifest["artifacts"]["dashboard.zip"] = dashboard_archive(dashboard, node_metadata)
        node_packaging.verify_manifest(ROOT, OUT / "dashboard.zip", node_metadata)
    else:
        manifest["artifacts_built"] = False
    identity = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest["release_id"] = hashlib.sha256(identity).hexdigest()
    (ROOT / "build/test-validation-result.json").write_text(json.dumps({"release_id": manifest["release_id"], "success": True,
        "suites": results, "sdk_capabilities": sdk_metadata["capabilities"], "cfn_lint": lint}, indent=2) + "\n", encoding="utf-8")
    OUT.mkdir(parents=True, exist_ok=True)
    filename = "manifest.json" if build_archives else "check-result.json"
    (OUT / filename).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return {"status": "BUILT" if build_archives else "CHECKED", "release_id": manifest["release_id"],
            "manifest": str(OUT / filename), "cfn_lint": lint, "aws_deployed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--build", action="store_true")
    args = parser.parse_args()
    print(json.dumps(build(args.build)))


if __name__ == "__main__":
    main()
