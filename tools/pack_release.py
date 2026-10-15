"""Package a company-independent deployment bundle, excluding local settings."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'dist' / 'enterprise-security-platform-deploy.zip'
spec = importlib.util.spec_from_file_location('public_source_guard', ROOT / 'tools/publication_check.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
node_spec = importlib.util.spec_from_file_location('public_node_packaging', ROOT / 'node_packaging.py')
node_packaging = importlib.util.module_from_spec(node_spec)
node_spec.loader.exec_module(node_packaging)


def verify_terraform_sources(files, manifest):
    names = {name for name in files if name.startswith('terraform/')}
    recorded = {name for name in manifest.get('source_files', {}) if name.startswith('terraform/')}
    if not names or names != recorded or 'terraform/.terraform.lock.hcl' not in names:
        raise ValueError('TERRAFORM_SOURCE_MANIFEST_REQUIRED')
    for name in names:
        if hashlib.sha256(files[name].read_bytes()).hexdigest() != manifest['source_files'][name]:
            raise ValueError('TERRAFORM_SOURCE_HASH_MISMATCH')


def main():
    subprocess.run([sys.executable, '-B', str(ROOT / 'tools/publication_check.py'), '--root', str(ROOT)], check=True)
    manifest_path = ROOT / 'build/release/manifest.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if manifest.get('validation') != 'passed' or manifest.get('account_neutral') is not True or manifest.get('contains_workload') is not False:
        raise ValueError('VALIDATED_ACCOUNT_NEUTRAL_RELEASE_REQUIRED')
    files = {path.relative_to(ROOT).as_posix(): path for path in ROOT.rglob('*')
             if path.is_file() and not path.is_symlink() and guard.allowed_source(path.relative_to(ROOT).as_posix())}
    verify_terraform_sources(files, manifest)
    for name in ('runtime.zip', 'dashboard.zip'):
        path = ROOT / 'build/release' / name
        if hashlib.sha256(path.read_bytes()).hexdigest() != manifest['artifacts'][name]['sha256']:
            raise ValueError('RELEASE_ARTIFACT_HASH_MISMATCH')
        files['build/release/' + name] = path
    node_packaging.verify_manifest(ROOT, ROOT / 'build/release/dashboard.zip', manifest.get('node_dependencies', {}))
    files['build/release/manifest.json'] = manifest_path
    result_path = ROOT / 'build/test-validation-result.json'
    tests = json.loads(result_path.read_text(encoding='utf-8'))
    if tests.get('success') is not True or tests.get('release_id') != manifest['release_id']:
        raise ValueError('MATCHING_TEST_RESULT_REQUIRED')
    files['build/test-validation-result.json'] = result_path
    for name, expected in manifest['source_files'].items():
        if name not in files or hashlib.sha256(files[name].read_bytes()).hexdigest() != expected:
            raise ValueError('SOURCE_HASH_MISMATCH')
    for name, expected in manifest['templates'].items():
        path = files.get('infrastructure/' + name)
        if path is None or hashlib.sha256(path.read_bytes()).hexdigest() != expected['sha256']:
            raise ValueError('TEMPLATE_HASH_MISMATCH')
    OUT.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(OUT, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, path in sorted(files.items()):
            info = zipfile.ZipInfo('enterprise-security-platform/' + name, (2020, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())
    subprocess.run([sys.executable, '-B', str(ROOT / 'tools/publication_check.py'), '--root', str(ROOT), '--archive', str(OUT)], check=True)
    checksum = hashlib.sha256(OUT.read_bytes()).hexdigest()
    OUT.with_suffix('.zip.sha256').write_text(checksum + '  ' + OUT.name + '\n', encoding='utf-8')
    print(json.dumps({'status': 'PUBLIC_DEPLOYMENT_BUNDLE_CREATED', 'release_id': manifest['release_id'],
                      'archive': OUT.name, 'sha256': checksum, 'files': len(files)}))


if __name__ == '__main__':
    main()
