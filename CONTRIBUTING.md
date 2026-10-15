# Contributing

Open an issue for a bug or proposed behavior change using synthetic examples. For security findings, follow [SECURITY.md](SECURITY.md). Keep company installation settings, real resource identifiers and production evidence outside the repository.

Use Python 3.13 and Node.js 24 LTS. Install the locked Python runtime dependencies and onboarding validation dependency, then build locally:

```sh
python -m pip install --only-binary=:all: --require-hashes -r runtime-requirements.lock.txt
python -m pip install jsonschema==4.25.1 cfn-lint==1.57.2
python -B tools/publication_check.py --root .
python -B -m unittest discover -s tools -p 'test_*.py'
python -B build_release.py --build
python -B tools/pack_release.py
```

The build runs infrastructure, runtime, installer and dashboard tests, checks SDK capabilities and packages locked dependencies. It does not call AWS. `validate_cloud.py`, `validate_http.py`, `validate_operations.py` and `validate_receipts.py` are optional company acceptance tools that call the company's AWS installation; CI does not run them.

Keep changes focused. Explain the problem, resulting behavior, meaningful validation and any operational limits in a pull request. Changes to WAF response, approval, identity, service binding or publication evidence need tests proving that unauthorized and ambiguous inputs cannot perform a write or claim a successful action.

Commit source, generated neutral templates and dependency lockfiles when relevant. Do not commit `build/`, `dist/`, `node_modules/`, environments, logs, company configuration or acceptance results. Keep synthetic credentials visibly fake and use reserved example domains and documented example accounts.

Update [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) when dependencies change. Review upstream license metadata and retain original dependency license/notice files in packages. GitHub Actions must use reviewed full commit SHAs; the default workflow has read-only repository permissions and no AWS keys or OIDC deployment role.

The project's original code is licensed under Apache-2.0; see `LICENSE`. Third-party dependencies retain their own licenses and notices.
