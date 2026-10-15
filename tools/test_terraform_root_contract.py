"""Exercise the current root input guards with real, offline Terraform plans.

Only the reviewed variables file is copied into an empty temporary module. No
AWS provider, company configuration, backend or credentials are used.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TERRAFORM = os.environ.get("TERRAFORM_BINARY") or shutil.which("terraform")


@unittest.skipUnless(TERRAFORM, "Terraform is required for native input contract tests")
class TerraformRootContractTests(unittest.TestCase):
    def test_rejects_unsupported_and_oversized_inputs_before_any_provider(self):
        fixtures = {
            "unsupported_principal": ('principal_scopes = [{ principal_arn = "unsupported" }]', "var.principal_scopes"),
            "empty_tag_key": ('exclude_tags = { "" = "value" }', "var.exclude_tags"),
            "oversized_tag_key": ('exclude_tags = { (join("", [for n in range(129) : "a"])) = "value" }', "var.exclude_tags"),
            "oversized_tag_value": ('exclude_tags = { sample = join("", [for n in range(257) : "a"]) }', "var.exclude_tags"),
            "too_many_tags": ('exclude_tags = { for n in range(51) : "tag${n}" => "x" }', "var.exclude_tags"),
            # Each tag meets the character limit; only its aggregate UTF-8 byte
            # budget fails. A character-count-only check would accept this.
            "utf8_tag_budget": ('exclude_tags = { for n in range(3) : "tag${n}" => join("", [for m in range(180) : "한"]) }', "var.exclude_tags"),
            "enforce_without_action": ('response_mode = "enforce"\n    acknowledge_enforcement = true\n    allowed_actions = ["monitor"]', "var.response_mode"),
        }
        global_variables = '\n'.join([
            'variables {', '  installation_id = "offline-platform"',
            '  account_id = "' + "0" * 12 + '"', '  control_region = "us-east-1"',
            '  discovery_regions = ["us-east-1"]', '  release_id = "' + "a" * 64 + '"', '}',
        ])
        runs = ['run "safe_defaults" {\n  command = plan\n}']
        for name, (inputs, failure) in fixtures.items():
            runs.append(f'run "{name}" {{\n  command = plan\n  variables {{\n    {inputs}\n  }}\n  expect_failures = [{failure}]\n}}')
        workspace = ROOT / "build/terraform-root-contract-tests"
        workspace.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=workspace) as directory:
            module = Path(directory)
            self.assertTrue(module.resolve().is_relative_to(workspace.resolve()))
            shutil.copyfile(ROOT / "terraform/variables.tf", module / "variables.tf")
            (module / "tests").mkdir()
            (module / "tests/inputs.tftest.hcl").write_text(global_variables + '\n\n' + '\n\n'.join(runs) + '\n', encoding="utf-8")
            environment = dict(os.environ, TF_IN_AUTOMATION="1")
            environment.pop("TF_DATA_DIR", None)
            environment.pop("TF_CLI_ARGS", None)
            for command in (["init", "-backend=false", "-input=false", "-no-color"], ["test", "-no-color"]):
                result = subprocess.run([TERRAFORM, *command], cwd=module, env=environment,
                                        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("8 passed, 0 failed", result.stdout)


if __name__ == "__main__":
    unittest.main()
