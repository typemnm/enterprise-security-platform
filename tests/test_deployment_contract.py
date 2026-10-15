"""A Terraform output file cannot authorize operations on arbitrary resources."""
import copy
import argparse
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("deployment_contract_tests", ROOT / "service-onboarding/deployment_contract.py")
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)
ACCOUNT, REGION, NAME = "123456789012", "ap-northeast-2", "security-company"
TAGS = {"ManagedBy": "enterprise-security", "InstallationId": NAME}
DIGEST = "a" * 43 + "="


def deployment():
    out = {"InstallationId": NAME, "AuditBucketName": "security-owned-audit", "SecurityEventBusName": "security-bus",
           "SecurityEventBusArn": f"arn:aws:events:{REGION}:{ACCOUNT}:event-bus/security-bus",
           "PipelineStateMachineArn": f"arn:aws:states:{REGION}:{ACCOUNT}:stateMachine:{NAME}-governance-pipeline",
           "CognitoUserPoolId": REGION + "_Pool123", "CognitoClientId": "client123",
           "DashboardUrl": "https://api123" + f".execute-api.{REGION}.amazonaws.com"}
    out["OidcIssuer"] = f"https://cognito-idp.{REGION}.amazonaws.com/{out['CognitoUserPoolId']}"
    out["DashboardRedirectUri"] = out["DashboardUrl"] + "/auth/callback"
    for stem in contract.TABLES:
        out[stem + "TableName"] = NAME + "-" + stem.lower()
        out[stem + "TableArn"] = f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{out[stem + 'TableName']}"
    out.update(ReceiptTableName=out["PublicationReceiptsTableName"], ReceiptTableArn=out["PublicationReceiptsTableArn"])
    for field in contract.FUNCTIONS:
        suffix = field.removesuffix("FunctionArn").lower()
        out[field] = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{NAME}-{suffix}" + ("" if field in {"DiscoveryFunctionArn", "DashboardFunctionArn"} else ":live")
    ingress = {r: f"arn:aws:lambda:{r}:{ACCOUNT}:function:{NAME}-ingress-{r}" for r in (REGION, "us-east-1")}
    out["SecurityLogIngressArn"] = ingress[REGION]
    out["NotificationQueueUrl"] = f"https://sqs.{REGION}.amazonaws.com/{ACCOUNT}/{NAME}-notifications"
    out["NotificationQueueArn"] = f"arn:aws:sqs:{REGION}:{ACCOUNT}:{NAME}-notifications"
    for field in ("DiscoveryScheduleRuleArn", "DiscoveryResourceEventRuleArn"):
        out[field] = f"arn:aws:events:{REGION}:{ACCOUNT}:rule/{NAME}-{field.lower()}"
    return {"deployment": {"sensitive": False, "value": {"schema_version": "2.0", "deployment_method": "terraform",
        "installation_id": NAME, "account_id": ACCOUNT, "control_plane_region": REGION, "release_id": "a" * 64,
        "automatic_onboarding_enabled": True, "default_dry_run": True, "outputs": out, "ingress_arns": ingress}}}


class LiveAws:
    """Metadata comes from an independent live snapshot, not the supplied file."""
    def __init__(self, document):
        value = copy.deepcopy(document["deployment"]["value"])
        self.out, self.ingress = value["outputs"], value["ingress_arns"]
        self.calls, self.account, self.bad_tag, self.bad_api, self.bad_alias, self.bad_pool = [], ACCOUNT, None, False, False, False
        self.functions = {}
        for field, handler in contract.FUNCTIONS.items():
            arn = self.out[field]
            self.functions[arn] = {"FunctionArn": arn.rsplit(":", 1)[0] if arn.endswith(":live") else arn,
                "State": "Active", "Version": "7" if arn.endswith(":live") else "$LATEST", "Handler": handler,
                "CodeSha256": DIGEST, "Role": f"arn:aws:iam::{ACCOUNT}:role/{NAME}-role", "Environment": {}}
        discovery = self.functions[self.out["DiscoveryFunctionArn"]]["Environment"]
        discovery.update(EXPECTED_ACCOUNT=ACCOUNT, INSTALLATION_ID=NAME, CONTROL_PLANE_REGION=REGION,
            REGISTRY_TABLE=self.out["RegistryTableName"], LEASE_TABLE=self.out["LeaseTableName"], AUDIT_BUCKET=self.out["AuditBucketName"],
            EVENT_BUS_ARN=self.out["SecurityEventBusArn"], INGRESS_ARNS_JSON=json.dumps(self.ingress), ENVIRONMENT="prod",
            INSTALLATION_SCOPE="tagged", RESPONSE_MODE="observe", DISCOVERY_REGIONS=REGION, ALLOWED_ACTIONS="monitor,block_ip")
        pipeline = self.functions[self.out["SignalIngressFunctionArn"]]["Environment"]
        pipeline.update(EXPECTED_ACCOUNT=ACCOUNT, REGISTRY_TABLE=self.out["RegistryTableName"], CASES_TABLE=self.out["CasesTableName"],
            OPERATIONS_TABLE=self.out["ResponseOperationsTableName"], LEASE_TABLE=self.out["LeaseTableName"],
            PIPELINE_STATE_MACHINE_ARN=self.out["PipelineStateMachineArn"], DEFAULT_DRY_RUN="true", MODEL_ARN="")
        self.functions[self.out["NotifierFunctionArn"]]["Environment"].update(QUEUE_URL=self.out["NotificationQueueUrl"],
            REGISTRY_TABLE=self.out["RegistryTableName"], CASES_TABLE=self.out["CasesTableName"],
            SLACK_SECRET_ARN="", SLACK_CHANNEL_ID="", NOTIFICATIONS_ENABLED="false")
        self.functions[self.out["DashboardFunctionArn"]]["Environment"].update(PUBLIC_ORIGIN=self.out["DashboardUrl"],
            OIDC_ISSUER=self.out["OidcIssuer"], OIDC_CLIENT_ID=self.out["CognitoClientId"], OIDC_REDIRECT_URI=self.out["DashboardRedirectUri"],
            SESSION_TABLE=self.out["DashboardSessionTableName"], SERVICE_REGISTRY_TABLE=self.out["RegistryTableName"],
            CASES_TABLE=self.out["CasesTableName"], APPROVE_FUNCTION_NAME=self.out["ApprovalFunctionArn"])
        for region, arn in self.ingress.items():
            self.functions[arn] = {"FunctionArn": arn, "State": "Active", "Version": "$LATEST", "Handler": "runtime.ingest.handler", "CodeSha256": DIGEST,
                "Role": f"arn:aws:iam::{ACCOUNT}:role/{NAME}-ingress-role", "Environment": {"EXPECTED_ACCOUNT": ACCOUNT, "CONTROL_PLANE_REGION": REGION,
                    "INSTALLATION_ID": NAME, "REGISTRY_TABLE": self.out["RegistryTableName"], "LEASE_TABLE": self.out["LeaseTableName"],
                    "CASES_TABLE": self.out["CasesTableName"], "EVENT_BUS_ARN": self.out["SecurityEventBusArn"], "AUDIT_BUCKET": self.out["AuditBucketName"], "ENVIRONMENT": "prod"}}

    def tags(self, service):
        return {} if self.bad_tag == service else copy.deepcopy(TAGS)

    def __call__(self, *args, profile, region):
        self.calls.append(args)
        service, action = args[:2]
        value = lambda field: args[args.index(field) + 1]
        tags = self.tags(service)
        if (service, action) == ("sts", "get-caller-identity"):
            return {"Account": self.account, "Arn": f"arn:aws:iam::{self.account}:role/Operator"}
        if (service, action) == ("dynamodb", "describe-table"):
            return {"TableArn": f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{value('--table-name')}", "TableStatus": "ACTIVE"}
        if action in {"list-tags-of-resource", "list-tags-for-resource", "list-tags", "list-queue-tags"}:
            return {"Tags": tags} if service not in {"stepfunctions"} else {"tags": [{"key": k, "value": v} for k, v in tags.items()]}
        if (service, action) == ("lambda", "get-function-configuration"):
            return copy.deepcopy(self.functions[value("--function-name")])
        if (service, action) == ("lambda", "get-alias"):
            return {"AliasArn": value("--function-name") + ":live", "FunctionVersion": "8" if self.bad_alias else "7"}
        if (service, action) == ("iam", "get-role"):
            return {"Arn": f"arn:aws:iam::{ACCOUNT}:role/{value('--role-name')}", "Tags": [{"Key": k, "Value": v} for k, v in tags.items()]}
        if (service, action) == ("stepfunctions", "describe-state-machine"):
            return {"stateMachineArn": self.out["PipelineStateMachineArn"], "status": "ACTIVE"}
        if (service, action) == ("cognito-idp", "describe-user-pool"):
            return {"Id": self.out["CognitoUserPoolId"], "Arn": f"arn:aws:cognito-idp:{REGION}:{ACCOUNT}:userpool/{self.out['CognitoUserPoolId']}", "UserPoolTags": tags}
        if (service, action) == ("cognito-idp", "describe-user-pool-client"):
            return {"UserPoolId": self.out["CognitoUserPoolId"], "ClientId": "foreign" if self.bad_pool else self.out["CognitoClientId"],
                    "CallbackURLs": [self.out["DashboardRedirectUri"]], "AllowedOAuthFlows": ["code"]}
        if (service, action) == ("apigatewayv2", "get-api"):
            return {"ApiId": value("--api-id"), "ProtocolType": "HTTP", "ApiEndpoint": self.out["DashboardUrl"], "Tags": tags}
        if (service, action) == ("apigatewayv2", "get-integrations"):
            return {"Items": [{"IntegrationType": "AWS_PROXY", "IntegrationUri": "foreign" if self.bad_api else self.out["DashboardFunctionArn"]}]}
        if (service, action) == ("sqs", "get-queue-attributes"):
            return {"Attributes": {"QueueArn": self.out["NotificationQueueArn"]}}
        if (service, action) == ("events", "describe-rule"):
            return {"Arn": f"arn:aws:events:{REGION}:{ACCOUNT}:rule/{value('--name')}", "Name": value("--name"), "EventBusName": "default", "State": "ENABLED"}
        if (service, action) == ("events", "list-targets-by-rule"):
            return {"Targets": [{"Arn": self.out["DiscoveryFunctionArn"]}]}
        raise AssertionError("Unexpected AWS operation: " + str(args[:2]))


class TerraformContractTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "outputs.json"
        self.document = deployment()
        self.aws = LiveAws(self.document)

    def resolve(self, **kwargs):
        self.path.write_text(json.dumps(self.document), encoding="utf-8")
        return contract.resolve_terraform(self.path, installation_id=NAME, profile="company", region=REGION, call=self.aws, **kwargs)

    def test_live_scope_bindings_verify_without_any_cloudformation_stack(self):
        result = self.resolve(account_id=ACCOUNT)
        self.assertEqual(result.foundation_parameters["AllowedActions"], "monitor,block_ip")
        self.assertEqual(result.foundation_parameters["AutomaticOnboardingEnabled"], "true")
        self.assertEqual(result.governance_parameters["RuntimeCodeSha256"], DIGEST)
        self.assertEqual(result.governance_parameters["DefaultDryRun"], "true")
        self.assertFalse(any(row[0] in {"cloudformation", "secretsmanager"} for row in self.aws.calls))
        self.assertFalse(any(row[1] in {"invoke", "update-item", "update-ip-set", "delete-ip-set"} for row in self.aws.calls))
        self.assertTrue(all("--query" in row for row in self.aws.calls if row[:2] == ("lambda", "get-function-configuration")))

    def test_foreign_sts_account_stops_before_resource_reads(self):
        self.aws.account = "999999999999"
        with self.assertRaisesRegex(contract.DeploymentError, "STS_ACCOUNT"):
            self.resolve()
        self.assertEqual(len(self.aws.calls), 1)

    def test_different_requested_identity_is_rejected_before_aws(self):
        with self.assertRaisesRegex(contract.DeploymentError, "IDENTITY_MISMATCH"):
            self.resolve(account_id="999999999999")
        self.assertEqual(self.aws.calls, [])

    def test_file_cannot_redirect_arn_to_foreign_account(self):
        self.document["deployment"]["value"]["outputs"]["RegistryTableArn"] = f"arn:aws:dynamodb:{REGION}:999999999999:table/foreign"
        with self.assertRaisesRegex(contract.DeploymentError, "OUTPUT_ARN_ACCOUNT"):
            self.resolve()
        self.assertEqual(len(self.aws.calls), 1)

    def test_same_account_other_table_still_needs_live_lambda_binding(self):
        out = self.document["deployment"]["value"]["outputs"]
        out.update(RegistryTableName="another-owned-table", RegistryTableArn=f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/another-owned-table")
        with self.assertRaisesRegex(contract.DeploymentError, "DISCOVERY_BINDING"):
            self.resolve()

    def test_installation_tags_required_for_each_trust_boundary(self):
        for service in ("dynamodb", "lambda", "iam", "stepfunctions", "cognito-idp", "apigatewayv2", "sqs", "events"):
            with self.subTest(service=service):
                self.aws = LiveAws(self.document)
                self.aws.bad_tag = service
                with self.assertRaisesRegex(contract.DeploymentError, "OWNERSHIP"):
                    self.resolve()

    def test_alias_client_and_api_bindings_are_live_not_output_claims(self):
        for field, error in (("bad_alias", "ALIAS"), ("bad_pool", "COGNITO_CLIENT"), ("bad_api", "API_BINDING")):
            with self.subTest(field=field):
                self.aws = LiveAws(self.document)
                setattr(self.aws, field, True)
                with self.assertRaisesRegex(contract.DeploymentError, error):
                    self.resolve()

    def test_file_policy_flags_cannot_override_live_runtime(self):
        for field, error in (("default_dry_run", "PIPELINE_BINDING"), ("automatic_onboarding_enabled", "AUTOMATIC_POLICY")):
            self.document = deployment()
            self.aws = LiveAws(self.document)
            self.document["deployment"]["value"][field] = False
            with self.subTest(field=field), self.assertRaisesRegex(contract.DeploymentError, error):
                self.resolve()

    def test_ingress_mapping_cannot_swap_region_or_own_runtime(self):
        self.document["deployment"]["value"]["ingress_arns"]["us-east-1"] = self.document["deployment"]["value"]["ingress_arns"][REGION]
        with self.assertRaisesRegex(contract.DeploymentError, "INGRESS_MAPPING"):
            self.resolve()

    def test_duplicate_fields_and_non_terraform_contract_fail_without_aws(self):
        self.path.write_text('{"deployment":{"value":{"schema_version":"2.0","schema_version":"1.0"}}}', encoding="utf-8")
        with self.assertRaisesRegex(contract.DeploymentError, "DUPLICATE"):
            contract.load(self.path)
        self.document["deployment"]["value"]["deployment_method"] = "cloudformation"
        with self.assertRaisesRegex(contract.DeploymentError, "UNSUPPORTED_DEPLOYMENT"):
            self.resolve()
        self.assertEqual(self.aws.calls, [])

    def test_direct_output_and_metadata_receipt_do_not_require_python_installer(self):
        self.path.write_text(json.dumps(self.document["deployment"]["value"]), encoding="utf-8")
        metadata = contract.installation_result(deployment_outputs=self.path)
        self.assertEqual(metadata["status"], "DEPLOYED")
        self.assertTrue(metadata["automatic_onboarding_enabled"])
        self.assertEqual(metadata["account_id"], ACCOUNT)
        self.assertEqual(self.aws.calls, [])
        result = contract.resolve_terraform(self.path, installation_id=NAME, profile="company", region=REGION, call=self.aws)
        self.assertEqual(result.outputs["InstallationId"], NAME)

    def test_operational_https_check_is_explicit_and_never_mutates_aws(self):
        import validate_http
        self.path.write_text(json.dumps(self.document), encoding="utf-8")
        metadata = contract.installation_result(deployment_outputs=self.path)
        with self.assertRaisesRegex(ValueError, "VALIDATION_ONLY_INSTALL"):
            validate_http.verify(metadata, profile="company", region=REGION, deployment_outputs=self.path)
        self.assertEqual(self.aws.calls, [])
        out = self.aws.out

        class Response:
            def __init__(self, status, headers=None, body=b""):
                self.status, self.headers, self.body = status, headers or {}, body
            def read(self, maximum): return self.body[:maximum]
            def close(self): pass

        class Opener:
            def open(self, request, timeout):
                url = request.full_url
                if url == out["DashboardUrl"] + "/healthz": return Response(200, body=b'{"ok":true}')
                if url == out["DashboardUrl"] + "/": return Response(302, {"Location": "/auth/login"})
                if url == out["DashboardUrl"] + "/auth/login":
                    query = urlencode({"response_type": "code", "code_challenge_method": "S256", "client_id": out["CognitoClientId"],
                        "redirect_uri": out["DashboardRedirectUri"], "state": "synthetic-state", "nonce": "synthetic-nonce", "code_challenge": "synthetic-challenge"})
                    return Response(302, {"Location": "https://synthetic.auth." + REGION + ".amazoncognito.com/oauth2/authorize?" + query,
                        "Set-Cookie": "synthetic=placeholder; HttpOnly; Secure; SameSite=Lax"})
                return Response(401)

        with patch.object(validate_http, "cli", self.aws), patch.object(validate_http, "build_opener", return_value=Opener()):
            result = validate_http.verify(metadata, profile="company", region=REGION, deployment_outputs=self.path, read_only_operational=True)
        self.assertEqual(result["status"], "HTTP_BOUNDARY_PASSED")
        self.assertEqual(len(result["checks"]), 9)
        self.assertEqual(result["installation_mode"], "READ_ONLY_OPERATIONAL")
        self.assertFalse(result["actual_response"])
        self.assertFalse(any(row[0] in {"cloudformation", "secretsmanager"} or row[1].startswith(("put-", "update-", "delete-", "invoke")) for row in self.aws.calls))

    def test_operational_http_flag_cannot_bypass_ownership_with_legacy_receipt(self):
        import validate_http
        with self.assertRaisesRegex(ValueError, "REQUIRES_TERRAFORM_OUTPUTS"):
            validate_http.verify({"status": "DEPLOYED"}, profile="company", region=REGION, read_only_operational=True)

    def test_discovery_uses_verified_terraform_function_and_sanitizes_response(self):
        spec = importlib.util.spec_from_file_location("terraform_onboard_test", ROOT / "service-onboarding/onboard.py")
        onboard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(onboard)
        self.path.write_text(json.dumps(self.document), encoding="utf-8")
        args = argparse.Namespace(profile="company", region=REGION, apply=False, allow_all_supported=False,
                                  confirm_installation_id=None, deployment_outputs=self.path)
        # Terraform sets have a stable lexical order; the company's JSON lists
        # may use a different order without changing their scope or authority.
        environment = self.aws.functions[self.aws.out["DiscoveryFunctionArn"]]["Environment"]
        environment["ALLOWED_ACTIONS"] = "block_ip,monitor"
        environment["DISCOVERY_REGIONS"] = ",".join(sorted([REGION, "us-east-1"]))
        config = {"installation_id": NAME, "account_id": ACCOUNT, "environment": "prod", "response_mode": "observe",
                  "allowed_actions": ["monitor", "block_ip"], "discovery": {"scope": "tagged", "regions": ["us-east-1", REGION]}}
        def cli(*arguments, **kwargs):
            if arguments[:2] == ("lambda", "invoke"):
                self.assertEqual(arguments[arguments.index("--function-name") + 1], self.aws.out["DiscoveryFunctionArn"])
                request = Path(arguments[arguments.index("--payload") + 1].removeprefix("fileb://"))
                self.assertEqual(json.loads(request.read_text()), {"operation": "discover"})
                Path(arguments[-1]).write_text(json.dumps({"count": 0, "resources": [], "credentials": "must-not-print"}), encoding="utf-8")
                return {"StatusCode": 200}
            return self.aws(*arguments, **kwargs)
        result = onboard.discover(config, args, call=cli)
        self.assertEqual(result["operation"], "discover")
        self.assertEqual(result["result"], {"count": 0, "resources": []})
        self.assertFalse(any(row[0] == "cloudformation" for row in self.aws.calls))

    def test_discovery_rejects_real_scope_changes_unknown_actions_and_duplicates(self):
        spec = importlib.util.spec_from_file_location("terraform_onboard_scope_tests", ROOT / "service-onboarding/onboard.py")
        onboard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(onboard)
        self.path.write_text(json.dumps(self.document), encoding="utf-8")
        args = argparse.Namespace(profile="company", region=REGION, apply=False, allow_all_supported=False,
                                  confirm_installation_id=None, deployment_outputs=self.path)
        for environment_field, actual, config_field, configured in (
                ("ALLOWED_ACTIONS", "monitor", "allowed_actions", ["monitor", "block_ip"]),
                ("DISCOVERY_REGIONS", REGION, "regions", [REGION, "us-east-1"]),
                ("ALLOWED_ACTIONS", "monitor,isolate", "allowed_actions", ["monitor", "block_ip"]),
                ("ALLOWED_ACTIONS", "monitor,monitor", "allowed_actions", ["monitor"]),
                ("DISCOVERY_REGIONS", REGION + "," + REGION, "regions", [REGION]),
                ("ALLOWED_ACTIONS", "monitor,block_ip", "allowed_actions", ["monitor", "monitor"]),
                ("ALLOWED_ACTIONS", "monitor,block_ip", "allowed_actions", ["monitor", "isolate"]),
                ("DISCOVERY_REGIONS", REGION, "regions", [REGION, REGION])):
            with self.subTest(field=environment_field, actual=actual, configured=configured):
                self.aws = LiveAws(self.document)
                self.aws.functions[self.aws.out["DiscoveryFunctionArn"]]["Environment"][environment_field] = actual
                config = {"installation_id": NAME, "account_id": ACCOUNT, "environment": "prod", "response_mode": "observe",
                          "allowed_actions": ["monitor", "block_ip"], "discovery": {"scope": "tagged", "regions": [REGION]}}
                if config_field == "regions": config["discovery"]["regions"] = configured
                else: config[config_field] = configured
                with self.assertRaisesRegex(ValueError, "scope differ|Invalid or duplicate"):
                    onboard.discover(config, args, call=self.aws)
                self.assertFalse(any(row[:2] == ("lambda", "invoke") for row in self.aws.calls))


if __name__ == "__main__":
    unittest.main()
