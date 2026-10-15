import copy
import importlib.util
import json
from pathlib import Path
import re
from types import SimpleNamespace
import unittest

from build_templates import foundation, regional_ingress, waf_bundle


def role_statements(resources, role):
    statements = [item for policy in resources[role]["Properties"].get("Policies", [])
                  for item in policy["PolicyDocument"]["Statement"]]
    for resource in resources.values():
        if resource["Type"] == "AWS::IAM::Policy" and {"Ref": role} in resource["Properties"]["Roles"]:
            statements.extend(resource["Properties"]["PolicyDocument"]["Statement"])
    return statements

ONBOARD = Path(__file__).resolve().parents[1] / "service-onboarding"
spec = importlib.util.spec_from_file_location("onboard", ONBOARD / "onboard.py")
onboard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(onboard)


class InfrastructureTests(unittest.TestCase):
    def test_reference_graph_has_no_unknown_resources_or_cycles(self):
        for template in [foundation(), regional_ingress(), waf_bundle("REGIONAL"), waf_bundle("CLOUDFRONT")]:
            resources = template["Resources"]
            self.assertFalse(set(resources) & set(template.get("Parameters", {})), "Parameter/resource names must be unique")
            symbols = set(resources) | set(template.get("Parameters", {}))
            edges = {name: set() for name in resources}

            def walk(value, owner):
                if isinstance(value, list):
                    for item in value:
                        walk(item, owner)
                elif isinstance(value, dict):
                    if "Ref" in value:
                        target = value["Ref"]
                        self.assertTrue(target in symbols or target.startswith("AWS::"), target)
                        if target in resources:
                            edges[owner].add(target)
                    if "Fn::GetAtt" in value:
                        target = value["Fn::GetAtt"][0]
                        self.assertIn(target, resources)
                        edges[owner].add(target)
                    if "Fn::Sub" in value:
                        raw = value["Fn::Sub"]
                        raw = raw[0] if isinstance(raw, list) else raw
                        for token in re.findall(r"\$\{([^}]+)\}", raw):
                            target = token.split(".")[0]
                            self.assertTrue(target in symbols or target.startswith("AWS::"), target)
                            if target in resources:
                                edges[owner].add(target)
                    for item in value.values():
                        walk(item, owner)
            for owner, value in resources.items():
                walk(value, owner)
            done = set()
            def visit(node, chain):
                self.assertNotIn(node, chain, "Dependency cycle: " + str(chain + [node]))
                if node in done:
                    return
                for target in edges[node]:
                    visit(target, chain + [node])
                done.add(node)
            for name in resources:
                visit(name, [])

    def test_foundation_is_account_neutral_and_contains_no_application(self):
        t = foundation()
        content = json.dumps(t)
        self.assertFalse(re.search(r"\b[0-9]{12}\b", content))
        self.assertNotIn("WHS", content)
        self.assertNotIn("vuln", content.lower())
        self.assertNotIn("AWS::EC2::Instance", content)
        self.assertNotIn("AWS::ECS::Service", content)

    def test_state_backups_cognito_and_sessions_are_protected(self):
        r = foundation()["Resources"]
        for name in ["ServiceRegistry", "CasesTable", "ExpectedActivityTable", "DashboardSessionTable", "ResponseOperationsTable"]:
            self.assertEqual(r[name]["DeletionPolicy"], "Retain")
            self.assertTrue(r[name]["Properties"]["DeletionProtectionEnabled"])
            self.assertTrue(r[name]["Properties"]["PointInTimeRecoverySpecification"]["PointInTimeRecoveryEnabled"])
        self.assertNotIn("TimeToLiveSpecification", r["ResponseOperationsTable"]["Properties"])
        self.assertEqual(r["DashboardSessionTable"]["Properties"]["KeySchema"][0]["AttributeName"], "session_id")
        self.assertEqual(r["AdminUserPool"]["Properties"]["MfaConfiguration"], "ON")
        self.assertTrue(r["AdminUserPool"]["Properties"]["AdminCreateUserConfig"]["AllowAdminCreateUserOnly"])
        self.assertFalse(r["AdminClient"]["Properties"]["GenerateSecret"])
        self.assertEqual(r["AdminClient"]["Properties"]["AllowedOAuthFlows"], ["code"])

    def test_discovery_and_alarms_have_failure_routes(self):
        template = foundation()
        r = template["Resources"]
        self.assertEqual(template["Parameters"]["AutomaticOnboardingEnabled"]["Default"], "false")
        for name in ["DiscoverySchedule", "DiscoveryResourceEvent"]:
            target = r[name]["Properties"]["Targets"][0]
            self.assertIn("DeadLetterConfig", target)
            self.assertGreater(target["RetryPolicy"]["MaximumRetryAttempts"], 0)
            self.assertEqual(r[name]["Properties"]["State"], {"Fn::If": ["AutomaticOnboarding", "ENABLED", "DISABLED"]})
        alarms = [v for v in r.values() if v["Type"] == "AWS::CloudWatch::Alarm"]
        self.assertGreaterEqual(len(alarms), 3)
        relayed = set(r["IngressAlarmStateChangeRelay"]["Properties"]["EventPattern"]["detail"]["alarmName"][index]["Ref"] for index in range(4))
        self.assertTrue(all(value["Properties"].get("AlarmActions") or name in relayed
            for name, value in r.items() if value["Type"] == "AWS::CloudWatch::Alarm"))

    def test_runtime_interface_and_artifact_version_are_bound(self):
        r = foundation()["Resources"]
        env = r["DiscoveryFunction"]["Properties"]["Environment"]["Variables"]
        self.assertEqual(env["ENVIRONMENT"], {"Ref": "Environment"})
        self.assertEqual(env["CONTROL_PLANE_REGION"], {"Ref": "AWS::Region"})
        self.assertIn("S3ObjectVersion", r["SecurityLogIngressFunction"]["Properties"]["Code"])
        perms = json.dumps(r["DiscoverySdkPolicy"])
        self.assertIn("wafv2:CheckCapacity", perms)
        self.assertIn("/operations/onboarding/*", perms)
        self.assertEqual(r["DashboardFunction"]["Properties"]["Environment"]["Variables"]["REPORT_BUCKET"], {"Ref": "AuditBucket"})

    def test_ingress_cross_region_batch_processing_has_five_minute_budget(self):
        for template in [foundation(), regional_ingress()]:
            function = template["Resources"]["SecurityLogIngressFunction"]["Properties"]
            self.assertEqual(function["Timeout"], 300)
            self.assertEqual(function["Handler"], "runtime.ingest.handler")
            self.assertIn("LEASE_TABLE", function["Environment"]["Variables"])
            role = role_statements(template["Resources"], "SecurityLogIngressRole")
            permissions = [item for item in role if "dynamodb:BatchGetItem" in item["Action"]]
            self.assertEqual(len(permissions), 1)
            self.assertTrue({"dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"} <= set(permissions[0]["Action"]))
        functions = foundation()["Resources"]
        self.assertEqual(functions["DashboardFunction"]["Properties"]["Timeout"], 30)
        self.assertEqual(functions["DiscoveryFunction"]["Properties"]["Timeout"], 300)

    def test_ingress_async_failures_have_encrypted_private_queue_and_bounded_retries(self):
        for template in [foundation(), regional_ingress()]:
            resources = template["Resources"]
            queue = resources["SecurityLogIngressFailureQueue"]["Properties"]
            self.assertTrue(queue["SqsManagedSseEnabled"])
            self.assertEqual(queue["MessageRetentionPeriod"], 1209600)
            invocation = resources["SecurityLogIngressAsyncFailure"]["Properties"]
            self.assertEqual(set(resources["SecurityLogIngressAsyncFailure"]["DependsOn"]), {"SecurityLogIngressFailureDeliveryPolicy", "SecurityLogIngressFailureQueuePolicy"})
            self.assertEqual(invocation["Qualifier"], "$LATEST")
            self.assertEqual(invocation["MaximumRetryAttempts"], 2)
            self.assertEqual(invocation["MaximumEventAgeInSeconds"], 3600)
            self.assertEqual(invocation["DestinationConfig"]["OnFailure"]["Destination"], {"Fn::GetAtt": ["SecurityLogIngressFailureQueue", "Arn"]})
            role = role_statements(resources, "SecurityLogIngressRole")
            send = [item for item in role if item["Action"] == "sqs:SendMessage"]
            self.assertEqual([item["Resource"] for item in send], [{"Fn::GetAtt": ["SecurityLogIngressFailureQueue", "Arn"]}])
            deny = resources["SecurityLogIngressFailureQueuePolicy"]["Properties"]["PolicyDocument"]["Statement"][0]
            self.assertEqual(deny["Effect"], "Deny")
            self.assertEqual(deny["Condition"], {"Bool": {"aws:SecureTransport": "false"}})

    def test_ingress_alarm_relay_accepts_only_four_owned_local_alarms_and_exact_bus(self):
        for template in [foundation(), regional_ingress()]:
            resources = template["Resources"]
            rule = resources["IngressAlarmStateChangeRelay"]["Properties"]
            pattern = rule["EventPattern"]
            self.assertEqual(pattern["account"], [{"Ref": "AWS::AccountId"}])
            self.assertEqual(pattern["region"], [{"Ref": "AWS::Region"}])
            self.assertEqual(pattern["source"], ["aws.cloudwatch"])
            names = pattern["detail"]["alarmName"]
            self.assertEqual(len(names), 4)
            self.assertEqual(set(item["Ref"] for item in names), {"IngressErrorsAlarm", "IngressAsyncDroppedAlarm", "IngressDestinationFailuresAlarm", "IngressDlqDepthAlarm"})
            role = resources["IngressAlarmRelayRole"]["Properties"]
            trust = role["AssumeRolePolicyDocument"]["Statement"][0]
            self.assertEqual(trust["Principal"], {"Service": "events.amazonaws.com"})
            self.assertEqual(trust["Condition"]["StringEquals"]["aws:SourceAccount"], {"Ref": "AWS::AccountId"})
            policy = role["Policies"][0]["PolicyDocument"]["Statement"]
            self.assertEqual(len(policy), 1)
            self.assertEqual(policy[0]["Action"], "events:PutEvents")
            self.assertEqual(policy[0]["Resource"], rule["Targets"][0]["Arn"])
            self.assertEqual(rule["Targets"][0]["DeadLetterConfig"]["Arn"], {"Fn::GetAtt": ["IngressAlarmRelayFailureQueue", "Arn"]})
            self.assertNotIn("RetryPolicy", rule["Targets"][0])
            self.assertEqual(resources["IngressAlarmStateChangeRelay"]["DependsOn"], ["IngressAlarmRelayFailureQueuePolicy"])
            self.assertIn("KmsMasterKeyId", resources["IngressAlarmRelayFailureQueue"]["Properties"])
            dlq_metric = resources["IngressDlqDepthAlarm"]["Properties"]["Metrics"]
            self.assertEqual(len(dlq_metric), 5)
            event_metrics = [item["MetricStat"]["Metric"] for item in dlq_metric[1:] if item["MetricStat"]["Metric"]["Namespace"] == "AWS/Events"]
            self.assertEqual({item["MetricName"] for item in event_metrics}, {"FailedInvocations", "InvocationsFailedToBeSentToDlq"})
            self.assertTrue(all(len(item["Dimensions"]) == 1 and item["Dimensions"][0]["Name"] == "RuleName" for item in event_metrics))

    def test_ops_publisher_is_role_scoped_and_existing_cloudwatch_policy_is_preserved(self):
        resources = foundation()["Resources"]
        topics = resources["OpsTopicPolicy"]["Properties"]["PolicyDocument"]["Statement"]
        self.assertEqual(topics[0]["Principal"], {"Service": "cloudwatch.amazonaws.com"})
        self.assertTrue(all(isinstance(item.get("Sid"), str) and item["Sid"] for item in topics))
        self.assertEqual(len({item["Sid"] for item in topics}), len(topics))
        self.assertIn("aws:PrincipalArn", topics[1]["Condition"]["ArnEquals"])
        self.assertNotIn("SourceArn", json.dumps(topics[1]))
        key = resources["OpsKey"]["Properties"]["KeyPolicy"]["Statement"]
        publisher = [item for item in key if item.get("Condition", {}).get("ArnEquals", {}).get("aws:PrincipalArn")]
        self.assertEqual(len(publisher), 1)
        self.assertIn("kms:ViaService", publisher[0]["Condition"]["StringEquals"])
        self.assertNotIn("aws:SourceArn", json.dumps(publisher[0]))

    def test_ingress_sdk_reads_only_local_waf_logs_and_credentials_cannot_forge_receipts(self):
        for template in [foundation(), regional_ingress()]:
            resources = template["Resources"]
            sdk = resources["SecurityLogIngressSdkPolicy"]["Properties"]["PolicyDocument"]["Statement"]
            self.assertTrue(all(item["Condition"]["ArnEquals"]["lambda:SourceFunctionArn"] == {"Fn::GetAtt": ["SecurityLogIngressFunction", "Arn"]} for item in sdk))
            logs = [item for item in sdk if item["Action"] == "logs:FilterLogEvents"]
            self.assertEqual(len(logs), 1)
            self.assertEqual(logs[0]["Resource"], {"Fn::Sub": "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:aws-waf-logs-*"})
            backend = resources["SecurityLogIngressFailureDeliveryPolicy"]["Properties"]["PolicyDocument"]["Statement"]
            self.assertNotIn("lambda:SourceFunctionArn", json.dumps(backend))

    def test_discovery_eventbridge_and_async_dlq_use_cmk_without_backend_source_function_condition(self):
        resources = foundation()["Resources"]
        self.assertNotIn("SqsManagedSseEnabled", resources["DiscoveryDlq"]["Properties"])
        self.assertEqual(resources["DiscoveryDlq"]["Properties"]["KmsMasterKeyId"], {"Fn::GetAtt": ["DiscoveryDlqKey", "Arn"]})
        key_statement = resources["DiscoveryDlqKey"]["Properties"]["KeyPolicy"]["Statement"][1]
        self.assertEqual(key_statement["Fn::If"][0], "HasDiscoveryEventBridgeRules")
        self.assertEqual(key_statement["Fn::If"][1]["Condition"]["ArnEquals"]["aws:SourceArn"], {"Ref": "DiscoveryEventBridgeRuleArns"})
        self.assertNotIn("DiscoverySchedule", json.dumps(key_statement))
        self.assertIn("DiscoveryScheduleRuleArn", foundation()["Outputs"])
        self.assertIn("DiscoveryResourceEventRuleArn", foundation()["Outputs"])
        backend = resources["DiscoveryFailureDeliveryPolicy"]["Properties"]["PolicyDocument"]["Statement"]
        self.assertNotIn("lambda:SourceFunctionArn", json.dumps(backend))
        self.assertEqual(backend[1]["Resource"], {"Fn::GetAtt": ["DiscoveryDlqKey", "Arn"]})
        self.assertIn("DiscoveryAsyncDropped", resources)
        self.assertIn("DiscoveryDestinationFailures", resources)
        self.assertEqual(set(resources["DiscoveryAsyncFailure"]["DependsOn"]), {"DiscoveryFailureDeliveryPolicy", "DiscoveryDlqPolicy"})

    def test_discovery_sdk_credentials_are_scoped_to_the_source_function(self):
        resources = foundation()["Resources"]
        sdk = resources["DiscoverySdkPolicy"]["Properties"]["PolicyDocument"]["Statement"]
        self.assertTrue(all(item["Condition"]["ArnEquals"]["lambda:SourceFunctionArn"] == {"Fn::GetAtt": ["DiscoveryFunction", "Arn"]} for item in sdk))
        actions = json.dumps(sdk)
        self.assertIn("elasticloadbalancing:GetLoadBalancerWebACL", actions)
        self.assertIn("elasticloadbalancing:CreateWebACLAssociation", actions)
        self.assertIn("amplify:ListResourcesForWebACL", actions)

    def test_all_foundation_and_regional_sqs_policies_use_singleton_resource_arns(self):
        for template in [foundation(), regional_ingress()]:
            for name, row in template["Resources"].items():
                if row["Type"] != "AWS::SQS::QueuePolicy":
                    continue
                queues = row["Properties"]["Queues"]
                self.assertEqual(len(queues), 1, name)
                for entry in row["Properties"]["PolicyDocument"]["Statement"]:
                    self.assertEqual(entry["Resource"], {"Fn::GetAtt": [queues[0]["Ref"], "Arn"]}, name)

    def test_nonempty_principal_declarations_are_rejected_until_adapter_exists(self):
        config = json.loads((ONBOARD / "installation.example.json").read_text())
        config["principal_scopes"] = [{"principal_arn": "arn:aws:iam::123456789012:role/application", "actions": ["kms:Decrypt"],
            "resource_arns": ["arn:aws:kms:us-east-1:123456789012:key/example"]}]
        with self.assertRaisesRegex(ValueError, "adapter is not installed"):
            onboard.validate(config)

    def test_waf_modules_never_overwrite_external_association(self):
        for scope in ["REGIONAL", "CLOUDFRONT"]:
            t = waf_bundle(scope)
            self.assertFalse(any(x["Type"] == "AWS::WAFv2::WebACLAssociation" for x in t["Resources"].values()))
            self.assertFalse(any(x["Type"] == "AWS::CloudFront::Distribution" for x in t["Resources"].values()))
            self.assertEqual(t["Resources"]["WebAcl"]["Properties"]["Scope"], scope)
            fields = t["Resources"]["WafLogging"]["Properties"]["RedactedFields"]
            self.assertIn({"QueryString": {}}, fields)


class OnboardingTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((ONBOARD / "installation.example.json").read_text())

    def test_unknown_services_and_auto_https_origin_require_no_target_input(self):
        self.assertEqual(onboard.validate(self.config), self.config)
        self.assertNotIn("resource_arn", self.config)
        self.assertNotIn("dashboard_origin", self.config)

    def test_reject_arbitrary_target_and_insecure_origin(self):
        for patch in [{"resource_arn": "arn:aws:wafv2:example"}, {"dashboard_origin": "http://example.com"},
                      {"dashboard_origin": "https://example.com/path"}]:
            value = {**self.config, **patch}
            with self.assertRaises(ValueError):
                onboard.validate(value)

    def test_principal_scope_rejects_wildcard_and_cross_account(self):
        value = copy.deepcopy(self.config)
        value["account_id"] = "123456789012"
        value["principal_scopes"] = [{"principal_arn": "arn:aws:iam::123456789012:role/app",
            "actions": ["secretsmanager:GetSecretValue"], "resource_arns": ["arn:aws:secretsmanager:us-east-1:123456789012:secret:*"]}]
        with self.assertRaises(ValueError):
            onboard.validate(value)
        value["principal_scopes"][0]["resource_arns"] = ["arn:aws:secretsmanager:us-east-1:999999999999:secret:name-id"]
        with self.assertRaises(ValueError):
            onboard.validate(value)

    def test_safe_discovery_output_does_not_print_raw_header_or_secret(self):
        raw = {"status": "READY", "DistributionConfig": {"CustomHeaders": [{"HeaderValue": "private-origin"}]},
               "SecretString": "not-for-console", "candidates": [{"service_id": "customer-api", "resource_arn": "arn:aws:cloudfront::123456789012:distribution/EXAMPLE",
               "headers": {"authorization": "secret"}}]}
        result = onboard.safe_report(raw)
        self.assertNotIn("private-origin", json.dumps(result))
        self.assertNotIn("SecretString", json.dumps(result))
        self.assertEqual(result["candidates"][0]["service_id"], "customer-api")
        self.assertEqual(onboard.safe_report({"operation": "discover", "resources": [{"status": "CANDIDATE", "service_id": "customer-api"}]}),
            {"operation": "discover", "resources": [{"status": "CANDIDATE", "service_id": "customer-api"}]})

    def test_discovery_rejects_account_scope_and_automation_mismatches_before_invocation(self):
        args = SimpleNamespace(profile="default", region="us-east-1", allow_all_supported=False, apply=False, confirm_installation_id=None)
        config = copy.deepcopy(self.config)
        config["account_id"] = "123456789012"
        calls = []
        def wrong_account(*arguments, **kwargs):
            calls.append(arguments)
            return {"Account": "999999999999"}
        with self.assertRaisesRegex(ValueError, "Wrong AWS account"):
            onboard.discover(config, args, call=wrong_account)
        self.assertEqual(len(calls), 1)
        config.pop("account_id")
        config["discovery"]["scope"] = "all-supported"
        with self.assertRaisesRegex(ValueError, "allow-all-supported"):
            onboard.discover(config, args, call=wrong_account)
        self.assertEqual(len(calls), 2)
        config["discovery"]["scope"] = "tagged"
        args.apply = True
        with self.assertRaisesRegex(ValueError, "confirm-installation-id"):
            onboard.discover(config, args, call=wrong_account)
        self.assertEqual(len(calls), 3)

    def test_render_carries_scope_and_provenance_configuration(self):
        args = SimpleNamespace(code_bucket="artifact-bucket", code_key="sha/runtime.zip", code_version="version",
            dashboard_code_bucket="artifact-bucket", dashboard_code_key="sha/dashboard.zip", dashboard_code_version="version",
            dashboard_role=None, handler="runtime.discovery.handler", runtime="python3.13", dashboard_handler="lambda.handler")
        values = {x["ParameterKey"]: x["ParameterValue"] for x in onboard.render_parameters(self.config, args)}
        self.assertEqual(values["InstallationScope"], "tagged")
        self.assertEqual(values["DashboardOrigin"], "")
        self.assertEqual(values["PrincipalScopesJson"], "[]")
        self.assertEqual(values["AllowedActions"], "monitor,block_ip")


if __name__ == "__main__":
    unittest.main()
