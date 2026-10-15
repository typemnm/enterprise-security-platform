"""Offline dependency, ownership, credential and deployment contract checks."""
import json
import re
import unittest
from control_plane_builder import template


class ControlPlaneTests(unittest.TestCase):
    def setUp(self):
        self.template = template()
        self.resources = self.template["Resources"]

    def test_resource_graph_contains_no_cycles_or_unknown_symbols(self):
        r = self.resources
        symbols = set(r) | set(self.template["Parameters"])
        graph = {name: set() for name in r}
        def walk(value, owner):
            if isinstance(value, list):
                for item in value:
                    walk(item, owner)
            elif isinstance(value, dict):
                if "Ref" in value:
                    name = value["Ref"]
                    self.assertTrue(name in symbols or name.startswith("AWS::"), name)
                    if name in r:
                        graph[owner].add(name)
                if "Fn::GetAtt" in value:
                    name = value["Fn::GetAtt"][0]
                    self.assertIn(name, r)
                    graph[owner].add(name)
                if "Fn::Sub" in value:
                    for token in re.findall(r"\$\{([^}]+)\}", value["Fn::Sub"]):
                        name = token.split(".")[0]
                        self.assertTrue(name in symbols or name.startswith("AWS::"), name)
                        if name in r:
                            graph[owner].add(name)
                for name in value.get("DependsOn", []):
                    self.assertIn(name, r)
                    graph[owner].add(name)
                for item in value.values():
                    walk(item, owner)
        for name, resource in r.items():
            walk(resource, name)
        seen = set()
        def visit(name, path):
            self.assertNotIn(name, path, "Cycle " + str(path + [name]))
            if name not in seen:
                for dependency in graph[name]:
                    visit(dependency, path + [name])
                seen.add(name)
        for name in r:
            visit(name, [])

    def test_runtime_code_and_configuration_are_retained_immutable_versions(self):
        self.assertNotIn("Default", self.template["Parameters"]["RuntimeCodeVersion"])
        for name, resource in self.resources.items():
            if resource["Type"] == "AWS::Lambda::Function":
                self.assertEqual(resource["Properties"]["Code"]["S3ObjectVersion"], {"Ref": "RuntimeCodeVersion"})
                self.assertTrue(resource["Properties"]["Handler"].startswith("runtime."))
                self.assertEqual(resource["Properties"]["Description"], {"Fn::Sub": "Reviewed configuration revision ${RuntimeConfigRevision}"})
            if resource["Type"] == "AWS::Lambda::Version":
                self.assertEqual(resource["DeletionPolicy"], "Retain")
                self.assertEqual(resource["UpdateReplacePolicy"], "Retain")
                self.assertEqual(resource["Properties"]["CodeSha256"], {"Ref": "RuntimeCodeSha256"})
                self.assertIn("RuntimeConfigRevision", resource["Properties"]["Description"]["Fn::Sub"])

    def test_workflow_functions_are_real_alias_substitutions_and_data_logs_are_disabled(self):
        workflow = self.resources["PipelineStateMachine"]["Properties"]
        self.assertEqual(workflow["StateMachineType"], "STANDARD")
        self.assertFalse(workflow["LoggingConfiguration"]["IncludeExecutionData"])
        self.assertEqual(workflow["LoggingConfiguration"]["Destinations"][0]["CloudWatchLogsLogGroup"]["LogGroupArn"], {"Fn::GetAtt": ["WorkflowLogs", "Arn"]})
        definition = json.loads(workflow["DefinitionString"])
        placeholders = set(re.findall(r"\$\{(\w+)\}", workflow["DefinitionString"]))
        self.assertEqual(placeholders, set(workflow["DefinitionSubstitutions"]))
        self.assertEqual(workflow["DefinitionSubstitutions"]["PipelineFunctionArn"], {"Ref": "PipelineAlias"})
        self.assertEqual(definition["States"]["PublishAndWait"]["Parameters"]["Payload"]["TaskToken.$"], "$$.Task.Token")
        self.assertEqual(self.resources["TerminalRule"]["Properties"]["EventPattern"]["detail"]["status"], ["FAILED", "TIMED_OUT", "ABORTED"])

    def test_optional_slack_and_response_permissions_are_off_by_default(self):
        for field in ["SlackSecretArn", "SlackChannelId", "ModelArn"]:
            self.assertEqual(self.template["Parameters"][field]["Default"], "")
        self.assertEqual(self.template["Parameters"]["DefaultDryRun"]["Default"], "true")
        self.assertEqual(self.template["Parameters"]["NaclResponseEnabled"]["Default"], "false")
        self.assertEqual(self.resources["NotifierQueueMapping"]["Properties"]["Enabled"], {"Fn::If": ["SlackConfigured", True, False]})
        for name in ["Notifier", "Ops"]:
            statements = self.resources[name + "Role"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
            secret = [entry["Fn::If"][1] for entry in statements if "Fn::If" in entry and entry["Fn::If"][0] == "SlackConfigured"][0]
            self.assertEqual(secret["Action"], "secretsmanager:GetSecretValue")
            self.assertIn("lambda:SourceFunctionArn", secret["Condition"]["ArnEquals"])
            proof = [entry for entry in statements if entry.get("Resource") == {"Ref": "ExpectedActivityTableArn"}][0]
            self.assertEqual(proof["Action"], "dynamodb:PutItem")
            self.assertIn("lambda:SourceFunctionArn", proof["Condition"]["ArnEquals"])

    def test_approval_and_blocker_have_separate_exclusive_capabilities(self):
        approval = json.dumps(self.resources["ApprovalRole"])
        blocker = json.dumps(self.resources["BlockerRole"])
        notifier = json.dumps(self.resources["NotifierRole"])
        self.assertIn("states:SendTaskSuccess", approval)
        self.assertNotIn("wafv2:UpdateIPSet", approval)
        self.assertIn("wafv2:UpdateIPSet", blocker)
        self.assertNotIn("states:SendTaskSuccess", blocker)
        self.assertNotIn("states:SendTaskSuccess", notifier)
        self.assertNotIn("wafv2:", notifier)
        policy = self.resources["DashboardApprovalPolicy"]["Properties"]["PolicyDocument"]["Statement"][0]
        self.assertEqual(policy["Resource"], {"Ref": "ApprovalAlias"})
        self.assertEqual(policy["Condition"]["ArnEquals"]["lambda:SourceFunctionArn"], {"Ref": "DashboardFunctionArn"})

    def test_delivery_failure_recovery_and_operational_destinations_exist(self):
        r = self.resources
        self.assertEqual(r["OutboxStreamMapping"]["Properties"]["DestinationConfig"]["OnFailure"]["Destination"], {"Fn::GetAtt": ["StreamFailures", "Arn"]})
        self.assertEqual(r["NotifierQueueMapping"]["Properties"]["FunctionResponseTypes"], ["ReportBatchItemFailures"])
        self.assertEqual(r["ReconcileSchedule"]["Properties"]["ScheduleExpression"], "rate(1 minute)")
        alarms = [resource for resource in r.values() if resource["Type"] == "AWS::CloudWatch::Alarm"]
        self.assertGreaterEqual(len(alarms), 16)
        self.assertTrue(all(resource["Properties"]["AlarmActions"] == [{"Ref": "OpsTopicArn"}] for resource in alarms))
        self.assertEqual(r["OpsSubscription"]["Properties"]["Endpoint"], {"Ref": "OpsAlias"})

    def test_blocker_can_verify_exclusive_bindings_for_all_sdk_resource_types(self):
        statements = self.resources["BlockerRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
        text = json.dumps(statements)
        for action in ["cloudfront:GetDistributionConfig", "cloudfront:ListDistributionsByWebACLId", "wafv2:GetWebACLForResource", "wafv2:GetWebACL", "wafv2:ListResourcesForWebACL",
                       "elasticloadbalancing:GetLoadBalancerWebACL", "elasticloadbalancing:DescribeWebACLAssociation", "appsync:ListResourcesForWebACL", "cognito-idp:ListResourcesForWebACL",
                       "apprunner:ListAssociatedServicesForWebAcl", "ec2:DescribeVerifiedAccessInstanceWebAclAssociations", "amplify:ListResourcesForWebACL", "bedrock-agentcore:GatewayListResourcesForWebACL"]:
            self.assertIn(action, text)
        lists = [entry for entry in statements if isinstance(entry.get("Action"), list) and "cloudfront:ListDistributionsByWebACLId" in entry["Action"]][0]
        self.assertEqual(lists["Resource"], "*")
        self.assertIn("lambda:SourceFunctionArn", lists["Condition"]["ArnEquals"])
        self.assertIn("cloudfront:ListDistributionTenantsByCustomization", lists["Action"])
        self.assertIn("ec2:DescribeVerifiedAccessInstanceWebAclAssociations", lists["Action"])
        dependent = [entry for entry in statements if isinstance(entry.get("Action"), list) and "cognito-idp:ListResourcesForWebACL" in entry["Action"]][0]
        self.assertEqual(dependent["Resource"], {"Fn::Sub": "arn:${AWS::Partition}:wafv2:*:${AWS::AccountId}:*/webacl/*/*"})
        self.assertIn("apprunner:ListAssociatedServicesForWebAcl", dependent["Action"])
        self.assertNotIn("wafv2:AssociateWebACL", text)

    def test_foundation_state_is_referenced_and_no_workload_or_lab_is_created(self):
        raw = json.dumps(self.template)
        self.assertNotRegex(raw, r"(?<![0-9])[0-9]{12}(?![0-9])")
        self.assertNotIn("WHS", raw)
        self.assertFalse(any(value["Type"] in {"AWS::DynamoDB::Table", "AWS::EC2::Instance", "AWS::CloudFront::Distribution"} for value in self.resources.values()))
        for output in ["ApprovalFunctionArn", "PipelineStateMachineArn", "SignalIngressFunctionArn", "ReconcilerFunctionArn"]:
            self.assertIn(output, self.template["Outputs"])

    def test_ingress_alarm_relay_selects_exact_owned_names_and_minimal_payload(self):
        parameters = self.template["Parameters"]
        self.assertNotIn("Default", parameters["InstallationId"])
        self.assertEqual(parameters["IngressAlarmNames"]["Type"], "CommaDelimitedList")
        self.assertNotIn("Default", parameters["IngressAlarmNames"])
        rule = self.resources["IngressOpsRule"]["Properties"]
        self.assertEqual(rule["Name"], {"Fn::Sub": "${InstallationId}-ingress-ops"})
        self.assertEqual(rule["EventBusName"], {"Ref": "SecurityEventBusName"})
        self.assertEqual(rule["EventPattern"]["account"], [{"Ref": "AWS::AccountId"}])
        self.assertEqual(rule["EventPattern"]["detail"]["alarmName"], {"Ref": "IngressAlarmNames"})
        target = rule["Targets"][0]
        self.assertEqual(target["RoleArn"], {"Fn::GetAtt": ["IngressOpsPublisherRole", "Arn"]})
        self.assertEqual(target["Arn"], {"Ref": "OpsTopicArn"})
        self.assertEqual(target["InputTransformer"]["InputPathsMap"], {"alarm": "$.detail.alarmName", "state": "$.detail.state.value"})
        transformed = target["InputTransformer"]["InputTemplate"].replace("<alarm>", '"fixture-alarm"').replace("<state>", '"ALARM"')
        self.assertEqual(json.loads(transformed), {"AlarmName": "fixture-alarm", "NewStateValue": "ALARM"})
        self.assertNotIn("reason", json.dumps(target["InputTransformer"]).lower())

    def test_ingress_alarm_publisher_and_failure_queue_are_exactly_scoped(self):
        role = self.resources["IngressOpsPublisherRole"]["Properties"]
        self.assertEqual(role["RoleName"], {"Fn::Sub": "${InstallationId}-ingress-ops-publisher"})
        trust = role["AssumeRolePolicyDocument"]["Statement"][0]
        expected = {"Fn::Sub": "arn:${AWS::Partition}:events:${AWS::Region}:${AWS::AccountId}:rule/${SecurityEventBusName}/${InstallationId}-ingress-ops"}
        self.assertEqual(trust["Condition"]["ArnEquals"]["aws:SourceArn"], expected)
        permissions = role["Policies"][0]["PolicyDocument"]["Statement"]
        self.assertEqual(permissions[0], {"Effect": "Allow", "Action": "sns:Publish", "Resource": {"Ref": "OpsTopicArn"}})
        self.assertEqual(permissions[1]["Resource"], {"Ref": "OpsKeyArn"})
        self.assertEqual(permissions[1]["Condition"]["StringEquals"]["kms:ViaService"], {"Fn::Sub": "sns.${AWS::Region}.${AWS::URLSuffix}"})
        queue = self.resources["IngressOpsFailures"]["Properties"]
        self.assertEqual(queue["QueueName"], {"Fn::Sub": "${InstallationId}-ingress-ops-failures"})
        self.assertEqual(queue["KmsMasterKeyId"], {"Ref": "OpsKeyArn"})
        self.assertNotIn("SqsManagedSseEnabled", queue)
        policy = self.resources["IngressOpsFailurePolicy"]["Properties"]["PolicyDocument"]["Statement"]
        self.assertEqual(policy[0]["Condition"]["ArnEquals"]["aws:SourceArn"], expected)
        self.assertEqual(policy[1]["Effect"], "Deny")
        self.assertEqual(policy[1]["Condition"], {"Bool": {"aws:SecureTransport": "false"}})
        self.assertEqual(self.resources["IngressOpsRule"]["Properties"]["Targets"][0]["DeadLetterConfig"]["Arn"], {"Fn::GetAtt": ["IngressOpsFailures", "Arn"]})

    def test_all_governance_queues_and_managed_pollers_have_compatible_cmk_permissions(self):
        for name in ["NotificationQueue", "NotificationFailures", "IngressFailures", "TerminalFailures", "StreamFailures", "IngressOpsFailures"]:
            queue = self.resources[name]["Properties"]
            self.assertEqual(queue["KmsMasterKeyId"], {"Ref": "OpsKeyArn"})
            self.assertNotIn("SqsManagedSseEnabled", queue)
        for name in ["Pipeline", "Terminal", "PublicationReconciler", "Outbox", "Notifier"]:
            statements = self.resources[name + "Role"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
            keys = [item for item in statements if item.get("Resource") == {"Ref": "OpsKeyArn"}]
            self.assertEqual(len(keys), 1)
            self.assertNotIn("lambda:SourceFunctionArn", json.dumps(keys))
            self.assertEqual(keys[0]["Condition"]["StringEquals"]["kms:ViaService"], {"Fn::Sub": "sqs.${AWS::Region}.${AWS::URLSuffix}"})
            if name != "Notifier":
                self.assertEqual(set(keys[0]["Action"]), {"kms:GenerateDataKey", "kms:Decrypt"})
        self.assertEqual(self.template["Outputs"]["OpsEventBridgeRuleArns"]["Value"], {"Fn::Join": [",", [
            {"Fn::GetAtt": [name, "Arn"]} for name in ["PublicationRule", "ServiceSignalRule", "TerminalRule", "ReconcileSchedule", "IngressOpsRule"]]]})
        self.assertEqual(self.resources["IngressOpsDeliveryErrors"]["Properties"]["Dimensions"], [{"Name": "RuleName", "Value": {"Ref": "IngressOpsRule"}}])
        self.assertIn("IngressOpsDlqDeliveryErrors", self.resources)
        for name in ["Pipeline", "Terminal", "PublicationReconciler"]:
            policy = "IngressFailurePolicy" if name == "Pipeline" else "TerminalFailurePolicy"
            self.assertEqual(set(self.resources[name + "AsyncFailure"]["DependsOn"]), {name + "Alias", name + "Role", policy})
        self.assertEqual(set(self.resources["OutboxStreamMapping"]["DependsOn"]), {"OutboxRole", "StreamFailurePolicy"})
        self.assertEqual(set(self.resources["NotifierQueueMapping"]["DependsOn"]), {"NotifierRole", "EventQueuePolicy", "NotificationFailurePolicy"})

    def test_sqs_resource_policy_statements_use_one_exact_queue_and_split_in_order(self):
        policies = {name: row for name, row in self.resources.items() if row["Type"] == "AWS::SQS::QueuePolicy"}
        self.assertEqual(policies["EventQueuePolicy"]["Properties"]["Queues"], [{"Ref": "NotificationQueue"}])
        for name, row in policies.items():
            queues = row["Properties"]["Queues"]
            self.assertEqual(len(queues), 1, name)
            queue = queues[0]["Ref"]
            for entry in row["Properties"]["PolicyDocument"]["Statement"]:
                self.assertEqual(entry["Resource"], {"Fn::GetAtt": [queue, "Arn"]}, name)
                self.assertNotIsInstance(entry["Resource"], list)
        for name in ["NotificationFailurePolicy", "IngressFailurePolicy", "TerminalFailurePolicy"]:
            self.assertEqual(policies[name]["DependsOn"], ["EventQueuePolicy"])
        self.assertEqual(policies["TerminalFailurePolicy"]["Properties"]["PolicyDocument"]["Statement"][0]["Condition"]["ArnEquals"]["aws:SourceArn"], [
            {"Fn::GetAtt": ["TerminalRule", "Arn"]}, {"Fn::GetAtt": ["ReconcileSchedule", "Arn"]}])

    def test_notifier_reads_only_committed_case_metadata(self):
        statements = self.resources["NotifierRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
        case_read = [item for item in statements if item.get("Action") == "dynamodb:GetItem" and item.get("Resource") == {"Ref": "CasesTableArn"}][0]
        attrs = case_read["Condition"]["ForAllValues:StringEquals"]["dynamodb:Attributes"]
        self.assertIn("dashboard_publication", attrs)
        self.assertNotIn("task_token", attrs)
        self.assertNotIn("report_md", attrs)
        self.assertEqual(case_read["Condition"]["Null"], {"dynamodb:Attributes": "false"})
        self.assertIn("lambda:SourceFunctionArn", case_read["Condition"]["ArnEquals"])


if __name__ == "__main__":
    unittest.main()
