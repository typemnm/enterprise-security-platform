"""Generate account-neutral CloudFormation resources; no AWS calls or demo app."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def ref(name):
    return {"Ref": name}


def sub(value):
    return {"Fn::Sub": value}


def arn(name):
    return {"Fn::GetAtt": [name, "Arn"]}


def tags(extra=None):
    return [{"Key": "ManagedBy", "Value": "enterprise-security"},
            {"Key": "Environment", "Value": ref("Environment")},
            *({"Key": k, "Value": v} for k, v in (extra or {}).items())]


def parameter(kind="String", **kwargs):
    return {"Type": kind, **kwargs}


def table(key):
    return {"Type": "AWS::DynamoDB::Table", "DeletionPolicy": "Retain",
            "UpdateReplacePolicy": "Retain", "Properties": {
                "BillingMode": "PAY_PER_REQUEST", "DeletionProtectionEnabled": True,
                "AttributeDefinitions": [{"AttributeName": key, "AttributeType": "S"}],
                "KeySchema": [{"AttributeName": key, "KeyType": "HASH"}],
                "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True},
                "SSESpecification": {"SSEEnabled": True}, "Tags": tags()}}


def statement(actions, resources, **kwargs):
    return {"Effect": "Allow", "Action": actions, "Resource": resources, **kwargs}


def ingress_resources(bucket, key, registry, registry_arn, expected, expected_arn, cases, cases_arn,
                      bus_arn, audit, audit_arn, control_region, audit_key_arn, version=None, lease=None, lease_arn=None, installation=None):
    if installation is None:
        raise ValueError("INSTALLATION_ID_REQUIRED_FOR_INGRESS_ALARM_BINDING")
    def name(suffix):
        return {"Fn::Join": ["", [installation, sub("-${AWS::Region}-" + suffix)]]}
    relay_name = name("ingress-relay")
    relay_arn = {"Fn::Join": ["", [sub("arn:${AWS::Partition}:events:${AWS::Region}:${AWS::AccountId}:rule/"), relay_name]]}
    relay_queue_name = name("ingress-relay-failures")
    resources = {
        "SecurityLogIngressLogs": {"Type": "AWS::Logs::LogGroup", "Properties": {
            "LogGroupName": sub("/enterprise/security/${AWS::StackName}/ingress"),
            "RetentionInDays": ref("LogRetentionDays"), "Tags": tags()}},
        "SecurityLogIngressRole": {"Type": "AWS::IAM::Role", "Properties": {
            "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"Service": "lambda.amazonaws.com"}}]},
            "Policies": [{"PolicyName": "VerifiedIngress", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
                statement(["logs:CreateLogStream", "logs:PutLogEvents"], sub("${SecurityLogIngressLogs.Arn}:*")),
                statement("dynamodb:GetItem", [registry_arn, expected_arn]),
                statement("dynamodb:Query", {"Fn::Join": ["", [registry_arn, "/index/WebAclArnIndex"]]}),
                *([statement(["dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"], lease_arn)] if lease_arn is not None else []),
                statement(["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"], cases_arn),
                statement("events:PutEvents", bus_arn),
                statement("cloudwatch:PutMetricData", "*", Condition={"StringEquals": {
                    "cloudwatch:namespace": "EnterpriseSecurity/Operations", "aws:RequestedRegion": control_region}}),
                statement("s3:PutObject", {"Fn::Join": ["", [audit_arn, "/ingestion/*"]]}),
                statement(["kms:GenerateDataKey", "kms:Decrypt"], audit_key_arn)]}}],
            "Tags": tags({"security:control-plane": "true"})}},
        "SecurityLogIngressFunction": {"Type": "AWS::Lambda::Function", "Properties": {
            "Runtime": "python3.13", "Handler": "runtime.ingest.handler", "Timeout": 300, "MemorySize": 256,
            "Role": arn("SecurityLogIngressRole"), "Code": {"S3Bucket": bucket, "S3Key": key,
                **({"S3ObjectVersion": version} if version is not None else {})},
            "LoggingConfig": {"LogGroup": ref("SecurityLogIngressLogs"), "LogFormat": "JSON"},
            "Environment": {"Variables": {"EXPECTED_ACCOUNT": ref("AWS::AccountId"), "CONTROL_PLANE_REGION": control_region,
                "REGISTRY_TABLE": registry, "EXPECTED_ACTIVITY_TABLE": expected, "CASES_TABLE": cases,
                "ENVIRONMENT": ref("Environment"), **({"INSTALLATION_ID": installation} if installation is not None else {}),
                **({"LEASE_TABLE": lease} if lease is not None else {}),
                "EVENT_BUS_ARN": bus_arn, "AUDIT_BUCKET": audit}}, "Tags": tags({"security:control-plane": "true"})}},
        "SecurityLogIngressPermission": {"Type": "AWS::Lambda::Permission", "Properties": {
            "FunctionName": ref("SecurityLogIngressFunction"), "Action": "lambda:InvokeFunction", "Principal": "logs.amazonaws.com",
            "SourceAccount": ref("AWS::AccountId"), "SourceArn": sub("arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:aws-waf-logs-*")}},
        "CaseBudgetLogMetric": {"Type": "AWS::Logs::MetricFilter", "Properties": {
            "LogGroupName": ref("SecurityLogIngressLogs"), "FilterPattern": "{ $.budget_limited > 0 && $.installation_id = * && $.environment = * }",
            "MetricTransformations": [{"MetricNamespace": "EnterpriseSecurity/Operations", "MetricName": "CaseBudgetLimitedLog",
                "MetricValue": "$.budget_limited", "Unit": "Count", "Dimensions": [{"Key": "InstallationId", "Value": "$.installation_id"},
                                                                    {"Key": "Environment", "Value": "$.environment"}]}]}},
    }
    sdk_statements = resources["SecurityLogIngressRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    sdk_statements.append(statement("logs:FilterLogEvents", sub("arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:aws-waf-logs-*")))
    for entry in sdk_statements:
        entry.setdefault("Condition", {}).setdefault("ArnEquals", {})["lambda:SourceFunctionArn"] = arn("SecurityLogIngressFunction")
    resources["SecurityLogIngressRole"]["Properties"].pop("Policies")
    resources["SecurityLogIngressSdkPolicy"] = {"Type": "AWS::IAM::Policy", "Properties": {"PolicyName": "VerifiedLogIngressSdk",
        "Roles": [ref("SecurityLogIngressRole")], "PolicyDocument": {"Version": "2012-10-17", "Statement": sdk_statements}}}
    resources["SecurityLogIngressFailureQueue"] = {"Type": "AWS::SQS::Queue", "Properties": {
        "SqsManagedSseEnabled": True, "MaximumMessageSize": 1048576, "MessageRetentionPeriod": 1209600,
        "Tags": tags({"security:control-plane": "true", "FailurePath": "log-ingress-async"})}}
    resources["SecurityLogIngressFailureQueuePolicy"] = {"Type": "AWS::SQS::QueuePolicy", "Properties": {
        "Queues": [ref("SecurityLogIngressFailureQueue")], "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Deny", "Principal": "*", "Action": "sqs:*", "Resource": arn("SecurityLogIngressFailureQueue"),
            "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}}}
    resources["SecurityLogIngressFailureDeliveryPolicy"] = {"Type": "AWS::IAM::Policy", "Properties": {"PolicyName": "LogIngressFailureDelivery",
        "Roles": [ref("SecurityLogIngressRole")], "PolicyDocument": {"Version": "2012-10-17", "Statement": [
            statement("sqs:SendMessage", arn("SecurityLogIngressFailureQueue"))]}}}
    resources["SecurityLogIngressAsyncFailure"] = {"Type": "AWS::Lambda::EventInvokeConfig",
        "DependsOn": ["SecurityLogIngressFailureDeliveryPolicy", "SecurityLogIngressFailureQueuePolicy"], "Properties": {
        "FunctionName": ref("SecurityLogIngressFunction"), "Qualifier": "$LATEST", "MaximumRetryAttempts": 2,
        "MaximumEventAgeInSeconds": 3600, "DestinationConfig": {"OnFailure": {"Destination": arn("SecurityLogIngressFailureQueue")}}}}
    # EventBridge DLQs require their own compatible customer-managed key.
    resources["IngressAlarmRelayKey"] = {"Type": "AWS::KMS::Key", "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain", "Properties": {
        "EnableKeyRotation": True, "Tags": tags({"security:control-plane": "true"}), "KeyPolicy": {
            "Version": "2012-10-17", "Statement": [statement("kms:*", "*", Principal={"AWS": sub("arn:${AWS::Partition}:iam::${AWS::AccountId}:root")}),
                statement(["kms:Decrypt", "kms:GenerateDataKey"], "*", Principal={"Service": "events.amazonaws.com"},
                    Condition={"StringEquals": {"aws:SourceAccount": ref("AWS::AccountId")}, "ArnEquals": {"aws:SourceArn": relay_arn}})]}}}
    resources["IngressAlarmRelayFailureQueue"] = {"Type": "AWS::SQS::Queue", "Properties": {
        "QueueName": relay_queue_name, "KmsMasterKeyId": arn("IngressAlarmRelayKey"), "MaximumMessageSize": 1048576,
        "MessageRetentionPeriod": 1209600, "Tags": tags({"security:control-plane": "true", "FailurePath": "regional-alarm-relay"})}}
    resources["IngressAlarmRelayFailureQueuePolicy"] = {"Type": "AWS::SQS::QueuePolicy", "Properties": {
        "Queues": [ref("IngressAlarmRelayFailureQueue")], "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Deny", "Principal": "*", "Action": "sqs:*", "Resource": arn("IngressAlarmRelayFailureQueue"),
            "Condition": {"Bool": {"aws:SecureTransport": "false"}}},
            statement("sqs:SendMessage", arn("IngressAlarmRelayFailureQueue"), Principal={"Service": "events.amazonaws.com"},
                Condition={"StringEquals": {"aws:SourceAccount": ref("AWS::AccountId")}, "ArnEquals": {"aws:SourceArn": relay_arn}})]}}}
    resources["IngressAlarmRelayRole"] = {"Type": "AWS::IAM::Role", "Properties": {
        "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [statement("sts:AssumeRole", None,
            Principal={"Service": "events.amazonaws.com"}, Condition={"StringEquals": {"aws:SourceAccount": ref("AWS::AccountId")},
                "ArnEquals": {"aws:SourceArn": relay_arn}})]},
        "Policies": [{"PolicyName": "OwnIngressAlarmsToCentralBus", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
            statement("events:PutEvents", bus_arn, Condition={"StringEquals": {"events:source": "aws.cloudwatch",
                "events:detail-type": "CloudWatch Alarm State Change", "aws:RequestedRegion": control_region}})]}}],
        "Tags": tags({"security:control-plane": "true"})}}
    # IAM role trust documents have no Resource element.
    resources["IngressAlarmRelayRole"]["Properties"]["AssumeRolePolicyDocument"]["Statement"][0].pop("Resource")
    definitions = [("IngressErrorsAlarm", "errors", "Errors"), ("IngressAsyncDroppedAlarm", "async-dropped", "AsyncEventsDropped"),
                   ("IngressDestinationFailuresAlarm", "destination-failures", "DestinationDeliveryFailures"),
                   ("IngressDlqDepthAlarm", "dlq-depth", None)]
    for logical, suffix, metric in definitions:
        alarm = {"AlarmName": name("log-ingress-" + suffix), "EvaluationPeriods": 1, "Threshold": 1,
            "ComparisonOperator": "GreaterThanOrEqualToThreshold", "TreatMissingData": "notBreaching", "Tags": tags({"security:control-plane": "true"})}
        if metric:
            alarm.update(Namespace="AWS/Lambda", MetricName=metric, Statistic="Sum", Period=60,
                         Dimensions=[{"Name": "FunctionName", "Value": ref("SecurityLogIngressFunction")}])
        else:
            alarm["Metrics"] = [{"Id": "depth", "Expression": "SUM(METRICS())", "ReturnData": True}, *[
                {"Id": "queue" + str(index), "ReturnData": False, "MetricStat": {"Period": 60, "Stat": "Maximum", "Metric": {
                    "Namespace": "AWS/SQS", "MetricName": "ApproximateNumberOfMessagesVisible",
                    "Dimensions": [{"Name": "QueueName", "Value": {"Fn::GetAtt": [queue, "QueueName"]}}]}}}
                for index, queue in enumerate(["SecurityLogIngressFailureQueue", "IngressAlarmRelayFailureQueue"])]]
            # Include undeliverable relay failures even when no message could
            # reach its DLQ. Use the stable literal name, avoiding rule ->
            # alarm -> rule dependencies in this exact four-alarm relay.
            alarm["Metrics"].extend({"Id": "relay" + str(index), "ReturnData": False,
                "MetricStat": {"Period": 60, "Stat": "Sum", "Metric": {"Namespace": "AWS/Events", "MetricName": event_metric,
                    "Dimensions": [{"Name": "RuleName", "Value": relay_name}]}}}
                for index, event_metric in enumerate(["FailedInvocations", "InvocationsFailedToBeSentToDlq"]))
        resources[logical] = {"Type": "AWS::CloudWatch::Alarm", "Properties": alarm}
    resources["IngressAlarmStateChangeRelay"] = {"Type": "AWS::Events::Rule", "DependsOn": ["IngressAlarmRelayFailureQueuePolicy"], "Properties": {
        "Name": relay_name, "State": "ENABLED", "EventPattern": {"source": ["aws.cloudwatch"],
            "detail-type": ["CloudWatch Alarm State Change"], "account": [ref("AWS::AccountId")], "region": [ref("AWS::Region")],
            "detail": {"alarmName": [ref(logical) for logical, _, _ in definitions],
                       "state": {"value": ["ALARM", "OK", "INSUFFICIENT_DATA"]}}},
        "Targets": [{"Id": "CentralOperations", "Arn": bus_arn, "RoleArn": arn("IngressAlarmRelayRole"),
            # Event bus targets support a DLQ but reject a custom RetryPolicy.
            "DeadLetterConfig": {"Arn": arn("IngressAlarmRelayFailureQueue")}}]}}
    return resources


def regional_ingress():
    parameters = {name: parameter() for name in ["CodeBucket", "CodeKey", "RegistryTableName", "RegistryTableArn",
        "ExpectedActivityTableName", "ExpectedActivityTableArn", "CasesTableName", "CasesTableArn",
        "SecurityEventBusArn", "AuditBucketName", "AuditBucketArn", "AuditKeyArn", "ControlPlaneRegion", "LeaseTableName", "LeaseTableArn", "InstallationId"]}
    parameters.update({"CodeVersion": parameter(Default=""), "Environment": parameter(Default="prod"), "LogRetentionDays": parameter("Number", Default=90,
        AllowedValues=[30, 60, 90, 180, 365])})
    resources = ingress_resources(*[ref(name) for name in ["CodeBucket", "CodeKey", "RegistryTableName", "RegistryTableArn",
        "ExpectedActivityTableName", "ExpectedActivityTableArn", "CasesTableName", "CasesTableArn",
        "SecurityEventBusArn", "AuditBucketName", "AuditBucketArn", "ControlPlaneRegion", "AuditKeyArn"]],
        version={"Fn::If": ["VersionPinned", ref("CodeVersion"), ref("AWS::NoValue")]}, lease=ref("LeaseTableName"), lease_arn=ref("LeaseTableArn"), installation=ref("InstallationId"))
    return {"AWSTemplateFormatVersion": "2010-09-09", "Description": "Deploy per resource region; forward verified WAF observations to the central control plane.",
        "Parameters": parameters, "Conditions": {"VersionPinned": {"Fn::Not": [{"Fn::Equals": [ref("CodeVersion"), ""]}]}},
        "Resources": resources, "Outputs": {"SecurityLogIngressArn": {"Value": arn("SecurityLogIngressFunction")},
            "SecurityLogIngressFailureQueueUrl": {"Value": ref("SecurityLogIngressFailureQueue")},
            "SecurityLogIngressFailureQueueArn": {"Value": arn("SecurityLogIngressFailureQueue")},
            "IngressAlarmRelayFailureQueueUrl": {"Value": ref("IngressAlarmRelayFailureQueue")}}}


def foundation():
    params = {
        "Environment": parameter(Default="prod", AllowedPattern="[a-z][a-z0-9-]{1,15}"),
        "DashboardOrigin": parameter(Default="", AllowedPattern=r"|https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?",
                                     Description="Optional verified custom HTTPS origin; empty provisions an API Gateway HTTPS dashboard endpoint."),
        "DashboardRoleName": parameter(Default="", AllowedPattern=r"|[A-Za-z0-9+=,.@_-]{1,64}"),
        "DashboardCodeBucket": parameter(), "DashboardCodeKey": parameter(),
        "DashboardCodeVersion": parameter(Default=""), "DashboardHandler": parameter(Default="lambda.handler"),
        "ApprovalFunctionArn": parameter(Default="", AllowedPattern=r"|arn:aws(?:-us-gov|-cn)?:lambda:[a-z0-9-]+:[0-9]{12}:function:[A-Za-z0-9_-]+(?::[A-Za-z0-9_-]+)?"),
        "AutomaticOnboardingEnabled": parameter(Default="false", AllowedValues=["true", "false"],
            Description="Enable only after governance and all same-region ingress artifacts are installed and verified."),
        "InstallationScope": parameter(Default="tagged", AllowedValues=["tagged", "all-supported"]),
        "DiscoveryRegions": parameter("CommaDelimitedList", Description="Explicit enabled AWS regions; no account-wide implicit expansion."),
        "ResponseMode": parameter(Default="observe", AllowedValues=["observe", "enforce"]),
        "AllowedActions": parameter("CommaDelimitedList", Default="monitor,block_ip"),
        "PrincipalScopesJson": parameter(Default="[]", AllowedPattern=r"\[\s*\]", Description="Only empty principal scopes are supported until a CloudTrail adapter is installed."),
        "ExcludeTagsJson": parameter(Default='{"security:exclude":"true"}'),
        "IngressArnsJson": parameter(Default="{}", Description="Region to verified same-region ingress ARN map; installer populates after regional shard creation."),
        "OpsEventBridgeRuleArns": parameter("CommaDelimitedList", Default="", Description="Exact owned governance rule ARNs; installer preserves on update and wires after governance deployment."),
        "DiscoveryEventBridgeRuleArns": parameter("CommaDelimitedList", Default="", Description="Exact discovery schedule/resource rule ARNs; installer populates after first automatic-OFF foundation creation."),
        "DiscoveryCodeBucket": parameter(), "DiscoveryCodeKey": parameter(),
        "DiscoveryCodeVersion": parameter(Default=""),
        "DiscoveryHandler": parameter(Default="runtime.discovery.handler"),
        "DiscoveryRuntime": parameter(Default="python3.13", AllowedValues=["python3.13"]),
        "DiscoveryScheduleExpression": parameter(Default="rate(5 minutes)", AllowedPattern=r"rate\([1-9][0-9]* (?:minute|minutes)\)"),
        "LogRetentionDays": parameter("Number", Default=90, AllowedValues=[30, 60, 90, 120, 180, 365]),
        "AuditRetentionDays": parameter("Number", Default=365, MinValue=90, MaxValue=3650),
    }
    resources = {}
    root_principal = sub("arn:${AWS::Partition}:iam::${AWS::AccountId}:root")
    resources["AuditKey"] = {"Type": "AWS::KMS::Key", "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain",
        "Properties": {"EnableKeyRotation": True, "PendingWindowInDays": 30, "Tags": tags(),
          "KeyPolicy": {"Version": "2012-10-17", "Statement": [
              statement("kms:*", "*", Principal={"AWS": root_principal})]}}}
    resources["AuditBucket"] = {"Type": "AWS::S3::Bucket", "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain",
        "Properties": {"VersioningConfiguration": {"Status": "Enabled"},
            "OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]},
            "BucketEncryption": {"ServerSideEncryptionConfiguration": [{
                "ServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": arn("AuditKey")},
                "BucketKeyEnabled": True}]},
            "PublicAccessBlockConfiguration": {k: True for k in ["BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"]},
            "LifecycleConfiguration": {"Rules": [{"Id": "ApprovedRetention", "Status": "Enabled",
                "ExpirationInDays": ref("AuditRetentionDays"), "NoncurrentVersionExpiration": {"NoncurrentDays": 90},
                "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7}}]}, "Tags": tags()}}
    resources["AuditBucketPolicy"] = {"Type": "AWS::S3::BucketPolicy", "Properties": {"Bucket": ref("AuditBucket"),
        "PolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:*",
            "Resource": [arn("AuditBucket"), sub("${AuditBucket.Arn}/*")], "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}}}
    for name, key in [("ServiceRegistry", "service_id"), ("DiscoveryLeaseTable", "lease_id"),
                      ("ExpectedActivityTable", "activity_id"), ("DashboardSessionTable", "session_id"),
                      ("CasesTable", "case_id"), ("ResponseOperationsTable", "lease_id"),
                      ("PublicationReceiptsTable", "notification_id")]:
        resources[name] = table(key)
        if name in {"DiscoveryLeaseTable", "ExpectedActivityTable", "DashboardSessionTable"}:
            resources[name]["Properties"]["TimeToLiveSpecification"] = {"AttributeName": "expires_at", "Enabled": True}
    resources["CasesTable"]["Properties"].update({"StreamSpecification": {"StreamViewType": "NEW_AND_OLD_IMAGES"},
        "AttributeDefinitions": [{"AttributeName": x, "AttributeType": "S"} for x in ["case_id", "status", "updated_at", "publication_state", "notification_state"]]
                                 + [{"AttributeName": x, "AttributeType": "N"} for x in ["publication_retry_at", "notification_retry_at"]],
        "GlobalSecondaryIndexes": [{"IndexName": "status-updated-at", "KeySchema": [
            {"AttributeName": "status", "KeyType": "HASH"}, {"AttributeName": "updated_at", "KeyType": "RANGE"}],
            "Projection": {"ProjectionType": "KEYS_ONLY"}},
            {"IndexName": "PublicationStateIndex", "KeySchema": [{"AttributeName": "publication_state", "KeyType": "HASH"},
                {"AttributeName": "publication_retry_at", "KeyType": "RANGE"}], "Projection": {"ProjectionType": "KEYS_ONLY"}},
            {"IndexName": "NotificationStateIndex", "KeySchema": [{"AttributeName": "notification_state", "KeyType": "HASH"},
                {"AttributeName": "notification_retry_at", "KeyType": "RANGE"}], "Projection": {"ProjectionType": "KEYS_ONLY"}}]})
    resources["ServiceRegistry"]["Properties"].update({
        "AttributeDefinitions": [{"AttributeName": x, "AttributeType": "S"} for x in ["service_id", "web_acl_arn"]],
        "GlobalSecondaryIndexes": [{"IndexName": "WebAclArnIndex", "KeySchema": [{"AttributeName": "web_acl_arn", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "KEYS_ONLY"}}]})
    resources["SecurityEventBus"] = {"Type": "AWS::Events::EventBus", "Properties": {"Name": sub("${AWS::StackName}-security"), "Tags": tags()}}
    ops_publisher = sub("arn:${AWS::Partition}:iam::${AWS::AccountId}:role/${AWS::StackName}-ingress-ops-publisher")
    resources["OpsKey"] = {"Type": "AWS::KMS::Key", "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain", "Properties": {
        "EnableKeyRotation": True, "Tags": tags(), "KeyPolicy": {"Version": "2012-10-17", "Statement": [
            statement("kms:*", "*", Principal={"AWS": root_principal}),
            statement(["kms:Decrypt", "kms:GenerateDataKey*"], "*", Principal={"Service": "cloudwatch.amazonaws.com"},
                      Condition={"StringEquals": {"aws:SourceAccount": ref("AWS::AccountId")},
                                 "ArnLike": {"aws:SourceArn": sub("arn:${AWS::Partition}:cloudwatch:${AWS::Region}:${AWS::AccountId}:alarm:*")}}),
            # EventBridge SNS encryption does not support SourceArn/Account
            # conditions. The exact rule is bound in the publisher role trust.
            statement(["kms:Decrypt", "kms:GenerateDataKey"], "*", Principal={"AWS": root_principal},
                Condition={"ArnEquals": {"aws:PrincipalArn": ops_publisher},
                    "StringEquals": {"kms:ViaService": sub("sns.${AWS::Region}.${AWS::URLSuffix}")}}),
            # Unlike SNS, EventBridge's encrypted SQS DLQ supports source binding.
            {"Fn::If": ["HasOpsEventBridgeRules", statement(["kms:Decrypt", "kms:GenerateDataKey"], "*", Principal={"Service": "events.amazonaws.com"},
                Condition={"StringEquals": {"aws:SourceAccount": ref("AWS::AccountId")},
                    "ArnEquals": {"aws:SourceArn": ref("OpsEventBridgeRuleArns")}}), ref("AWS::NoValue")]}]}}}
    resources["OpsTopic"] = {"Type": "AWS::SNS::Topic", "Properties": {"KmsMasterKeyId": arn("OpsKey"), "Tags": tags()}}
    resources["OpsTopicPolicy"] = {"Type": "AWS::SNS::TopicPolicy", "Properties": {"Topics": [ref("OpsTopic")],
        "PolicyDocument": {"Version": "2012-10-17", "Statement": [statement("sns:Publish", ref("OpsTopic"),
            Sid="PublishOwnedCloudWatchAlarms", Principal={"Service": "cloudwatch.amazonaws.com"}, Condition={"StringEquals": {"aws:SourceAccount": ref("AWS::AccountId")},
            "ArnLike": {"aws:SourceArn": sub("arn:${AWS::Partition}:cloudwatch:${AWS::Region}:${AWS::AccountId}:alarm:*")}}),
            statement("sns:Publish", ref("OpsTopic"), Sid="PublishOwnedIngressRelay", Principal={"AWS": root_principal},
                Condition={"ArnEquals": {"aws:PrincipalArn": ops_publisher}})]}}}
    resources["DiscoveryDlqKey"] = {"Type": "AWS::KMS::Key", "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain", "Properties": {
        "EnableKeyRotation": True, "Tags": tags({"security:control-plane": "true"}), "KeyPolicy": {"Version": "2012-10-17", "Statement": [
            statement("kms:*", "*", Principal={"AWS": root_principal}),
            {"Fn::If": ["HasDiscoveryEventBridgeRules", statement(["kms:GenerateDataKey", "kms:Decrypt"], "*", Principal={"Service": "events.amazonaws.com"},
                Condition={"StringEquals": {"aws:SourceAccount": ref("AWS::AccountId")},
                    "ArnEquals": {"aws:SourceArn": ref("DiscoveryEventBridgeRuleArns")}}), ref("AWS::NoValue")]}]}}}
    resources["DiscoveryDlq"] = {"Type": "AWS::SQS::Queue", "Properties": {"KmsMasterKeyId": arn("DiscoveryDlqKey"),
        "MessageRetentionPeriod": 1209600, "Tags": tags()}}
    resources["DiscoveryLogs"] = {"Type": "AWS::Logs::LogGroup", "Properties": {
        "LogGroupName": sub("/enterprise/security/${AWS::StackName}/discovery"), "RetentionInDays": ref("LogRetentionDays"), "Tags": tags()}}
    read_actions = ["elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:DescribeTags", "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeRules", "elasticloadbalancing:DescribeTargetGroups", "elasticloadbalancing:DescribeTargetHealth",
        "cloudfront:ListDistributions", "cloudfront:GetDistribution", "cloudfront:GetDistributionConfig", "cloudfront:ListTagsForResource",
        "cloudfront:ListDistributionsByWebACLId", "cloudfront:ListDistributionTenantsByCustomization", "ec2:DescribeRegions", "wafv2:ListWebACLs", "wafv2:ListIPSets",
        "wafv2:GetWebACL", "wafv2:GetIPSet", "wafv2:GetWebACLForResource", "wafv2:ListResourcesForWebACL", "wafv2:ListTagsForResource",
        "wafv2:GetLoggingConfiguration", "wafv2:CheckCapacity"]
    account_resource = sub("arn:${AWS::Partition}:wafv2:*:${AWS::AccountId}:*/*")
    resources["DiscoveryRole"] = {"Type": "AWS::IAM::Role", "Properties": {
        "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"Service": "lambda.amazonaws.com"}}]},
        "Policies": [{"PolicyName": "DiscoveryScopedAccount", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
            statement(["logs:CreateLogStream", "logs:PutLogEvents"], sub("${DiscoveryLogs.Arn}:*")),
            statement(read_actions, "*"),
            statement(["elasticloadbalancing:DescribeWebACLAssociation", "appsync:ListResourcesForWebACL", "amplify:ListResourcesForWebACL",
                       "ec2:DescribeVerifiedAccessInstanceWebAclAssociations", "bedrock-agentcore:GatewayListResourcesForWebACL"], "*"),
            statement(["cognito-idp:ListResourcesForWebACL", "apprunner:ListAssociatedServicesForWebAcl"], sub("arn:${AWS::Partition}:wafv2:*:${AWS::AccountId}:regional/webacl/*/*")),
            statement("elasticloadbalancing:GetLoadBalancerWebACL", sub("arn:${AWS::Partition}:elasticloadbalancing:*:${AWS::AccountId}:loadbalancer/app/*/*")),
            statement(["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Scan", "dynamodb:DeleteItem"], [arn("ServiceRegistry"), arn("DiscoveryLeaseTable")]),
            statement(["wafv2:CreateWebACL", "wafv2:CreateIPSet", "wafv2:TagResource"], account_resource),
            statement(["wafv2:UpdateWebACL", "wafv2:AssociateWebACL"], account_resource),
            statement("elasticloadbalancing:CreateWebACLAssociation", sub("arn:${AWS::Partition}:elasticloadbalancing:*:${AWS::AccountId}:loadbalancer/app/*/*")),
            statement("elasticloadbalancing:SetWebAcl", "*", Condition={"StringEquals": {"aws:RequestedRegion": ref("DiscoveryRegions")}}),
            statement("wafv2:PutLoggingConfiguration", account_resource),
            statement(["logs:CreateLogGroup", "logs:PutRetentionPolicy"],
                      sub("arn:${AWS::Partition}:logs:*:${AWS::AccountId}:log-group:aws-waf-logs-security-*")),
            statement(["logs:PutSubscriptionFilter", "logs:DescribeSubscriptionFilters"],
                      sub("arn:${AWS::Partition}:logs:*:${AWS::AccountId}:log-group:aws-waf-logs-*")),
            statement(["logs:DescribeLogGroups", "logs:DescribeResourcePolicies", "logs:CreateLogDelivery", "logs:PutResourcePolicy"], "*",
                      Condition={"StringEquals": {"aws:RequestedRegion": {"Fn::Split": [",", {"Fn::Join": [",", [
                          {"Fn::Join": [",", ref("DiscoveryRegions")]}, "us-east-1"]]}]}}}),
            statement("cloudfront:UpdateDistribution", sub("arn:${AWS::Partition}:cloudfront::${AWS::AccountId}:distribution/*")),
            statement(["s3:PutObject"], sub("${AuditBucket.Arn}/operations/onboarding/*")),
            statement(["kms:GenerateDataKey", "kms:Decrypt"], arn("AuditKey")),
            statement("events:PutEvents", arn("SecurityEventBus")), statement("sqs:SendMessage", arn("DiscoveryDlq"))]}}], "Tags": tags()}}
    # Discovery needs broad read/attach operations because target ARNs do not exist
    # at installation. Runtime ownership/tag/scope/ETag guards are mandatory.
    resources["DiscoveryFunction"] = {"Type": "AWS::Lambda::Function", "Properties": {
        "Runtime": ref("DiscoveryRuntime"), "Handler": ref("DiscoveryHandler"), "Timeout": 300, "MemorySize": 512,
        "Role": arn("DiscoveryRole"), "ReservedConcurrentExecutions": 1,
        "Code": {"S3Bucket": ref("DiscoveryCodeBucket"), "S3Key": ref("DiscoveryCodeKey"),
                 "S3ObjectVersion": {"Fn::If": ["VersionPinned", ref("DiscoveryCodeVersion"), ref("AWS::NoValue")]}},
        "LoggingConfig": {"LogGroup": ref("DiscoveryLogs"), "LogFormat": "JSON"},
        "Environment": {"Variables": {"REGISTRY_TABLE": ref("ServiceRegistry"), "LEASE_TABLE": ref("DiscoveryLeaseTable"),
            "EXPECTED_ACTIVITY_TABLE": ref("ExpectedActivityTable"), "AUDIT_BUCKET": ref("AuditBucket"),
            "EVENT_BUS_ARN": arn("SecurityEventBus"), "EXPECTED_ACCOUNT": ref("AWS::AccountId"),
            "ENVIRONMENT": ref("Environment"), "CONTROL_PLANE_REGION": ref("AWS::Region"),
            "INSTALLATION_ID": ref("AWS::StackName"),
            "INSTALLATION_SCOPE": ref("InstallationScope"), "DISCOVERY_REGIONS": {"Fn::Join": [",", ref("DiscoveryRegions")]},
            "RESPONSE_MODE": ref("ResponseMode"), "ALLOWED_ACTIONS": {"Fn::Join": [",", ref("AllowedActions")]},
            "PRINCIPAL_SCOPES_JSON": ref("PrincipalScopesJson"), "EXCLUDE_TAGS_JSON": ref("ExcludeTagsJson"),
            "INGRESS_ARNS_JSON": ref("IngressArnsJson"),
            "SECURITY_LOG_INGRESS_ARN": arn("SecurityLogIngressFunction"), "LOG_RETENTION_DAYS": {"Fn::Sub": "${LogRetentionDays}"}}},
        "Tags": tags({"security:control-plane": "true"})}}
    # Keep the source-function condition out of the inline role to avoid a
    # Function -> Role -> Function dependency cycle. Lambda-managed async
    # failure delivery has no SourceFunctionArn and keeps its exact DLQ grant.
    discovery_statements = resources["DiscoveryRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    destination_statements = [entry for entry in discovery_statements if entry["Action"] == "sqs:SendMessage"]
    sdk_statements = [entry for entry in discovery_statements if entry["Action"] != "sqs:SendMessage"]
    for entry in sdk_statements:
        entry.setdefault("Condition", {})["ArnEquals"] = {"lambda:SourceFunctionArn": arn("DiscoveryFunction")}
    resources["DiscoveryRole"]["Properties"].pop("Policies")
    resources["DiscoveryFailureDeliveryPolicy"] = {"Type": "AWS::IAM::Policy", "Properties": {"PolicyName": "DiscoveryFailureDelivery",
        "Roles": [ref("DiscoveryRole")], "PolicyDocument": {"Version": "2012-10-17", "Statement": [*destination_statements,
            statement(["kms:GenerateDataKey", "kms:Decrypt"], arn("DiscoveryDlqKey"), Condition={"StringEquals": {
                "kms:ViaService": sub("sqs.${AWS::Region}.${AWS::URLSuffix}"), "kms:CallerAccount": ref("AWS::AccountId")}})]}}}
    resources["DiscoverySdkPolicy"] = {"Type": "AWS::IAM::Policy", "Properties": {"PolicyName": "VerifiedDiscoverySdk",
        "Roles": [ref("DiscoveryRole")], "PolicyDocument": {"Version": "2012-10-17", "Statement": sdk_statements}}}
    resources.update(ingress_resources(ref("DiscoveryCodeBucket"), ref("DiscoveryCodeKey"), ref("ServiceRegistry"),
        arn("ServiceRegistry"), ref("ExpectedActivityTable"), arn("ExpectedActivityTable"), ref("CasesTable"), arn("CasesTable"),
        arn("SecurityEventBus"), ref("AuditBucket"), arn("AuditBucket"), ref("AWS::Region"), arn("AuditKey"),
        version={"Fn::If": ["VersionPinned", ref("DiscoveryCodeVersion"), ref("AWS::NoValue")]},
        lease=ref("DiscoveryLeaseTable"), lease_arn=arn("DiscoveryLeaseTable"), installation=ref("AWS::StackName")))
    resources["OnboardingReviewMetric"] = {"Type": "AWS::Logs::MetricFilter", "Properties": {
        "LogGroupName": ref("DiscoveryLogs"), "FilterPattern": '{ $.operation = "reconcile" && $.review_required >= 0 && $.installation_id = * && $.environment = * }',
        "MetricTransformations": [{"MetricNamespace": "EnterpriseSecurity/Operations", "MetricName": "OnboardingReviewRequired",
            "MetricValue": "$.review_required", "Unit": "Count", "Dimensions": [{"Key": "InstallationId", "Value": "$.installation_id"},
                                                               {"Key": "Environment", "Value": "$.environment"}]}]}}
    for logical, metric in [("OnboardingReviewAlarm", "OnboardingReviewRequired"), ("CaseBudgetAlarm", "CaseBudgetLimited")]:
        resources[logical] = {"Type": "AWS::CloudWatch::Alarm", "Properties": {"AlarmDescription": "Manual review required; inspect scoped security platform logs.",
            "Namespace": "EnterpriseSecurity/Operations", "MetricName": metric,
            "Dimensions": [{"Name": "InstallationId", "Value": ref("AWS::StackName")}, {"Name": "Environment", "Value": ref("Environment")}],
            "Statistic": "Sum", "Period": 300, "EvaluationPeriods": 1, "DatapointsToAlarm": 1, "Threshold": 1,
            "ComparisonOperator": "GreaterThanOrEqualToThreshold", "TreatMissingData": "notBreaching",
            "AlarmActions": [ref("OpsTopic")], "OKActions": [ref("OpsTopic")]}}
    resources["DiscoveryAsyncFailure"] = {"Type": "AWS::Lambda::EventInvokeConfig",
        "DependsOn": ["DiscoveryFailureDeliveryPolicy", "DiscoveryDlqPolicy"], "Properties": {"FunctionName": ref("DiscoveryFunction"),
        "Qualifier": "$LATEST", "MaximumRetryAttempts": 2, "MaximumEventAgeInSeconds": 3600,
        "DestinationConfig": {"OnFailure": {"Destination": arn("DiscoveryDlq")}}}}
    pattern = {"source": ["aws.elasticloadbalancing", "aws.cloudfront", "aws.tag"], "$or": [
        {"detail-type": ["AWS API Call via CloudTrail"], "detail": {"eventName": ["CreateLoadBalancer", "CreateDistribution", "CreateDistributionWithTags", "AddTags", "TagResource"]}},
        {"detail-type": ["Tag Change on Resource"]}]}
    for name, extra in [("DiscoverySchedule", {"ScheduleExpression": ref("DiscoveryScheduleExpression")}),
                        ("DiscoveryResourceEvent", {"EventPattern": pattern})]:
        resources[name] = {"Type": "AWS::Events::Rule", "Properties": {"State": {"Fn::If": ["AutomaticOnboarding", "ENABLED", "DISABLED"]}, **extra,
            "Targets": [{"Id": "Reconcile", "Arn": arn("DiscoveryFunction"), "Input": '{"operation":"reconcile"}',
                "RetryPolicy": {"MaximumRetryAttempts": 10, "MaximumEventAgeInSeconds": 3600},
                "DeadLetterConfig": {"Arn": arn("DiscoveryDlq")}}]}}
        resources[name + "Permission"] = {"Type": "AWS::Lambda::Permission", "Properties": {
            "FunctionName": ref("DiscoveryFunction"), "Action": "lambda:InvokeFunction", "Principal": "events.amazonaws.com",
            "SourceArn": arn(name), "SourceAccount": ref("AWS::AccountId")}}
    resources["DiscoveryDlqPolicy"] = {"Type": "AWS::SQS::QueuePolicy", "Properties": {"Queues": [ref("DiscoveryDlq")],
        "PolicyDocument": {"Version": "2012-10-17", "Statement": [statement("sqs:SendMessage", arn("DiscoveryDlq"),
            Principal={"Service": "events.amazonaws.com"}, Condition={"ArnEquals": {"aws:SourceArn": [arn("DiscoverySchedule"), arn("DiscoveryResourceEvent")]},
            "StringEquals": {"aws:SourceAccount": ref("AWS::AccountId")}}),
            {"Effect": "Deny", "Principal": "*", "Action": "sqs:*", "Resource": arn("DiscoveryDlq"),
             "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}}}
    for name, namespace, metric, dimension, statistic, threshold in [
        ("DiscoveryErrors", "AWS/Lambda", "Errors", {"Name": "FunctionName", "Value": ref("DiscoveryFunction")}, "Sum", 1),
        ("DiscoveryThrottles", "AWS/Lambda", "Throttles", {"Name": "FunctionName", "Value": ref("DiscoveryFunction")}, "Sum", 1),
        ("DiscoveryAsyncDropped", "AWS/Lambda", "AsyncEventsDropped", {"Name": "FunctionName", "Value": ref("DiscoveryFunction")}, "Sum", 1),
        ("DiscoveryDestinationFailures", "AWS/Lambda", "DestinationDeliveryFailures", {"Name": "FunctionName", "Value": ref("DiscoveryFunction")}, "Sum", 1),
        ("DiscoveryDeadLetters", "AWS/SQS", "ApproximateNumberOfMessagesVisible", {"Name": "QueueName", "Value": {"Fn::GetAtt": ["DiscoveryDlq", "QueueName"]}}, "Maximum", 1)]:
        resources[name] = {"Type": "AWS::CloudWatch::Alarm", "Properties": {"Namespace": namespace, "MetricName": metric,
            "Dimensions": [dimension], "Statistic": statistic, "Period": 300, "EvaluationPeriods": 1,
            "Threshold": threshold, "ComparisonOperator": "GreaterThanOrEqualToThreshold", "TreatMissingData": "notBreaching",
            "AlarmActions": [ref("OpsTopic")], "OKActions": [ref("OpsTopic")]}}
    resources["AdminUserPool"] = {"Type": "AWS::Cognito::UserPool", "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain", "Properties": {
        "DeletionProtection": "ACTIVE", "UsernameAttributes": ["email"], "UsernameConfiguration": {"CaseSensitive": False},
        "AutoVerifiedAttributes": ["email"], "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True},
        "MfaConfiguration": "ON", "EnabledMfas": ["SOFTWARE_TOKEN_MFA"],
        "AccountRecoverySetting": {"RecoveryMechanisms": [{"Name": "admin_only", "Priority": 1}]},
        "Policies": {"PasswordPolicy": {"MinimumLength": 14, "RequireLowercase": True, "RequireUppercase": True,
            "RequireNumbers": True, "RequireSymbols": True, "TemporaryPasswordValidityDays": 3}},
        "UserPoolTags": {"ManagedBy": "enterprise-security", "Environment": ref("Environment")}}}
    resources["SecurityAdmins"] = {"Type": "AWS::Cognito::UserPoolGroup", "Properties": {"UserPoolId": ref("AdminUserPool"), "GroupName": "security-admins"}}
    resources["AdminClient"] = {"Type": "AWS::Cognito::UserPoolClient", "Properties": {"UserPoolId": ref("AdminUserPool"),
        "GenerateSecret": False, "AllowedOAuthFlowsUserPoolClient": True, "AllowedOAuthFlows": ["code"],
        "AllowedOAuthScopes": ["openid", "email"], "SupportedIdentityProviders": ["COGNITO"],
        "CallbackURLs": [{"Fn::If": ["CustomDashboardOrigin", sub("${DashboardOrigin}/auth/callback"),
            sub("https://${DashboardHttpApi}.execute-api.${AWS::Region}.${AWS::URLSuffix}/auth/callback")]}],
        "LogoutURLs": [{"Fn::If": ["CustomDashboardOrigin", sub("${DashboardOrigin}/auth/logged-out"),
            sub("https://${DashboardHttpApi}.execute-api.${AWS::Region}.${AWS::URLSuffix}/auth/logged-out")]}],
        "PreventUserExistenceErrors": "ENABLED", "EnableTokenRevocation": True,
        "AccessTokenValidity": 15, "IdTokenValidity": 15, "RefreshTokenValidity": 1,
        "TokenValidityUnits": {"AccessToken": "minutes", "IdToken": "minutes", "RefreshToken": "days"},
        "ReadAttributes": ["email", "email_verified"], "WriteAttributes": ["email"]}}
    resources["AdminDomain"] = {"Type": "AWS::Cognito::UserPoolDomain", "Properties": {
        "UserPoolId": ref("AdminUserPool"), "Domain": sub("${AWS::StackName}-${AWS::AccountId}")}}
    resources["DashboardSessionsPolicy"] = {"Type": "AWS::IAM::Policy", "Condition": "HasDashboardRole", "Properties": {
        "PolicyName": sub("${AWS::StackName}-sessions"), "Roles": [ref("DashboardRoleName")],
        "PolicyDocument": {"Version": "2012-10-17", "Statement": [
            statement(["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"], arn("DashboardSessionTable"))]}}}
    resources["DashboardHttpApi"] = {"Type": "AWS::ApiGatewayV2::Api", "Properties": {"ProtocolType": "HTTP", "Name": sub("${AWS::StackName}-admin")}}
    resources["DashboardLogs"] = {"Type": "AWS::Logs::LogGroup", "Properties": {
        "LogGroupName": sub("/enterprise/security/${AWS::StackName}/dashboard"), "RetentionInDays": ref("LogRetentionDays")}}
    resources["DashboardRole"] = {"Type": "AWS::IAM::Role", "Properties": {
        "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"Service": "lambda.amazonaws.com"}}]},
        "Policies": [{"PolicyName": "DashboardBoundary", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
            statement(["logs:CreateLogStream", "logs:PutLogEvents"], sub("${DashboardLogs.Arn}:*")),
            statement(["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"], arn("DashboardSessionTable")),
            statement("dynamodb:GetItem", arn("CasesTable")),
            statement(["dynamodb:GetItem", "dynamodb:Scan"], arn("ServiceRegistry")),
            statement(["s3:GetObject"], [sub("${AuditBucket.Arn}/*/inv-*.md"), sub("${AuditBucket.Arn}/decisions/*")]),
            statement("s3:ListBucket", arn("AuditBucket")),
            statement("s3:PutObject", sub("${AuditBucket.Arn}/decisions/*")),
            statement(["kms:Decrypt", "kms:GenerateDataKey"], arn("AuditKey")),
            statement(["wafv2:GetIPSet", "wafv2:UpdateIPSet"], sub("arn:${AWS::Partition}:wafv2:*:${AWS::AccountId}:*/ipset/security-*/" + "*"))]}}], "Tags": tags()}}
    public_origin = {"Fn::If": ["CustomDashboardOrigin", ref("DashboardOrigin"), sub("https://${DashboardHttpApi}.execute-api.${AWS::Region}.${AWS::URLSuffix}")]}
    resources["DashboardFunction"] = {"Type": "AWS::Lambda::Function", "Properties": {
        "Runtime": "nodejs24.x", "Handler": ref("DashboardHandler"), "Timeout": 30, "MemorySize": 512, "Role": arn("DashboardRole"),
        "Code": {"S3Bucket": ref("DashboardCodeBucket"), "S3Key": ref("DashboardCodeKey"),
            "S3ObjectVersion": {"Fn::If": ["DashboardVersionPinned", ref("DashboardCodeVersion"), ref("AWS::NoValue")]}},
        "LoggingConfig": {"LogGroup": ref("DashboardLogs"), "LogFormat": "JSON"},
        "Environment": {"Variables": {"NODE_ENV": "production", "PUBLIC_ORIGIN": public_origin,
            "OIDC_ISSUER": sub("https://cognito-idp.${AWS::Region}.${AWS::URLSuffix}/${AdminUserPool}"),
            "OIDC_CLIENT_ID": ref("AdminClient"), "OIDC_REDIRECT_URI": {"Fn::Join": ["", [public_origin, "/auth/callback"]]},
            "ADMIN_GROUPS": "security-admins", "SESSION_TABLE": ref("DashboardSessionTable"),
            "SERVICE_REGISTRY_TABLE": ref("ServiceRegistry"), "CASES_TABLE": ref("CasesTable"),
            "REPORT_BUCKET": ref("AuditBucket"), "APPROVE_FUNCTION_NAME": ref("ApprovalFunctionArn"),
            "AUDIT_BUCKET": ref("AuditBucket"), "EXPECTED_ACCOUNT": ref("AWS::AccountId"),
            "COMPANY_ACCOUNT_ID": ref("AWS::AccountId")}}, "Tags": tags({"security:control-plane": "true"})}}
    resources["DashboardIntegration"] = {"Type": "AWS::ApiGatewayV2::Integration", "Properties": {
        "ApiId": ref("DashboardHttpApi"), "IntegrationType": "AWS_PROXY", "IntegrationUri": arn("DashboardFunction"), "PayloadFormatVersion": "2.0"}}
    for name, route in [("DashboardRootRoute", "ANY /"), ("DashboardProxyRoute", "ANY /{proxy+}")]:
        resources[name] = {"Type": "AWS::ApiGatewayV2::Route", "Properties": {"ApiId": ref("DashboardHttpApi"),
            "RouteKey": route, "Target": {"Fn::Join": ["/", ["integrations", ref("DashboardIntegration")]]}}}
    resources["DashboardStage"] = {"Type": "AWS::ApiGatewayV2::Stage", "Properties": {"ApiId": ref("DashboardHttpApi"),
        "StageName": "$default", "AutoDeploy": True, "DefaultRouteSettings": {"ThrottlingBurstLimit": 50, "ThrottlingRateLimit": 10}}}
    resources["DashboardApiPermission"] = {"Type": "AWS::Lambda::Permission", "Properties": {"Action": "lambda:InvokeFunction",
        "FunctionName": ref("DashboardFunction"), "Principal": "apigateway.amazonaws.com", "SourceAccount": ref("AWS::AccountId"),
        "SourceArn": sub("arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${DashboardHttpApi}/*/*")}}
    outputs = {
        "InstallationId": ref("AWS::StackName"),
        "InstallationId": ref("AWS::StackName"),
        "RegistryTableName": ref("ServiceRegistry"), "RegistryTableArn": arn("ServiceRegistry"),
        "LeaseTableName": ref("DiscoveryLeaseTable"), "LeaseTableArn": arn("DiscoveryLeaseTable"),
        "ExpectedActivityTableName": ref("ExpectedActivityTable"), "ExpectedActivityTableArn": arn("ExpectedActivityTable"),
        "CasesTableName": ref("CasesTable"), "CasesTableArn": arn("CasesTable"),
        "CasesTableStreamArn": {"Fn::GetAtt": ["CasesTable", "StreamArn"]},
        "CaseStatusIndexName": "status-updated-at", "ResponseOperationsTableName": ref("ResponseOperationsTable"),
        "ResponseOperationsTableArn": arn("ResponseOperationsTable"), "PublicationReceiptsTableName": ref("PublicationReceiptsTable"),
        "PublicationReceiptsTableArn": arn("PublicationReceiptsTable"),
        "AuditBucketName": ref("AuditBucket"), "AuditBucketArn": arn("AuditBucket"), "AuditKeyArn": arn("AuditKey"),
        "SecurityEventBusArn": arn("SecurityEventBus"), "SecurityEventBusName": ref("SecurityEventBus"),
        "OpsTopicArn": ref("OpsTopic"), "OpsKeyArn": arn("OpsKey"),
        "DiscoveryFunctionArn": arn("DiscoveryFunction"), "DiscoveryRoleArn": arn("DiscoveryRole"),
        "SecurityLogIngressArn": arn("SecurityLogIngressFunction"),
        "SecurityLogIngressFailureQueueUrl": ref("SecurityLogIngressFailureQueue"),
        "SecurityLogIngressFailureQueueArn": arn("SecurityLogIngressFailureQueue"),
        "IngressAlarmRelayFailureQueueUrl": ref("IngressAlarmRelayFailureQueue"),
        "DiscoveryDlqUrl": ref("DiscoveryDlq"), "DashboardSessionTableName": ref("DashboardSessionTable"),
        "DiscoveryScheduleRuleArn": arn("DiscoverySchedule"), "DiscoveryResourceEventRuleArn": arn("DiscoveryResourceEvent"),
        "DashboardSessionTableArn": arn("DashboardSessionTable"), "CognitoUserPoolId": ref("AdminUserPool"),
        "CognitoClientId": ref("AdminClient"), "OidcIssuer": sub("https://cognito-idp.${AWS::Region}.${AWS::URLSuffix}/${AdminUserPool}"),
        "DashboardRedirectUri": {"Fn::Join": ["", [public_origin, "/auth/callback"]]}, "AdminGroupName": "security-admins",
        "DashboardUrl": public_origin, "DashboardFunctionArn": arn("DashboardFunction"), "DashboardRoleArn": arn("DashboardRole"),
        "DashboardReportBucketName": ref("AuditBucket"), "DashboardReportBucketArn": arn("AuditBucket")}
    return {"AWSTemplateFormatVersion": "2010-09-09", "Description": "Enterprise security foundation; opt-in discovery, audited registry, operations and Cognito MFA.",
        "Parameters": params, "Conditions": {"HasDashboardRole": {"Fn::Not": [{"Fn::Equals": [ref("DashboardRoleName"), ""]}]},
             "AutomaticOnboarding": {"Fn::Equals": [ref("AutomaticOnboardingEnabled"), "true"]},
             "HasOpsEventBridgeRules": {"Fn::Not": [{"Fn::Equals": [{"Fn::Join": [",", ref("OpsEventBridgeRuleArns")]}, ""]}]},
             "HasDiscoveryEventBridgeRules": {"Fn::Not": [{"Fn::Equals": [{"Fn::Join": [",", ref("DiscoveryEventBridgeRuleArns")]}, ""]}]},
             "VersionPinned": {"Fn::Not": [{"Fn::Equals": [ref("DiscoveryCodeVersion"), ""]}]},
             "DashboardVersionPinned": {"Fn::Not": [{"Fn::Equals": [ref("DashboardCodeVersion"), ""]}]},
             "CustomDashboardOrigin": {"Fn::Not": [{"Fn::Equals": [ref("DashboardOrigin"), ""]}]}},
        "Resources": resources, "Outputs": {k: {"Value": v} for k, v in outputs.items()}}


def waf_bundle(scope):
    # Creates owned resources only. Association and current-ACL merge are done
    # by the guarded discovery backend, never by an unconditional association.
    t = {"AWSTemplateFormatVersion": "2010-09-09", "Description": f"Owned {scope} WAF bundle. Attach only after ownership/conflict inspection.",
        "Parameters": {"ServiceId": parameter(AllowedPattern="[a-z][a-z0-9-]{2,47}"),
            "Environment": parameter(Default="prod", AllowedPattern="[a-z][a-z0-9-]{1,15}"),
            "LogRetentionDays": parameter("Number", Default=90, AllowedValues=[30, 60, 90, 180, 365])}, "Resources": {}, "Outputs": {}}
    r = t["Resources"]
    for family in ["IPV4", "IPV6"]:
        r[family + "BlockSet"] = {"Type": "AWS::WAFv2::IPSet", "Properties": {"Scope": scope, "IPAddressVersion": family,
            "Name": sub("security-${ServiceId}-${Environment}-blocked-" + family.lower()),
            "Addresses": [], "Description": "Enterprise service-scoped response addresses. Registered targets only.", "Tags": tags({"security:service-id": ref("ServiceId")})}}
    def visibility(name):
        return {"CloudWatchMetricsEnabled": True, "MetricName": name, "SampledRequestsEnabled": False}
    rules = [{"Name": "EnterpriseIpBlock", "Priority": 0, "Action": {"Block": {}},
        "Statement": {"OrStatement": {"Statements": [{"IPSetReferenceStatement": {"Arn": arn(f + "BlockSet")}} for f in ["IPV4", "IPV6"]]}},
        "VisibilityConfig": visibility("EnterpriseIpBlock")}]
    for priority, group in [(10, "AWSManagedRulesCommonRuleSet"), (20, "AWSManagedRulesKnownBadInputsRuleSet")]:
        rules.append({"Name": group, "Priority": priority, "OverrideAction": {"Count": {}},
            "Statement": {"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": group}}, "VisibilityConfig": visibility(group)})
    r["WebAcl"] = {"Type": "AWS::WAFv2::WebACL", "Properties": {"Name": sub("security-${ServiceId}-${Environment}"), "Scope": scope, "DefaultAction": {"Allow": {}},
        "Rules": rules, "VisibilityConfig": visibility("EnterpriseSecurity"), "DataProtectionConfig": {"DataProtections": [
            {"Field": field, "Action": "SUBSTITUTION", "ExcludeRuleMatchDetails": False, "ExcludeRateBasedDetails": False}
            for field in [{"FieldType": "SINGLE_HEADER", "FieldKeys": ["authorization", "cookie", "x-api-key"]},
                          {"FieldType": "QUERY_STRING"}, {"FieldType": "BODY"}]]}, "Tags": tags({"security:service-id": ref("ServiceId")})}}
    r["WafLogs"] = {"Type": "AWS::Logs::LogGroup", "Properties": {"LogGroupName": sub("aws-waf-logs-security-${ServiceId}-${Environment}"),
        "RetentionInDays": ref("LogRetentionDays"), "Tags": tags({"security:service-id": ref("ServiceId")})}}
    r["WafLogging"] = {"Type": "AWS::WAFv2::LoggingConfiguration", "Properties": {"ResourceArn": arn("WebAcl"),
        "LogDestinationConfigs": [sub("arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:${WafLogs}")], "RedactedFields": [
            {"SingleHeader": {"Name": x}} for x in ["authorization", "cookie", "x-api-key"]] + [{"QueryString": {}}]}}
    for k, value in {"WebAclArn": arn("WebAcl"), "IPv4BlockSetArn": arn("IPV4BlockSet"),
                     "IPv6BlockSetArn": arn("IPV6BlockSet"), "WafLogGroupArn": sub("arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:${WafLogs}"), "Scope": scope}.items():
        t["Outputs"][k] = {"Value": value}
    return t


def write():
    templates = {"foundation.template.json": foundation(), "regional-waf.template.json": waf_bundle("REGIONAL"),
                 "cloudfront-waf.template.json": waf_bundle("CLOUDFRONT"),
                 "security-log-ingress.template.json": regional_ingress()}
    for name, template in templates.items():
        (ROOT / name).write_text(json.dumps(template, indent=2) + "\n", encoding="utf-8")
    return templates


if __name__ == "__main__":
    for name, value in write().items():
        print(json.dumps({"template": name, "resources": len(value["Resources"])}))
