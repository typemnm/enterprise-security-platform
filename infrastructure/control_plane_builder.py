"""Account-neutral governance resources backed by a pinned common runtime ZIP."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "runtime"))
from workflow_builder import cfn_workflow


def ref(name):
    return {"Ref": name}


def sub(value):
    return {"Fn::Sub": value}


def arn(name):
    return {"Fn::GetAtt": [name, "Arn"]}


def statement(actions, resources, **extra):
    return {"Effect": "Allow", "Action": actions, "Resource": resources, **extra}


def tags():
    return [{"Key": "ManagedBy", "Value": "enterprise-security"}, {"Key": "Environment", "Value": ref("Environment")},
            {"Key": "security:control-plane", "Value": "true"}]


def function_identity(name):
    # String construction avoids function -> role -> function dependency cycles.
    return sub("arn:${AWS::Partition}:lambda:${AWS::Region}:${AWS::AccountId}:function:${AWS::StackName}-" + name.lower())


def source_condition(name):
    return {"ArnEquals": {"lambda:SourceFunctionArn": function_identity(name)}}


def template():
    names = ["RuntimeCodeBucket", "RuntimeCodeKey", "RuntimeCodeVersion", "RuntimeCodeSha256",
             "RegistryTableName", "RegistryTableArn", "CasesTableName", "CasesTableArn", "CasesTableStreamArn",
             "OperationsTableName", "OperationsTableArn", "LeaseTableName", "LeaseTableArn",
             "ExpectedActivityTableName", "ExpectedActivityTableArn", "ReceiptTableName", "ReceiptTableArn",
             "AuditBucketName", "AuditBucketArn", "AuditKeyArn", "SecurityEventBusName", "SecurityEventBusArn",
             "OpsTopicArn", "OpsKeyArn", "InstallationId", "DashboardFunctionArn", "DashboardRoleArn"]
    params = {name: {"Type": "String"} for name in names}
    params["RuntimeCodeVersion"].update(MinLength=1, Description="S3 object version for the reviewed immutable runtime ZIP")
    params["RuntimeCodeSha256"].update(AllowedPattern="[A-Za-z0-9+/]{43}=", Description="Base64 SHA-256 checked again when publishing each Lambda version")
    params["InstallationId"].update(AllowedPattern="[a-z][a-z0-9-]{2,30}", Description="Exact owning foundation installation ID; installer verifies its output")
    params["IngressAlarmNames"] = {"Type": "CommaDelimitedList", "AllowedPattern": r"[a-z][a-z0-9-]{2,30}-[a-z]{2}(?:-[a-z]+)+-[0-9]-log-ingress-(?:errors|async-dropped|destination-failures|dlq-depth)",
        "Description": "Installer computes the four exact owned log-ingress alarm names for each installed resource region"}
    params.update({
        "RuntimeConfigRevision": {"Type": "String", "Default": "1", "AllowedPattern": "[A-Za-z0-9_.-]{1,64}", "Description": "Installer hashes effective environment configuration; publishes a new retained version on configuration changes"},
        "Environment": {"Type": "String", "Default": "prod", "AllowedPattern": "[a-z][a-z0-9-]{1,15}"},
        "DefaultDryRun": {"Type": "String", "Default": "true", "AllowedValues": ["true", "false"]},
        "LogRetentionDays": {"Type": "Number", "Default": 90, "AllowedValues": [30, 60, 90, 180, 365]},
        "SlackSecretArn": {"Type": "String", "Default": "", "AllowedPattern": r"|arn:aws(?:-us-gov|-cn)?:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+"},
        "SlackChannelId": {"Type": "String", "Default": "", "AllowedPattern": r"|[CG][A-Z0-9]{8,}"},
        "SlackSecretKeyArn": {"Type": "String", "Default": "", "Description": "Optional customer KMS key of the configured Slack secret"},
        "ModelArn": {"Type": "String", "Default": "", "AllowedPattern": r"|arn:aws(?:-us-gov|-cn)?:bedrock:[a-z0-9-]+:(?:[0-9]{12})?:[A-Za-z0-9_./:-]+"},
        "NaclResponseEnabled": {"Type": "String", "Default": "false", "AllowedValues": ["true", "false"], "Description": "Optional IAM capability; each service still requires explicit NACL policy and reserved slots"},
    })
    conditions = {
        "SlackConfigured": {"Fn::And": [{"Fn::Not": [{"Fn::Equals": [ref("SlackSecretArn"), ""]}]}, {"Fn::Not": [{"Fn::Equals": [ref("SlackChannelId"), ""]}]}]},
        "SlackCustomerKey": {"Fn::Not": [{"Fn::Equals": [ref("SlackSecretKeyArn"), ""]}]},
        "ModelConfigured": {"Fn::Not": [{"Fn::Equals": [ref("ModelArn"), ""]}]},
        "NaclResponse": {"Fn::Equals": [ref("NaclResponseEnabled"), "true"]},
    }
    resources = {}
    machine_arn = sub("arn:${AWS::Partition}:states:${AWS::Region}:${AWS::AccountId}:stateMachine:${AWS::StackName}-pipeline")
    execution_arn = sub("arn:${AWS::Partition}:states:${AWS::Region}:${AWS::AccountId}:execution:${AWS::StackName}-pipeline:inv-*")
    cases = ref("CasesTableArn")
    pub_indexes = {"Fn::Join": ["", [cases, "/index/PublicationStateIndex"]]}
    notify_indexes = {"Fn::Join": ["", [cases, "/index/NotificationStateIndex"]]}
    report_objects = {"Fn::Join": ["", [ref("AuditBucketArn"), "/*/inv-*.md"]]}
    common = {"EXPECTED_ACCOUNT": ref("AWS::AccountId"), "REGISTRY_TABLE": ref("RegistryTableName"), "CASES_TABLE": ref("CasesTableName")}
    write_case = statement(["dynamodb:GetItem", "dynamodb:UpdateItem"], cases)
    registry_read = statement("dynamodb:GetItem", ref("RegistryTableArn"))
    write_reports = statement("s3:PutObject", report_objects)
    audit_key = statement(["kms:GenerateDataKey", "kms:Decrypt"], ref("AuditKeyArn"))
    # Managed async delivery and SQS pollers run outside the function's SDK
    # execution context. Exact key/service/account grants must remain usable
    # without lambda:SourceFunctionArn; SDK-only permissions stay separate.
    def queue_key(actions):
        return statement(actions, ref("OpsKeyArn"), Condition={"StringEquals": {
            "kms:ViaService": sub("sqs.${AWS::Region}.${AWS::URLSuffix}"), "kms:CallerAccount": ref("AWS::AccountId")}})

    def function(name, handler, env, permissions, *, timeout=60, memory=256, concurrency=None):
        log = name + "Logs"
        resources[log] = {"Type": "AWS::Logs::LogGroup", "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain", "Properties": {
            "LogGroupName": sub("/enterprise/security/${AWS::StackName}/" + name.lower()), "RetentionInDays": ref("LogRetentionDays"), "Tags": tags()}}
        resources[name + "Role"] = {"Type": "AWS::IAM::Role", "Properties": {
            "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"Service": "lambda.amazonaws.com"}}]},
            "Policies": [{"PolicyName": "ScopedRuntime", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
                statement(["logs:CreateLogStream", "logs:PutLogEvents"], sub("${" + log + ".Arn}:*")), *permissions]}}], "Tags": tags()}}
        props = {"FunctionName": sub("${AWS::StackName}-" + name.lower()), "Runtime": "python3.13", "Handler": handler,
            "Description": sub("Reviewed configuration revision ${RuntimeConfigRevision}"),
            "Timeout": timeout, "MemorySize": memory, "Role": arn(name + "Role"),
            "Code": {"S3Bucket": ref("RuntimeCodeBucket"), "S3Key": ref("RuntimeCodeKey"), "S3ObjectVersion": ref("RuntimeCodeVersion")},
            "LoggingConfig": {"LogGroup": ref(log), "LogFormat": "JSON"}, "Environment": {"Variables": env}, "Tags": tags()}
        if concurrency is not None:
            props["ReservedConcurrentExecutions"] = concurrency
        resources[name + "Function"] = {"Type": "AWS::Lambda::Function", "Properties": props}
        resources[name + "Version"] = {"Type": "AWS::Lambda::Version", "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain", "Properties": {
            "FunctionName": ref(name + "Function"), "CodeSha256": ref("RuntimeCodeSha256"),
            "Description": sub("${RuntimeCodeSha256}:${RuntimeConfigRevision}")}}
        resources[name + "Alias"] = {"Type": "AWS::Lambda::Alias", "Properties": {"Name": "live", "FunctionName": ref(name + "Function"),
            "FunctionVersion": {"Fn::GetAtt": [name + "Version", "Version"]}}}

    function("Pipeline", "runtime.case_pipeline.handler", {**common, "OPERATIONS_TABLE": ref("OperationsTableName"), "LEASE_TABLE": ref("LeaseTableName"), "MODEL_ARN": ref("ModelArn"),
        "PIPELINE_STATE_MACHINE_ARN": machine_arn, "DEFAULT_DRY_RUN": ref("DefaultDryRun")},
        [write_case, registry_read, write_reports, audit_key, statement("dynamodb:GetItem", [ref("OperationsTableArn"), ref("LeaseTableArn")]),
         statement("states:StartExecution", machine_arn), statement("states:DescribeExecution", execution_arn),
         {"Fn::If": ["ModelConfigured", statement("bedrock:InvokeModel", ref("ModelArn")), ref("AWS::NoValue")]}], timeout=120, memory=512)
    function("Approval", "runtime.approval.handler", common,
        [write_case, registry_read, statement("states:SendTaskSuccess", "*", Condition=source_condition("Approval"))], timeout=30)
    function("Blocker", "runtime.blocker.handler", {**common, "OPERATIONS_TABLE": ref("OperationsTableName"), "LEASE_TABLE": ref("LeaseTableName"), "DEFAULT_DRY_RUN": ref("DefaultDryRun")},
        [registry_read, statement("dynamodb:GetItem", cases),
         statement(["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"], ref("OperationsTableArn")),
         statement(["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"], ref("LeaseTableArn")),
         statement(["wafv2:GetIPSet", "wafv2:UpdateIPSet"], sub("arn:${AWS::Partition}:wafv2:*:${AWS::AccountId}:*/ipset/security-*/*")),
         statement(["wafv2:GetWebACLForResource", "wafv2:GetWebACL", "wafv2:ListResourcesForWebACL"], sub("arn:${AWS::Partition}:wafv2:*:${AWS::AccountId}:*/webacl/*/*")),
         statement("cloudfront:GetDistributionConfig", sub("arn:${AWS::Partition}:cloudfront::${AWS::AccountId}:distribution/*")),
         # These list APIs lack resource-level IAM support. Bind SDK calls to
         # this response function and validate the exact registry set in code.
         statement(["cloudfront:ListDistributionsByWebACLId", "cloudfront:ListDistributionTenantsByCustomization", "elasticloadbalancing:DescribeWebACLAssociation", "appsync:ListResourcesForWebACL",
                    "amplify:ListResourcesForWebACL", "bedrock-agentcore:GatewayListResourcesForWebACL", "ec2:DescribeVerifiedAccessInstanceWebAclAssociations"], "*", Condition=source_condition("Blocker")),
         statement("elasticloadbalancing:GetLoadBalancerWebACL", sub("arn:${AWS::Partition}:elasticloadbalancing:*:${AWS::AccountId}:loadbalancer/app/*/*")),
         statement(["cognito-idp:ListResourcesForWebACL", "apprunner:ListAssociatedServicesForWebAcl"], sub("arn:${AWS::Partition}:wafv2:*:${AWS::AccountId}:*/webacl/*/*")),
         {"Fn::If": ["NaclResponse", statement("ec2:DescribeNetworkAcls", "*"), ref("AWS::NoValue")]},
         {"Fn::If": ["NaclResponse", statement("ec2:ReplaceNetworkAclEntry", sub("arn:${AWS::Partition}:ec2:*:${AWS::AccountId}:network-acl/*")), ref("AWS::NoValue")]}], timeout=150)
    function("Terminal", "runtime.terminal.handler", {**common, "PIPELINE_STATE_MACHINE_ARN": machine_arn},
        [write_case, registry_read, write_reports, audit_key, statement("states:DescribeExecution", execution_arn)], timeout=120)
    notifications = {"NOTIFICATION_BUS": ref("SecurityEventBusName")}
    event_put = statement("events:PutEvents", ref("SecurityEventBusArn"), Condition={"StringEquals": {"events:source": "whs.hitl.dashboard", "events:detail-type": "DashboardReportPublished.v1"}})
    function("PublicationReconciler", "runtime.publication_reconciler.handler", {"CASES_TABLE": ref("CasesTableName"), **notifications,
             "PUBLICATION_INDEX": "PublicationStateIndex", "NOTIFICATION_INDEX": "NotificationStateIndex", "RECONCILE_BATCH_SIZE": "25"},
        [write_case, statement("dynamodb:Query", [pub_indexes, notify_indexes]), write_reports, audit_key, event_put,
         statement("cloudwatch:PutMetricData", "*", Condition={"StringEquals": {"cloudwatch:namespace": "EnterpriseSecurity/Recovery"}})], timeout=120, concurrency=1)
    function("Outbox", "runtime.outbox_delivery.handler", {"CASES_TABLE": ref("CasesTableName"), **notifications},
        [write_case, event_put, statement(["dynamodb:DescribeStream", "dynamodb:GetRecords", "dynamodb:GetShardIterator", "dynamodb:ListStreams"], ref("CasesTableStreamArn")),
         statement("sqs:SendMessage", arn("StreamFailures")), queue_key(["kms:GenerateDataKey", "kms:Decrypt"])], timeout=60)
    secret_permissions = lambda name: [
        {"Fn::If": ["SlackConfigured", statement("secretsmanager:GetSecretValue", ref("SlackSecretArn"), Condition=source_condition(name)), ref("AWS::NoValue")]},
        {"Fn::If": ["SlackCustomerKey", statement("kms:Decrypt", ref("SlackSecretKeyArn"), Condition={"StringEquals": {"kms:ViaService": sub("secretsmanager.${AWS::Region}.${AWS::URLSuffix}")}, **source_condition(name)}), ref("AWS::NoValue")]},
        statement("dynamodb:PutItem", ref("ExpectedActivityTableArn"), Condition=source_condition(name))]
    slack_env = {"EXPECTED_ACCOUNT": ref("AWS::AccountId"), "SLACK_SECRET_ARN": ref("SlackSecretArn"), "SLACK_CHANNEL_ID": ref("SlackChannelId"),
                 "NOTIFICATIONS_ENABLED": {"Fn::If": ["SlackConfigured", "true", "false"]}, "NOTIFICATIONS_TABLE": ref("ReceiptTableName"),
                 "EXPECTED_ACTIVITY_TABLE": ref("ExpectedActivityTableName"), "AUDIT_BUCKET": ref("AuditBucketName"), "DASHBOARD_BUCKET": ref("AuditBucketName")}
    function("Notifier", "runtime.notifier.handler", {**slack_env, "REGISTRY_TABLE": ref("RegistryTableName"), "CASES_TABLE": ref("CasesTableName"), "QUEUE_URL": ref("NotificationQueue")},
        [registry_read, statement("dynamodb:GetItem", cases, Condition={**source_condition("Notifier"),
            "ForAllValues:StringEquals": {"dynamodb:Attributes": ["case_id", "service_id", "dashboard_bucket", "dashboard_key", "publication_state", "publication_revision",
                "dashboard_notification_hotl", "dashboard_notification_hitl", "dashboard_notification_outcome", "dashboard_publication"]},
            "Null": {"dynamodb:Attributes": "false"}}), statement(["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem"], ref("ReceiptTableArn")),
         statement("s3:GetObject", report_objects), statement("kms:Decrypt", ref("AuditKeyArn")),
         statement(["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes", "sqs:ChangeMessageVisibility"], arn("NotificationQueue")), queue_key("kms:Decrypt"), *secret_permissions("Notifier")], timeout=60)
    function("Ops", "runtime.ops.handler", {**slack_env, "OPS_TOPIC_ARN": ref("OpsTopicArn")},
        [statement(["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"], ref("ReceiptTableArn")), *secret_permissions("Ops")], timeout=60)

    resources["DashboardApprovalPolicy"] = {"Type": "AWS::IAM::Policy", "Properties": {"PolicyName": sub("${AWS::StackName}-approval"),
        "Roles": [{"Fn::Select": [1, {"Fn::Split": ["/", ref("DashboardRoleArn")]}]}], "PolicyDocument": {"Version": "2012-10-17", "Statement": [
            statement("lambda:InvokeFunction", ref("ApprovalAlias"), Condition={"ArnEquals": {"lambda:SourceFunctionArn": ref("DashboardFunctionArn")}})]}}}
    resources["WorkflowLogs"] = {"Type": "AWS::Logs::LogGroup", "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain", "Properties": {
        "LogGroupName": sub("/aws/vendedlogs/states/${AWS::StackName}/pipeline"), "RetentionInDays": ref("LogRetentionDays"), "Tags": tags()}}
    resources["WorkflowRole"] = {"Type": "AWS::IAM::Role", "Properties": {"AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"Service": "states.amazonaws.com"},
        "Condition": {"StringEquals": {"aws:SourceAccount": ref("AWS::AccountId")}, "ArnEquals": {"aws:SourceArn": machine_arn}}}]},
        "Policies": [{"PolicyName": "InvokeScopedAliases", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
            statement("lambda:InvokeFunction", [ref("PipelineAlias"), ref("BlockerAlias"), ref("TerminalAlias")]),
            # These CloudWatch Logs delivery APIs do not support resource-level IAM.
            statement(["logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery", "logs:DeleteLogDelivery", "logs:ListLogDeliveries", "logs:PutResourcePolicy", "logs:DescribeResourcePolicies", "logs:DescribeLogGroups"], "*") ]}}], "Tags": tags()}}
    resources["PipelineStateMachine"] = {"Type": "AWS::StepFunctions::StateMachine", "Properties": {
        "StateMachineName": sub("${AWS::StackName}-pipeline"), "StateMachineType": "STANDARD", "RoleArn": arn("WorkflowRole"),
        "DefinitionString": json.dumps(cfn_workflow(), ensure_ascii=False, separators=(",", ":")),
        "DefinitionSubstitutions": {"PipelineFunctionArn": ref("PipelineAlias"), "BlockerFunctionArn": ref("BlockerAlias"), "TerminalFunctionArn": ref("TerminalAlias")},
        "LoggingConfiguration": {"Level": "ERROR", "IncludeExecutionData": False,
            "Destinations": [{"CloudWatchLogsLogGroup": {"LogGroupArn": arn("WorkflowLogs")}}]}, "Tags": tags()}}
    for name in ["NotificationQueue", "NotificationFailures", "IngressFailures", "TerminalFailures", "StreamFailures"]:
        queue = {"KmsMasterKeyId": ref("OpsKeyArn"), "MessageRetentionPeriod": 1209600, "MaximumMessageSize": 1048576, "Tags": tags()}
        if name == "NotificationQueue":
            queue.update(VisibilityTimeout=360, RedrivePolicy={"deadLetterTargetArn": arn("NotificationFailures"), "maxReceiveCount": 5})
        resources[name] = {"Type": "AWS::SQS::Queue", "Properties": queue}
    resources["OutboxStreamMapping"] = {"Type": "AWS::Lambda::EventSourceMapping", "DependsOn": ["OutboxRole", "StreamFailurePolicy"], "Properties": {
        "FunctionName": ref("OutboxAlias"), "EventSourceArn": ref("CasesTableStreamArn"), "StartingPosition": "LATEST", "BatchSize": 25,
        "BisectBatchOnFunctionError": True, "MaximumRetryAttempts": 3, "MaximumRecordAgeInSeconds": 3600,
        "FunctionResponseTypes": ["ReportBatchItemFailures"],
        "DestinationConfig": {"OnFailure": {"Destination": arn("StreamFailures")}},
        "FilterCriteria": {"Filters": [{"Pattern": '{"eventName":["INSERT","MODIFY"]}'}]}}}
    resources["NotifierQueueMapping"] = {"Type": "AWS::Lambda::EventSourceMapping", "DependsOn": ["NotifierRole", "EventQueuePolicy", "NotificationFailurePolicy"], "Properties": {
        "FunctionName": ref("NotifierAlias"), "EventSourceArn": arn("NotificationQueue"), "BatchSize": 5,
        "Enabled": {"Fn::If": ["SlackConfigured", True, False]}, "FunctionResponseTypes": ["ReportBatchItemFailures"]}}

    def rule(name, properties, function_name, *, dlq=None):
        target = {"Id": "Deliver", "Arn": ref(function_name + "Alias"), "RetryPolicy": {"MaximumRetryAttempts": 10, "MaximumEventAgeInSeconds": 3600}}
        if dlq:
            target["DeadLetterConfig"] = {"Arn": arn(dlq)}
        resources[name] = {"Type": "AWS::Events::Rule", "Properties": {"State": "ENABLED", **properties, "Targets": [target]}}
        resources[name + "Permission"] = {"Type": "AWS::Lambda::Permission", "Properties": {"FunctionName": ref(function_name + "Alias"),
            "Action": "lambda:InvokeFunction", "Principal": "events.amazonaws.com", "SourceArn": arn(name), "SourceAccount": ref("AWS::AccountId")}}

    rule("ServiceSignalRule", {"EventBusName": ref("SecurityEventBusName"), "EventPattern": {
        "source": ["security.service"], "detail-type": ["ServiceSecuritySignal.v1"], "account": [ref("AWS::AccountId")],
        "region": [ref("AWS::Region")], "detail": {"schema_version": ["1.0"], "confidence": ["provider_signal"]}}}, "Pipeline", dlq="IngressFailures")
    rule("TerminalRule", {"EventPattern": {"source": ["aws.states"], "detail-type": ["Step Functions Execution Status Change"],
        "account": [ref("AWS::AccountId")], "region": [ref("AWS::Region")], "detail": {"stateMachineArn": [machine_arn], "status": ["FAILED", "TIMED_OUT", "ABORTED"]}}}, "Terminal", dlq="TerminalFailures")
    rule("ReconcileSchedule", {"ScheduleExpression": "rate(1 minute)"}, "PublicationReconciler", dlq="TerminalFailures")
    resources["PublicationRule"] = {"Type": "AWS::Events::Rule", "Properties": {"EventBusName": ref("SecurityEventBusName"), "State": "ENABLED",
        "EventPattern": {"source": ["whs.hitl.dashboard"], "detail-type": ["DashboardReportPublished.v1"], "account": [ref("AWS::AccountId")],
            "region": [ref("AWS::Region")], "detail": {"schema_version": ["1.0"]}},
        "Targets": [{"Id": "ReportQueue", "Arn": arn("NotificationQueue"), "RetryPolicy": {"MaximumRetryAttempts": 10, "MaximumEventAgeInSeconds": 3600}, "DeadLetterConfig": {"Arn": arn("NotificationFailures")}}]}}
    def event_queue_policy(logical, queue, source_rules, *, after_shared=False):
        # SQS queue resource policies require one exact Resource per statement.
        # Preserve the existing shared logical ID on the primary queue. New
        # policies wait for its update to finish clearing former assignments.
        source = arn(source_rules[0]) if len(source_rules) == 1 else [arn(name) for name in source_rules]
        policy = {"Type": "AWS::SQS::QueuePolicy", "Properties": {"Queues": [ref(queue)],
            "PolicyDocument": {"Version": "2012-10-17", "Statement": [
                statement("sqs:SendMessage", arn(queue), Sid="AllowOwnedEventBridgeDelivery", Principal={"Service": "events.amazonaws.com"},
                    Condition={"ArnEquals": {"aws:SourceArn": source}, "StringEquals": {"aws:SourceAccount": ref("AWS::AccountId")}}),
                {"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "sqs:*", "Resource": arn(queue),
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}}}
        if after_shared:
            policy["DependsOn"] = ["EventQueuePolicy"]
        resources[logical] = policy

    event_queue_policy("EventQueuePolicy", "NotificationQueue", ["PublicationRule"])
    event_queue_policy("NotificationFailurePolicy", "NotificationFailures", ["PublicationRule"], after_shared=True)
    event_queue_policy("IngressFailurePolicy", "IngressFailures", ["ServiceSignalRule"], after_shared=True)
    event_queue_policy("TerminalFailurePolicy", "TerminalFailures", ["TerminalRule", "ReconcileSchedule"], after_shared=True)
    resources["StreamFailurePolicy"] = {"Type": "AWS::SQS::QueuePolicy", "Properties": {"Queues": [ref("StreamFailures")],
        "PolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Principal": "*", "Action": "sqs:*",
            "Resource": arn("StreamFailures"), "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}}}
    for name, target, dlq in [("Pipeline", "ServiceSignalRule", "IngressFailures"), ("Terminal", "TerminalRule", "TerminalFailures"), ("PublicationReconciler", "ReconcileSchedule", "TerminalFailures")]:
        # EventBridge acceptance and Lambda's asynchronous execution are separate.
        failure_policy = "IngressFailurePolicy" if dlq == "IngressFailures" else "TerminalFailurePolicy"
        resources[name + "AsyncFailure"] = {"Type": "AWS::Lambda::EventInvokeConfig", "DependsOn": [name + "Alias", name + "Role", failure_policy], "Properties": {"FunctionName": ref(name + "Function"), "Qualifier": "live",
            "MaximumRetryAttempts": 2, "MaximumEventAgeInSeconds": 3600, "DestinationConfig": {"OnFailure": {"Destination": arn(dlq)}}}}
        resources[name + "Role"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"].append(statement("sqs:SendMessage", arn(dlq)))
        resources[name + "Role"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"].append(queue_key(["kms:GenerateDataKey", "kms:Decrypt"]))
    resources["OpsPermission"] = {"Type": "AWS::Lambda::Permission", "Properties": {"FunctionName": ref("OpsAlias"), "Action": "lambda:InvokeFunction",
        "Principal": "sns.amazonaws.com", "SourceArn": ref("OpsTopicArn"), "SourceAccount": ref("AWS::AccountId")}}
    resources["OpsSubscription"] = {"Type": "AWS::SNS::Subscription", "DependsOn": ["OpsPermission"], "Properties": {
        "TopicArn": ref("OpsTopicArn"), "Protocol": "lambda", "Endpoint": ref("OpsAlias")}}

    ingress_rule_arn = sub("arn:${AWS::Partition}:events:${AWS::Region}:${AWS::AccountId}:rule/${SecurityEventBusName}/${InstallationId}-ingress-ops")
    # SNS targets support a role. Bind that role to this exact custom-bus rule
    # rather than granting the EventBridge service broad publish/key access.
    resources["IngressOpsPublisherRole"] = {"Type": "AWS::IAM::Role", "Properties": {
        "RoleName": sub("${InstallationId}-ingress-ops-publisher"),
        "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
            "Principal": {"Service": "events.amazonaws.com"}, "Condition": {"StringEquals": {"aws:SourceAccount": ref("AWS::AccountId")},
                "ArnEquals": {"aws:SourceArn": ingress_rule_arn}}}]},
        "Policies": [{"PolicyName": "PublishOwnedIngressAlarms", "PolicyDocument": {"Version": "2012-10-17", "Statement": [
            statement("sns:Publish", ref("OpsTopicArn")),
            statement(["kms:GenerateDataKey", "kms:Decrypt"], ref("OpsKeyArn"), Condition={"StringEquals": {
                "kms:ViaService": sub("sns.${AWS::Region}.${AWS::URLSuffix}"), "kms:CallerAccount": ref("AWS::AccountId")}})]}}], "Tags": tags()}}
    resources["IngressOpsFailures"] = {"Type": "AWS::SQS::Queue", "Properties": {
        "QueueName": sub("${InstallationId}-ingress-ops-failures"), "KmsMasterKeyId": ref("OpsKeyArn"),
        "MessageRetentionPeriod": 1209600, "Tags": tags()}}
    resources["IngressOpsFailurePolicy"] = {"Type": "AWS::SQS::QueuePolicy", "Properties": {"Queues": [ref("IngressOpsFailures")],
        "PolicyDocument": {"Version": "2012-10-17", "Statement": [
            statement("sqs:SendMessage", arn("IngressOpsFailures"), Principal={"Service": "events.amazonaws.com"},
                Condition={"ArnEquals": {"aws:SourceArn": ingress_rule_arn}, "StringEquals": {"aws:SourceAccount": ref("AWS::AccountId")}}),
            {"Effect": "Deny", "Principal": "*", "Action": "sqs:*", "Resource": arn("IngressOpsFailures"), "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}}}
    resources["IngressOpsRule"] = {"Type": "AWS::Events::Rule", "DependsOn": ["IngressOpsFailurePolicy"], "Properties": {
        "Name": sub("${InstallationId}-ingress-ops"), "EventBusName": ref("SecurityEventBusName"), "State": "ENABLED",
        "EventPattern": {"source": ["aws.cloudwatch"], "detail-type": ["CloudWatch Alarm State Change"], "account": [ref("AWS::AccountId")],
            "detail": {"alarmName": ref("IngressAlarmNames"), "state": {"value": ["ALARM", "OK", "INSUFFICIENT_DATA"]}}},
        "Targets": [{"Id": "OwnedOpsTopic", "Arn": ref("OpsTopicArn"), "RoleArn": arn("IngressOpsPublisherRole"),
            "InputTransformer": {"InputPathsMap": {"alarm": "$.detail.alarmName", "state": "$.detail.state.value"},
                "InputTemplate": '{"AlarmName":<alarm>,"NewStateValue":<state>}'},
            "RetryPolicy": {"MaximumRetryAttempts": 10, "MaximumEventAgeInSeconds": 3600}, "DeadLetterConfig": {"Arn": arn("IngressOpsFailures")}}]}}

    def alarm(name, namespace, metric, dimensions, threshold=1, stat="Sum", period=300):
        resources[name] = {"Type": "AWS::CloudWatch::Alarm", "Properties": {"AlarmName": sub("${AWS::StackName}-" + name.lower()),
            "Namespace": namespace, "MetricName": metric, "Dimensions": dimensions, "Statistic": stat, "Period": period, "EvaluationPeriods": 1,
            "Threshold": threshold, "ComparisonOperator": "GreaterThanOrEqualToThreshold", "TreatMissingData": "notBreaching", "AlarmActions": [ref("OpsTopicArn")], "OKActions": [ref("OpsTopicArn")]}}
    for name in ["Pipeline", "Approval", "Blocker", "Terminal", "PublicationReconciler", "Outbox", "Notifier", "Ops"]:
        alarm(name + "Errors", "AWS/Lambda", "Errors", [{"Name": "FunctionName", "Value": ref(name + "Function")}])
    alarm("NotificationQueueAge", "AWS/SQS", "ApproximateAgeOfOldestMessage", [{"Name": "QueueName", "Value": {"Fn::GetAtt": ["NotificationQueue", "QueueName"]}}], threshold=300, stat="Maximum")
    for queue in ["NotificationFailures", "IngressFailures", "TerminalFailures", "StreamFailures"]:
        alarm(queue + "Messages", "AWS/SQS", "ApproximateNumberOfMessagesVisible", [{"Name": "QueueName", "Value": {"Fn::GetAtt": [queue, "QueueName"]}}], stat="Maximum")
    for metric in ["ExecutionsFailed", "ExecutionsTimedOut", "ExecutionsAborted"]:
        alarm(metric, "AWS/States", metric, [{"Name": "StateMachineArn", "Value": ref("PipelineStateMachine")}])
    for metric in ["PendingExamined", "DependencyErrors"]:
        alarm("Recovery" + metric, "EnterpriseSecurity/Recovery", metric,
            [{"Name": "FunctionName", "Value": ref("PublicationReconcilerFunction")}], stat="Maximum", period=60)
        resources["Recovery" + metric]["Properties"].update(EvaluationPeriods=3, DatapointsToAlarm=3)
    alarm("IngressOpsDeliveryErrors", "AWS/Events", "FailedInvocations", [{"Name": "RuleName", "Value": ref("IngressOpsRule")}])
    alarm("IngressOpsDlqDeliveryErrors", "AWS/Events", "InvocationsFailedToBeSentToDlq", [{"Name": "RuleName", "Value": ref("IngressOpsRule")}])
    for name in ["Pipeline", "Terminal", "PublicationReconciler"]:
        alarm(name + "AsyncDropped", "AWS/Lambda", "AsyncEventsDropped", [{"Name": "FunctionName", "Value": ref(name + "Function")}])
        alarm(name + "DestinationFailures", "AWS/Lambda", "DestinationDeliveryFailures", [{"Name": "FunctionName", "Value": ref(name + "Function")}])
    alarm("IngressOpsFailureMessages", "AWS/SQS", "ApproximateNumberOfMessagesVisible", [{"Name": "QueueName", "Value": {"Fn::GetAtt": ["IngressOpsFailures", "QueueName"]}}], stat="Maximum")
    outputs = {"PipelineStateMachineArn": ref("PipelineStateMachine"), "ApprovalFunctionArn": ref("ApprovalAlias"),
               "SignalIngressFunctionArn": ref("PipelineAlias"), "ServiceSignalRuleArn": arn("ServiceSignalRule"),
               "ReconcilerFunctionArn": ref("PublicationReconcilerAlias"), "NotifierFunctionArn": ref("NotifierAlias"), "TerminalFunctionArn": ref("TerminalAlias"),
               "OpsFunctionArn": ref("OpsAlias"), "BlockerFunctionArn": ref("BlockerAlias"), "OutboxFunctionArn": ref("OutboxAlias"),
               "ReceiptTableName": ref("ReceiptTableName"), "ReceiptTableArn": ref("ReceiptTableArn"), "NotificationQueueUrl": ref("NotificationQueue"),
               "NotificationQueueArn": arn("NotificationQueue"), "NotificationsEnabled": {"Fn::If": ["SlackConfigured", "true", "false"]},
               "IngressOpsRuleArn": arn("IngressOpsRule"), "IngressOpsPublisherRoleArn": arn("IngressOpsPublisherRole"),
               "IngressOpsFailureQueueArn": arn("IngressOpsFailures"), "IngressOpsFailureQueueUrl": ref("IngressOpsFailures"),
               "OpsEventBridgeRuleArns": {"Fn::Join": [",", [arn(x) for x in ["PublicationRule", "ServiceSignalRule", "TerminalRule", "ReconcileSchedule", "IngressOpsRule"]]]}}
    return {"AWSTemplateFormatVersion": "2010-09-09", "Description": "Enterprise governance: scoped HOTL/HITL, private approval callbacks, durable report delivery and operational alarms.",
            "Parameters": params, "Conditions": conditions, "Resources": resources, "Outputs": {name: {"Value": value} for name, value in outputs.items()}}


def build_template():
    return template()


if __name__ == "__main__":
    (ROOT / "control_plane.template.json").write_text(json.dumps(template(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("control_plane.template.json generated; no AWS calls")
