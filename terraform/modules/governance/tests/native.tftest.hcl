mock_provider "aws" {
  override_during = plan
  mock_data "aws_partition" {
    defaults = { partition = "aws", dns_suffix = "amazonaws.com" }
  }
  mock_resource "aws_lambda_function" {
    defaults = { version = "1" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { id = "offline-audit", arn = "arn:aws:s3:::offline-audit" }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = format("arn:aws:kms:us-east-1:%s:key/00000000-0000-4000-8000-aaaaaaaaaaaa", join("", [for n in range(12) : "0"])) }
  }
  mock_resource "aws_sns_topic" {
    defaults = { arn = format("arn:aws:sns:us-east-1:%s:offline-ops", join("", [for n in range(12) : "0"])) }
  }
  mock_resource "aws_lambda_alias" {
    defaults = { arn = format("arn:aws:lambda:us-east-1:%s:function:offline-function:live", join("", [for n in range(12) : "0"])) }
  }
  mock_resource "aws_sqs_queue" {
    defaults = { arn = format("arn:aws:sqs:us-east-1:%s:offline-queue", join("", [for n in range(12) : "0"])), url = format("https://sqs.us-east-1.amazonaws.com/%s/offline-queue", join("", [for n in range(12) : "0"])) }
  }
  mock_resource "aws_sfn_state_machine" {
    defaults = { arn = format("arn:aws:states:us-east-1:%s:stateMachine:offline-pipeline", join("", [for n in range(12) : "0"])) }
  }
}

run "native_safe_defaults" {
  command = plan
  variables {
    region          = "us-east-1"
    account_id      = join("", [for n in range(12) : "0"])
    stack_name      = "offline-platform-governance"
    installation_id = "offline-platform"
    parameters = {
      "RuntimeCodeBucket"         = "offline-artifacts"
      "RuntimeCodeKey"            = "offline-value"
      "RuntimeCodeVersion"        = "offline-value"
      "RuntimeCodeSha256"         = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
      "RegistryTableName"         = "offline-value"
      "RegistryTableArn"          = format("arn:aws:dynamodb:us-east-1:%s:table/offline-table", join("", [for n in range(12) : "0"]))
      "CasesTableName"            = "offline-value"
      "CasesTableArn"             = format("arn:aws:dynamodb:us-east-1:%s:table/offline-table", join("", [for n in range(12) : "0"]))
      "CasesTableStreamArn"       = format("arn:aws:dynamodb:us-east-1:%s:table/offline-cases/stream/2026-01-01T00:00:00.000", join("", [for n in range(12) : "0"]))
      "OperationsTableName"       = "offline-value"
      "OperationsTableArn"        = format("arn:aws:dynamodb:us-east-1:%s:table/offline-table", join("", [for n in range(12) : "0"]))
      "LeaseTableName"            = "offline-value"
      "LeaseTableArn"             = format("arn:aws:dynamodb:us-east-1:%s:table/offline-table", join("", [for n in range(12) : "0"]))
      "ExpectedActivityTableName" = "offline-value"
      "ExpectedActivityTableArn"  = format("arn:aws:dynamodb:us-east-1:%s:table/offline-table", join("", [for n in range(12) : "0"]))
      "ReceiptTableName"          = "offline-value"
      "ReceiptTableArn"           = format("arn:aws:dynamodb:us-east-1:%s:table/offline-table", join("", [for n in range(12) : "0"]))
      "AuditBucketName"           = "offline-value"
      "AuditBucketArn"            = "arn:aws:s3:::offline-audit"
      "AuditKeyArn"               = format("arn:aws:kms:us-east-1:%s:key/00000000-0000-4000-8000-aaaaaaaaaaaa", join("", [for n in range(12) : "0"]))
      "SecurityEventBusName"      = "offline-value"
      "SecurityEventBusArn"       = format("arn:aws:events:us-east-1:%s:event-bus/offline-security", join("", [for n in range(12) : "0"]))
      "OpsTopicArn"               = format("arn:aws:sns:us-east-1:%s:offline-ops", join("", [for n in range(12) : "0"]))
      "OpsKeyArn"                 = format("arn:aws:kms:us-east-1:%s:key/00000000-0000-4000-8000-aaaaaaaaaaaa", join("", [for n in range(12) : "0"]))
      "InstallationId"            = "offline-platform"
      "DashboardFunctionArn"      = format("arn:aws:lambda:us-east-1:%s:function:offline-dashboard", join("", [for n in range(12) : "0"]))
      "DashboardRoleArn"          = format("arn:aws:iam::%s:role/offline-dashboard", join("", [for n in range(12) : "0"]))
      "IngressAlarmNames"         = ["offline-alarm"]
    }
  }
  assert {
    condition     = aws_lambda_event_source_mapping.NotifierQueueMapping.enabled == false
    error_message = "Slack ingestion must remain disabled without credentials."
  }
  assert {
    condition     = aws_lambda_function.BlockerFunction.publish == true
    error_message = "Runtime must publish immutable versions."
  }
  assert {
    condition     = aws_lambda_function.BlockerFunction.environment[0].variables["DEFAULT_DRY_RUN"] == "true"
    error_message = "The blocker must default to dry run."
  }
  assert {
    condition     = jsondecode(aws_sfn_state_machine.PipelineStateMachine.definition).States.PrepareCase.Parameters.FunctionName == aws_lambda_alias.PipelineAlias.arn
    error_message = "ASL substitutions must point to reviewed aliases."
  }
}

run "configured_optional_integrations" {
  command = plan
  variables {
    region          = "us-east-1"
    account_id      = join("", [for n in range(12) : "0"])
    stack_name      = "offline-platform-governance"
    installation_id = "offline-platform"
    parameters = {
      "RuntimeCodeBucket"         = "offline-artifacts"
      "RuntimeCodeKey"            = "offline-value"
      "RuntimeCodeVersion"        = "offline-value"
      "RuntimeCodeSha256"         = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
      "RegistryTableName"         = "offline-value"
      "RegistryTableArn"          = format("arn:aws:dynamodb:us-east-1:%s:table/offline-table", join("", [for n in range(12) : "0"]))
      "CasesTableName"            = "offline-value"
      "CasesTableArn"             = format("arn:aws:dynamodb:us-east-1:%s:table/offline-table", join("", [for n in range(12) : "0"]))
      "CasesTableStreamArn"       = format("arn:aws:dynamodb:us-east-1:%s:table/offline-cases/stream/2026-01-01T00:00:00.000", join("", [for n in range(12) : "0"]))
      "OperationsTableName"       = "offline-value"
      "OperationsTableArn"        = format("arn:aws:dynamodb:us-east-1:%s:table/offline-table", join("", [for n in range(12) : "0"]))
      "LeaseTableName"            = "offline-value"
      "LeaseTableArn"             = format("arn:aws:dynamodb:us-east-1:%s:table/offline-table", join("", [for n in range(12) : "0"]))
      "ExpectedActivityTableName" = "offline-value"
      "ExpectedActivityTableArn"  = format("arn:aws:dynamodb:us-east-1:%s:table/offline-table", join("", [for n in range(12) : "0"]))
      "ReceiptTableName"          = "offline-value"
      "ReceiptTableArn"           = format("arn:aws:dynamodb:us-east-1:%s:table/offline-table", join("", [for n in range(12) : "0"]))
      "AuditBucketName"           = "offline-value"
      "AuditBucketArn"            = "arn:aws:s3:::offline-audit"
      "AuditKeyArn"               = format("arn:aws:kms:us-east-1:%s:key/00000000-0000-4000-8000-aaaaaaaaaaaa", join("", [for n in range(12) : "0"]))
      "SecurityEventBusName"      = "offline-value"
      "SecurityEventBusArn"       = format("arn:aws:events:us-east-1:%s:event-bus/offline-security", join("", [for n in range(12) : "0"]))
      "OpsTopicArn"               = format("arn:aws:sns:us-east-1:%s:offline-ops", join("", [for n in range(12) : "0"]))
      "OpsKeyArn"                 = format("arn:aws:kms:us-east-1:%s:key/00000000-0000-4000-8000-aaaaaaaaaaaa", join("", [for n in range(12) : "0"]))
      "InstallationId"            = "offline-platform"
      "DashboardFunctionArn"      = format("arn:aws:lambda:us-east-1:%s:function:offline-dashboard", join("", [for n in range(12) : "0"]))
      "DashboardRoleArn"          = format("arn:aws:iam::%s:role/offline-dashboard", join("", [for n in range(12) : "0"]))
      "IngressAlarmNames"         = ["offline-alarm"]
      "SlackSecretArn"            = format("arn:aws:secretsmanager:us-east-1:%s:secret:offline-secret-abcdef", join("", [for n in range(12) : "0"]))
      "SlackSecretKeyArn"         = format("arn:aws:kms:us-east-1:%s:key/00000000-0000-4000-8000-aaaaaaaaaaaa", join("", [for n in range(12) : "0"]))
      "SlackChannelId"            = "C_OFFLINE"
      "ModelArn"                  = "arn:aws:bedrock:us-east-1::foundation-model/offline-model"
      "NaclResponseEnabled"       = "true"
      "DefaultDryRun"             = "false"
    }
    physical_names = {
      PipelineFunction     = "kept-pipeline"
      PipelineStateMachine = "kept-pipeline-state"
      BlockerFunction      = "kept-blocker"
    }
  }
  assert {
    condition     = aws_lambda_event_source_mapping.NotifierQueueMapping.enabled == true
    error_message = "Explicit Slack settings must enable the notifier mapping."
  }

  assert {
    condition     = aws_lambda_function.BlockerFunction.environment[0].variables["DEFAULT_DRY_RUN"] == "false"
    error_message = "Reviewed enforcement must reach the blocker."
  }

  assert {
    condition     = strcontains(aws_lambda_function.PipelineFunction.environment[0].variables["PIPELINE_STATE_MACHINE_ARN"], "stateMachine:kept-pipeline-state")
    error_message = "Runtime execution binding must follow an imported state-machine name."
  }

  assert {
    condition     = strcontains(aws_iam_role_policy.BlockerRole_Inline0.policy, "function:kept-blocker")
    error_message = "SDK permissions must follow the imported unqualified function ARN."
  }
  assert {
    condition     = aws_lambda_permission.ServiceSignalRulePermission.function_name == "kept-pipeline" && aws_lambda_permission.ServiceSignalRulePermission.qualifier == "live"
    error_message = "Alias permissions must preserve the imported base function plus qualifier identity."
  }
}
