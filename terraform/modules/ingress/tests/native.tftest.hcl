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
    stack_name      = "offline-platform"
    installation_id = "offline-platform"
    parameters = {
      "CodeBucket"                = "offline-artifacts"
      "CodeKey"                   = "offline-value"
      "RegistryTableName"         = "offline-value"
      "RegistryTableArn"          = format("arn:aws:dynamodb:us-east-1:%s:table/offline-table", join("", [for n in range(12) : "0"]))
      "ExpectedActivityTableName" = "offline-value"
      "ExpectedActivityTableArn"  = format("arn:aws:dynamodb:us-east-1:%s:table/offline-table", join("", [for n in range(12) : "0"]))
      "CasesTableName"            = "offline-value"
      "CasesTableArn"             = format("arn:aws:dynamodb:us-east-1:%s:table/offline-table", join("", [for n in range(12) : "0"]))
      "SecurityEventBusArn"       = format("arn:aws:events:us-east-1:%s:event-bus/offline-security", join("", [for n in range(12) : "0"]))
      "AuditBucketName"           = "offline-value"
      "AuditBucketArn"            = "arn:aws:s3:::offline-audit"
      "AuditKeyArn"               = format("arn:aws:kms:us-east-1:%s:key/00000000-0000-4000-8000-aaaaaaaaaaaa", join("", [for n in range(12) : "0"]))
      "ControlPlaneRegion"        = "us-east-1"
      "LeaseTableName"            = "offline-value"
      "LeaseTableArn"             = format("arn:aws:dynamodb:us-east-1:%s:table/offline-table", join("", [for n in range(12) : "0"]))
      "InstallationId"            = "offline-platform"
    }
  }
  assert {
    condition     = aws_lambda_function.SecurityLogIngressFunction.timeout == 300
    error_message = "Regional ingress must keep the five-minute budget."
  }
  assert {
    condition     = aws_sqs_queue.SecurityLogIngressFailureQueue.message_retention_seconds == 1209600
    error_message = "Failure messages need fourteen-day retention."
  }
  assert {
    condition     = length(aws_cloudwatch_event_target.IngressAlarmStateChangeRelay_Target0.retry_policy) == 0
    error_message = "Event-bus targets must not have unsupported retry policy."
  }
}

run "alternate_ingress_region" {
  command = plan
  variables {
    region          = "eu-west-1"
    account_id      = join("", [for n in range(12) : "0"])
    stack_name      = "offline-platform"
    installation_id = "offline-platform"
    parameters = {
      "CodeBucket"                = "offline-artifacts"
      "CodeKey"                   = "offline-value"
      "RegistryTableName"         = "offline-value"
      "RegistryTableArn"          = format("arn:aws:dynamodb:us-east-1:%s:table/offline-table", join("", [for n in range(12) : "0"]))
      "ExpectedActivityTableName" = "offline-value"
      "ExpectedActivityTableArn"  = format("arn:aws:dynamodb:us-east-1:%s:table/offline-table", join("", [for n in range(12) : "0"]))
      "CasesTableName"            = "offline-value"
      "CasesTableArn"             = format("arn:aws:dynamodb:us-east-1:%s:table/offline-table", join("", [for n in range(12) : "0"]))
      "SecurityEventBusArn"       = format("arn:aws:events:us-east-1:%s:event-bus/offline-security", join("", [for n in range(12) : "0"]))
      "AuditBucketName"           = "offline-value"
      "AuditBucketArn"            = "arn:aws:s3:::offline-audit"
      "AuditKeyArn"               = format("arn:aws:kms:us-east-1:%s:key/00000000-0000-4000-8000-aaaaaaaaaaaa", join("", [for n in range(12) : "0"]))
      "ControlPlaneRegion"        = "us-east-1"
      "LeaseTableName"            = "offline-value"
      "LeaseTableArn"             = format("arn:aws:dynamodb:us-east-1:%s:table/offline-table", join("", [for n in range(12) : "0"]))
      "InstallationId"            = "offline-platform"
    }
  }
  assert {
    condition     = aws_lambda_function.SecurityLogIngressFunction.region == "eu-west-1"
    error_message = "Resource-level region must select the ingress region."
  }

  assert {
    condition     = strcontains(aws_iam_role.SecurityLogIngressRole.name, "eu-west-1")
    error_message = "Global IAM ingress role names must be unique per region."
  }

  assert {
    condition     = aws_lambda_function.SecurityLogIngressFunction.environment[0].variables["CONTROL_PLANE_REGION"] == "us-east-1"
    error_message = "The central SDK endpoint must remain the control region."
  }
}
