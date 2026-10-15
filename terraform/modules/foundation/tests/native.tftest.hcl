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
      "DashboardCodeBucket" = "offline-artifacts"
      "DashboardCodeKey"    = "offline-value"
      "DiscoveryRegions"    = ["offline-alarm"]
      "DiscoveryCodeBucket" = "offline-artifacts"
      "DiscoveryCodeKey"    = "offline-value"
    }
  }
  assert {
    condition     = aws_lambda_function.SecurityLogIngressFunction.timeout == 300
    error_message = "Ingress must preserve the five-minute processing budget."
  }
  assert {
    condition     = aws_cognito_user_pool.AdminUserPool.mfa_configuration == "ON"
    error_message = "Cognito MFA must stay enabled."
  }
  assert {
    condition     = aws_cognito_user_pool_client.AdminClient.generate_secret == false
    error_message = "New dashboard browser clients must be public PKCE clients."
  }
  assert {
    condition     = aws_sqs_queue.DiscoveryDlq.max_message_size == 1048576
    error_message = "An unspecified queue size must preserve the current SQS API default."
  }
  assert {
    condition     = length(aws_iam_role_policy.DashboardSessionsPolicy) == 0
    error_message = "The optional external dashboard policy must not exist by default."
  }
  assert {
    condition     = length(aws_dynamodb_table.ResponseOperationsTable.ttl) == 0
    error_message = "Permanent response tombstones must not expire."
  }
}

run "overrides_and_enabled_events" {
  command = plan
  variables {
    region          = "us-east-1"
    account_id      = join("", [for n in range(12) : "0"])
    stack_name      = "offline-platform"
    installation_id = "offline-platform"
    parameters = {
      "DashboardCodeBucket"        = "offline-artifacts"
      "DashboardCodeKey"           = "offline-value"
      "DiscoveryRegions"           = ["offline-alarm"]
      "DiscoveryCodeBucket"        = "offline-artifacts"
      "DiscoveryCodeKey"           = "offline-value"
      "AutomaticOnboardingEnabled" = "true"
      "DashboardRoleName"          = "offline-external-role"
    }
    physical_names = {
      DiscoveryFunction           = "kept-discovery"
      DiscoverySchedule           = "kept-schedule"
      DashboardFunction           = "kept-dashboard"
      DiscoverySchedulePermission = "kept-permission-sid"
    }
  }
  assert {
    condition     = length(aws_iam_role_policy.DashboardSessionsPolicy) == 1
    error_message = "The external dashboard policy must follow its condition."
  }

  assert {
    condition     = aws_cloudwatch_event_rule.DiscoverySchedule.state == "ENABLED"
    error_message = "The verified activation flag must enable discovery events."
  }

  assert {
    condition     = strcontains(aws_iam_role_policy.DiscoverySdkPolicy.policy, "function:kept-discovery")
    error_message = "SourceFunctionArn must follow the physical function override."
  }

  assert {
    condition     = aws_lambda_permission.DiscoverySchedulePermission.statement_id == "kept-permission-sid"
    error_message = "An imported Lambda permission must retain its existing statement ID."
  }
}

run "ascii_environment_within_budget" {
  command = plan
  variables {
    region          = "us-east-1"
    account_id      = join("", [for n in range(12) : "0"])
    stack_name      = "offline-platform"
    installation_id = "offline-platform"
    parameters = {
      DashboardCodeBucket = "offline-artifacts"
      DashboardCodeKey    = "offline-value"
      DiscoveryRegions    = ["us-east-1"]
      DiscoveryCodeBucket = "offline-artifacts"
      DiscoveryCodeKey    = "offline-value"
      ExcludeTagsJson     = jsonencode({ sample = join("", [for n in range(1000) : "a"]) })
    }
  }
  assert {
    condition     = length(local.environment_DiscoveryFunction.EXCLUDE_TAGS_JSON) < 1100
    error_message = "A valid small ASCII environment should remain deployable."
  }
}

run "reject_utf8_environment_over_budget" {
  command = plan
  variables {
    region          = "us-east-1"
    account_id      = join("", [for n in range(12) : "0"])
    stack_name      = "offline-platform"
    installation_id = "offline-platform"
    parameters = {
      DashboardCodeBucket = "offline-artifacts"
      DashboardCodeKey    = "offline-value"
      DiscoveryRegions    = ["us-east-1"]
      DiscoveryCodeBucket = "offline-artifacts"
      DiscoveryCodeKey    = "offline-value"
      ExcludeTagsJson     = jsonencode({ sample = join("", [for n in range(1000) : "한글"]) })
    }
  }
  expect_failures = [aws_lambda_function.DiscoveryFunction]
}
