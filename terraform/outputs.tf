output "deployment" {
  description = "Export with terraform output -json to a company-private file for operational validation."
  precondition {
    condition     = length(base64encode(local.ingress_alarm_names)) * 3 / 4 - length(regexall("=", base64encode(local.ingress_alarm_names))) <= 4096
    error_message = "IngressAlarmNames exceeds the supported 4096-byte input budget; reduce discovery regions."
  }
  precondition {
    condition     = module.foundation.DashboardFunctionArn == local.dashboard_function_arn && module.foundation.DashboardRoleArn == local.dashboard_role_arn && module.governance.ApprovalFunctionArn == local.approval_alias_arn
    error_message = "Predicted approval/dashboard wiring does not match the actual platform."
  }
  precondition {
    condition     = module.foundation.SecurityLogIngressArn == local.ingress_arns[var.control_region] && alltrue([for region in local.ingress_regions : module.ingress[region].SecurityLogIngressArn == local.ingress_arns[region]])
    error_message = "Regional ingress wiring does not match the actual platform."
  }
  value = {
    schema_version               = "2.0"
    deployment_method            = "terraform"
    installation_id              = var.installation_id
    account_id                   = var.account_id
    control_plane_region         = var.control_region
    release_id                   = var.release_id
    runtime_code_sha256          = local.runtime_sha256
    dashboard_code_sha256        = local.dashboard_sha256
    automatic_onboarding_enabled = var.automatic_onboarding_enabled
    default_dry_run              = var.default_dry_run
    ingress_arns                 = local.ingress_arns
    outputs                      = merge(module.foundation, module.governance)
  }
}
output "dashboard_url" { value = module.foundation.DashboardUrl }
output "installation_id" { value = var.installation_id }
