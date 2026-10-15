locals {
  regions         = setunion(var.discovery_regions, toset([var.control_region, "us-east-1"]))
  ingress_regions = setsubtract(local.regions, toset([var.control_region]))
  governance_name = "${var.installation_id}-governance"
  # These names are known before either module is created. Avoid mutual module
  # dependencies between dashboard approval, CMK grants and governance policies.
  name_specs = {
    dashboard          = { base = "${var.installation_id}-dashboardfunction", limit = 64 }
    dashboard_role     = { base = "${var.installation_id}-${var.control_region}-dashboardrole", limit = 64 }
    control_ingress    = { base = "${var.installation_id}-securitylogingressfunction", limit = 64 }
    discovery_schedule = { base = "${var.installation_id}-discoveryschedule", limit = 64 }
    discovery_event    = { base = "${var.installation_id}-discoveryresourceevent", limit = 64 }
    publication        = { base = "${local.governance_name}-publicationrule", limit = 64 }
    signal             = { base = "${local.governance_name}-servicesignalrule", limit = 64 }
    terminal           = { base = "${local.governance_name}-terminalrule", limit = 64 }
    reconcile          = { base = "${local.governance_name}-reconcileschedule", limit = 64 }
    bus                = { base = "${var.installation_id}-securityeventbus", limit = 256 }
  }
  default_names          = { for key, spec in local.name_specs : key => length(spec.base) <= spec.limit ? spec.base : "${substr(spec.base, 0, spec.limit - 9)}-${substr(sha256(spec.base), 0, 8)}" }
  dashboard_name         = lookup(var.physical_names.foundation, "DashboardFunction", local.default_names.dashboard)
  dashboard_role_name    = lookup(var.physical_names.foundation, "DashboardRole", local.default_names.dashboard_role)
  event_bus_name         = lookup(var.physical_names.foundation, "SecurityEventBus", local.default_names.bus)
  approval_name          = lookup(var.physical_names.governance, "ApprovalFunction", "${local.governance_name}-approval")
  approval_alias_arn     = "arn:aws:lambda:${var.control_region}:${var.account_id}:function:${local.approval_name}:live"
  dashboard_function_arn = "arn:aws:lambda:${var.control_region}:${var.account_id}:function:${local.dashboard_name}"
  dashboard_role_arn     = "arn:aws:iam::${var.account_id}:role/${local.dashboard_role_name}"
  ingress_default_bases  = { for region in local.regions : region => "${region == var.control_region ? var.installation_id : "${var.installation_id}-ingress"}-securitylogingressfunction" }
  ingress_function_names = { for region, base in local.ingress_default_bases : region => lookup(region == var.control_region ? var.physical_names.foundation : lookup(var.physical_names.ingress, region, {}), "SecurityLogIngressFunction", length(base) <= 64 ? base : "${substr(base, 0, 55)}-${substr(sha256(base), 0, 8)}") }
  ingress_arns           = { for region, name in local.ingress_function_names : region => "arn:aws:lambda:${region}:${var.account_id}:function:${name}" }
  ops_rule_names = {
    PublicationRule   = lookup(var.physical_names.governance, "PublicationRule", local.default_names.publication)
    ServiceSignalRule = lookup(var.physical_names.governance, "ServiceSignalRule", local.default_names.signal)
    TerminalRule      = lookup(var.physical_names.governance, "TerminalRule", local.default_names.terminal)
    ReconcileSchedule = lookup(var.physical_names.governance, "ReconcileSchedule", local.default_names.reconcile)
    IngressOpsRule    = lookup(var.physical_names.governance, "IngressOpsRule", "${var.installation_id}-ingress-ops")
  }
  ops_rule_arns       = [for logical in ["PublicationRule", "ServiceSignalRule", "TerminalRule", "ReconcileSchedule", "IngressOpsRule"] : "arn:aws:events:${var.control_region}:${var.account_id}:rule/${contains(["TerminalRule", "ReconcileSchedule"], logical) ? "" : "${local.event_bus_name}/"}${local.ops_rule_names[logical]}"]
  discovery_rule_arns = [for name in [lookup(var.physical_names.foundation, "DiscoverySchedule", local.default_names.discovery_schedule), lookup(var.physical_names.foundation, "DiscoveryResourceEvent", local.default_names.discovery_event)] : "arn:aws:events:${var.control_region}:${var.account_id}:rule/${name}"]
  ingress_alarm_names = join(",", flatten([for region in sort(tolist(local.regions)) : [for suffix in ["errors", "async-dropped", "destination-failures", "dlq-depth"] : "${var.installation_id}-${region}-log-ingress-${suffix}"]]))
  runtime_sha256      = filebase64sha256(var.runtime_zip_path)
  dashboard_sha256    = filebase64sha256(var.dashboard_zip_path)
}

module "artifacts" {
  source             = "./modules/artifacts"
  for_each           = local.regions
  account_id         = var.account_id
  region             = each.value
  installation_id    = var.installation_id
  release_id         = var.release_id
  key_prefix         = var.artifact_key_prefix
  runtime_zip_path   = var.runtime_zip_path
  dashboard_zip_path = var.dashboard_zip_path
  include_dashboard  = each.value == var.control_region
}

module "foundation" {
  source          = "./modules/foundation"
  stack_name      = var.installation_id
  installation_id = var.installation_id
  region          = var.control_region
  account_id      = var.account_id
  physical_names  = var.physical_names.foundation
  parameters = {
    Environment                  = var.environment
    DashboardOrigin              = var.dashboard_origin
    DashboardRoleName            = ""
    DashboardCodeBucket          = module.artifacts[var.control_region].bucket
    DashboardCodeKey             = module.artifacts[var.control_region].dashboard_key
    DashboardCodeVersion         = module.artifacts[var.control_region].dashboard_version
    DashboardHandler             = "lambda.handler"
    ApprovalFunctionArn          = local.approval_alias_arn
    AutomaticOnboardingEnabled   = tostring(var.automatic_onboarding_enabled)
    InstallationScope            = var.installation_scope
    DiscoveryRegions             = sort(tolist(var.discovery_regions))
    ResponseMode                 = var.response_mode
    AllowedActions               = sort(tolist(var.allowed_actions))
    PrincipalScopesJson          = jsonencode(var.principal_scopes)
    ExcludeTagsJson              = jsonencode(var.exclude_tags)
    IngressArnsJson              = jsonencode(local.ingress_arns)
    OpsEventBridgeRuleArns       = local.ops_rule_arns
    DiscoveryEventBridgeRuleArns = local.discovery_rule_arns
    DiscoveryCodeBucket          = module.artifacts[var.control_region].bucket
    DiscoveryCodeKey             = module.artifacts[var.control_region].runtime_key
    DiscoveryCodeVersion         = module.artifacts[var.control_region].runtime_version
    DiscoveryHandler             = "runtime.discovery.handler"
    DiscoveryRuntime             = "python3.13"
    DiscoveryScheduleExpression  = "rate(5 minutes)"
    LogRetentionDays             = var.log_retention_days
    AuditRetentionDays           = var.audit_retention_days
  }
}

module "ingress" {
  source          = "./modules/ingress"
  for_each        = local.ingress_regions
  stack_name      = "${var.installation_id}-ingress"
  installation_id = var.installation_id
  region          = each.value
  account_id      = var.account_id
  physical_names  = lookup(var.physical_names.ingress, each.value, {})
  parameters = {
    CodeBucket                = module.artifacts[each.value].bucket
    CodeKey                   = module.artifacts[each.value].runtime_key
    CodeVersion               = module.artifacts[each.value].runtime_version
    RegistryTableName         = module.foundation.RegistryTableName
    RegistryTableArn          = module.foundation.RegistryTableArn
    ExpectedActivityTableName = module.foundation.ExpectedActivityTableName
    ExpectedActivityTableArn  = module.foundation.ExpectedActivityTableArn
    CasesTableName            = module.foundation.CasesTableName
    CasesTableArn             = module.foundation.CasesTableArn
    SecurityEventBusArn       = module.foundation.SecurityEventBusArn
    AuditBucketName           = module.foundation.AuditBucketName
    AuditBucketArn            = module.foundation.AuditBucketArn
    AuditKeyArn               = module.foundation.AuditKeyArn
    ControlPlaneRegion        = var.control_region
    LeaseTableName            = module.foundation.LeaseTableName
    LeaseTableArn             = module.foundation.LeaseTableArn
    InstallationId            = var.installation_id
    Environment               = var.environment
    LogRetentionDays          = var.log_retention_days
  }
}

module "governance" {
  source          = "./modules/governance"
  stack_name      = local.governance_name
  installation_id = var.installation_id
  region          = var.control_region
  account_id      = var.account_id
  physical_names  = var.physical_names.governance
  parameters = {
    RuntimeCodeBucket         = module.artifacts[var.control_region].bucket
    RuntimeCodeKey            = module.artifacts[var.control_region].runtime_key
    RuntimeCodeVersion        = module.artifacts[var.control_region].runtime_version
    RuntimeCodeSha256         = local.runtime_sha256
    RegistryTableName         = module.foundation.RegistryTableName
    RegistryTableArn          = module.foundation.RegistryTableArn
    CasesTableName            = module.foundation.CasesTableName
    CasesTableArn             = module.foundation.CasesTableArn
    CasesTableStreamArn       = module.foundation.CasesTableStreamArn
    OperationsTableName       = module.foundation.ResponseOperationsTableName
    OperationsTableArn        = module.foundation.ResponseOperationsTableArn
    LeaseTableName            = module.foundation.LeaseTableName
    LeaseTableArn             = module.foundation.LeaseTableArn
    ExpectedActivityTableName = module.foundation.ExpectedActivityTableName
    ExpectedActivityTableArn  = module.foundation.ExpectedActivityTableArn
    ReceiptTableName          = module.foundation.PublicationReceiptsTableName
    ReceiptTableArn           = module.foundation.PublicationReceiptsTableArn
    AuditBucketName           = module.foundation.AuditBucketName
    AuditBucketArn            = module.foundation.AuditBucketArn
    AuditKeyArn               = module.foundation.AuditKeyArn
    SecurityEventBusName      = module.foundation.SecurityEventBusName
    SecurityEventBusArn       = module.foundation.SecurityEventBusArn
    OpsTopicArn               = module.foundation.OpsTopicArn
    OpsKeyArn                 = module.foundation.OpsKeyArn
    InstallationId            = var.installation_id
    DashboardFunctionArn      = local.dashboard_function_arn
    DashboardRoleArn          = local.dashboard_role_arn
    IngressAlarmNames         = local.ingress_alarm_names
    RuntimeConfigRevision     = var.release_id
    Environment               = var.environment
    DefaultDryRun             = tostring(var.default_dry_run)
    LogRetentionDays          = var.log_retention_days
    SlackSecretArn            = var.slack_secret_arn
    SlackChannelId            = var.slack_channel_id
    SlackSecretKeyArn         = var.slack_secret_key_arn
    ModelArn                  = var.model_arn
    NaclResponseEnabled       = tostring(var.enable_nacl_response)
  }
}

check "static_wiring" {
  assert {
    condition     = module.foundation.DashboardFunctionArn == local.dashboard_function_arn && module.foundation.DashboardRoleArn == local.dashboard_role_arn && module.governance.ApprovalFunctionArn == local.approval_alias_arn
    error_message = "A predicted function/role/alias identity differs from the deployed module. Do not enable onboarding."
  }
  assert {
    condition     = module.foundation.SecurityLogIngressArn == local.ingress_arns[var.control_region] && alltrue([for region in local.ingress_regions : module.ingress[region].SecurityLogIngressArn == local.ingress_arns[region]])
    error_message = "A regional ingress identity differs from the trusted discovery map."
  }
}
