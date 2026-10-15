variable "installation_id" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,30}$", var.installation_id))
    error_message = "installation_id must be an account-unique lowercase name of 3-31 characters."
  }
}
variable "account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "Provide the company account ID in an external variable file."
  }
}
variable "control_region" { type = string }
variable "environment" {
  type    = string
  default = "prod"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,15}$", var.environment))
    error_message = "Use a lowercase environment name of 2-16 characters."
  }
}
variable "discovery_regions" {
  type = set(string)
  validation {
    condition     = length(var.discovery_regions) > 0 && length(var.discovery_regions) <= 10 && alltrue([for r in var.discovery_regions : can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]$", r))])
    error_message = "Explicitly select 1-10 AWS regions."
  }
}
variable "installation_scope" {
  type    = string
  default = "tagged"
  validation {
    condition     = contains(["tagged", "all-supported"], var.installation_scope) && (var.installation_scope != "all-supported" || var.acknowledge_all_supported)
    error_message = "all-supported discovery requires explicit acknowledgement."
  }
}
variable "acknowledge_all_supported" {
  type    = bool
  default = false
}
variable "response_mode" {
  type    = string
  default = "observe"
  validation {
    condition     = contains(["observe", "enforce"], var.response_mode) && ((var.response_mode == "observe" && var.default_dry_run) || var.acknowledge_enforcement) && (var.response_mode != "enforce" || contains(var.allowed_actions, "block_ip"))
    error_message = "Use observe/dry-run or explicitly acknowledge enforcement; enforce also requires allowed_actions to include block_ip."
  }
}
variable "allowed_actions" {
  type    = set(string)
  default = ["monitor", "block_ip"]
  validation {
    condition     = length(var.allowed_actions) > 0 && length(setsubtract(var.allowed_actions, toset(["monitor", "block_ip"]))) == 0
    error_message = "The HTTP platform supports monitor and block_ip, not EC2 isolation."
  }
}
variable "principal_scopes" {
  type    = list(any)
  default = []
  validation {
    condition     = length(var.principal_scopes) == 0
    error_message = "The CloudTrail principal adapter is not installed; principal_scopes must be empty."
  }
}
variable "exclude_tags" {
  type    = map(string)
  default = { "security:exclude" = "true" }
  validation {
    condition     = length(var.exclude_tags) <= 50 && alltrue([for key, value in var.exclude_tags : length(key) >= 1 && length(key) <= 128 && length(value) <= 256])
    error_message = "Use at most 50 exclusion tags with keys of 1-128 characters and values of at most 256 characters."
  }
  validation {
    condition     = length(base64encode(jsonencode(var.exclude_tags))) * 3 / 4 - length(regexall("=", base64encode(jsonencode(var.exclude_tags)))) <= 1536
    error_message = "The compact UTF-8 exclude_tags JSON must not exceed 1536 bytes."
  }
}
variable "automatic_onboarding_enabled" {
  type    = bool
  default = false
}
variable "default_dry_run" {
  type    = bool
  default = true
}
variable "acknowledge_enforcement" {
  type    = bool
  default = false
}
variable "dashboard_origin" {
  type    = string
  default = ""
  validation {
    condition     = var.dashboard_origin == "" || can(regex("^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$", var.dashboard_origin))
    error_message = "Use an HTTPS origin without a path, or the provisioned API endpoint."
  }
}
variable "runtime_zip_path" {
  type    = string
  default = "../build/release/runtime.zip"
}
variable "dashboard_zip_path" {
  type    = string
  default = "../build/release/dashboard.zip"
}
variable "release_id" {
  type = string
  validation {
    condition     = can(regex("^[a-f0-9]{64}$", var.release_id))
    error_message = "Use the reviewed release manifest's SHA-256 release_id."
  }
}
variable "artifact_key_prefix" {
  description = "Stable versioned package prefix. Preserve the previous prefix when adopting an existing installation."
  type        = string
  default     = "packages"
  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$", var.artifact_key_prefix)) && !endswith(var.artifact_key_prefix, "/") && !strcontains(var.artifact_key_prefix, "..")
    error_message = "Use a stable relative S3 package prefix without a trailing slash or parent traversal."
  }
}
variable "slack_secret_arn" {
  type    = string
  default = ""
  validation {
    condition = (var.slack_secret_arn == "" && var.slack_channel_id == "") || (
      var.slack_channel_id != "" && can(regex("^arn:aws:secretsmanager:${var.control_region}:${var.account_id}:secret:[^*?[:space:]]+$", var.slack_secret_arn))
    )
    error_message = "Use a same-account/control-region Secret ARN and channel together; never supply a token value."
  }
}
variable "slack_channel_id" {
  type    = string
  default = ""
}
variable "slack_secret_key_arn" {
  type    = string
  default = ""
}
variable "model_arn" {
  type    = string
  default = ""
}
variable "enable_nacl_response" {
  type    = bool
  default = false
}
variable "log_retention_days" {
  type    = number
  default = 90
}
variable "audit_retention_days" {
  type    = number
  default = 365
  validation {
    condition     = var.audit_retention_days >= 90
    error_message = "Retain audit records for at least 90 days."
  }
}
variable "physical_names" {
  description = "Migration-only physical names, stored outside the repository. IDs and ARNs are not naming overrides."
  type = object({
    foundation = optional(map(string), {})
    governance = optional(map(string), {})
    ingress    = optional(map(map(string)), {})
  })
  default = {}
}

check "explicit_scope_and_response" {
  assert {
    condition     = var.installation_scope != "all-supported" || var.acknowledge_all_supported
    error_message = "all-supported requires acknowledge_all_supported=true."
  }
  assert {
    condition     = (var.response_mode == "observe" && var.default_dry_run) || var.acknowledge_enforcement
    error_message = "Enforcement settings require explicit company acknowledgement."
  }
  assert {
    condition     = (var.slack_secret_arn == "") == (var.slack_channel_id == "")
    error_message = "Configure both Slack Secret ARN and channel, or leave both empty."
  }
  assert {
    condition     = var.slack_secret_arn == "" || can(regex("^arn:aws:secretsmanager:${var.control_region}:${var.account_id}:secret:[^*?[:space:]]+$", var.slack_secret_arn))
    error_message = "Slack Secret must belong to the selected company account and control region."
  }
}
