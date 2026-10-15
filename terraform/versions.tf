terraform {
  required_version = ">= 1.12, < 2.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.69.0, < 7.0"
    }
  }
  backend "s3" {}
}

provider "aws" {
  region              = var.control_region
  allowed_account_ids = [var.account_id]
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

check "account" {
  assert {
    condition     = data.aws_caller_identity.current.account_id == var.account_id && data.aws_partition.current.partition == "aws"
    error_message = "Use the explicitly selected commercial AWS company account."
  }
}
