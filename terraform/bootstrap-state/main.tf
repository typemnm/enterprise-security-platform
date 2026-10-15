terraform {
  required_version = ">= 1.12, < 2.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 6.69.0, < 7.0" }
  }
  backend "local" {}
}
variable "region" { type = string }
variable "account_id" { type = string }
variable "state_bucket_name" { type = string }
variable "installation_id" { type = string }
provider "aws" {
  region              = var.region
  allowed_account_ids = [var.account_id]
}
data "aws_caller_identity" "current" {}
resource "aws_kms_key" "state" {
  description             = "Company-private Terraform state encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = { ManagedBy = "enterprise-security", InstallationId = var.installation_id, Purpose = "terraform-state" }
  policy                  = jsonencode({ Version = "2012-10-17", Statement = [{ Sid = "CompanyRootDelegation", Effect = "Allow", Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }, Action = "kms:*", Resource = "*" }] })
  lifecycle { prevent_destroy = true }
}
resource "aws_s3_bucket" "state" {
  bucket        = var.state_bucket_name
  force_destroy = false
  tags          = { ManagedBy = "enterprise-security", InstallationId = var.installation_id, Purpose = "terraform-state" }
  lifecycle { prevent_destroy = true }
}
resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.state.arn
    }
    bucket_key_enabled = true
  }
}
resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Deny", Principal = "*", Action = "s3:*", Resource = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"], Condition = { Bool = { "aws:SecureTransport" = "false" } } }] })
}
output "backend" {
  value = { bucket = aws_s3_bucket.state.id, region = var.region, encrypt = true, use_lockfile = true, kms_key_id = aws_kms_key.state.arn, key = "${var.installation_id}/terraform.tfstate" }
}
