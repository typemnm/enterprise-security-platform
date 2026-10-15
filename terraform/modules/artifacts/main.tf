variable "account_id" { type = string }
variable "region" { type = string }
variable "installation_id" { type = string }
variable "release_id" { type = string }
variable "key_prefix" { type = string }
variable "runtime_zip_path" { type = string }
variable "dashboard_zip_path" { type = string }
variable "include_dashboard" { type = bool }

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 6.69.0, < 7.0" }
  }
}
locals {
  bucket = "security-artifacts-${var.account_id}-${var.region}-${substr(sha256(var.installation_id), 0, 10)}"
  tags   = { ManagedBy = "enterprise-security", InstallationId = var.installation_id }
}
resource "aws_s3_bucket" "release" {
  region        = var.region
  bucket        = local.bucket
  force_destroy = false
  tags          = local.tags
  lifecycle { prevent_destroy = true }
}
resource "aws_s3_bucket_public_access_block" "release" {
  region                  = var.region
  bucket                  = aws_s3_bucket.release.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_ownership_controls" "release" {
  region = var.region
  bucket = aws_s3_bucket.release.id
  rule { object_ownership = "BucketOwnerEnforced" }
}
resource "aws_s3_bucket_versioning" "release" {
  region = var.region
  bucket = aws_s3_bucket.release.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "release" {
  region = var.region
  bucket = aws_s3_bucket.release.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}
resource "aws_s3_bucket_lifecycle_configuration" "release" {
  region     = var.region
  bucket     = aws_s3_bucket.release.id
  depends_on = [aws_s3_bucket_versioning.release]
  rule {
    id     = "ReleaseRetention"
    status = "Enabled"
    filter { prefix = "" }
    noncurrent_version_expiration { noncurrent_days = 90 }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}
resource "aws_s3_bucket_policy" "release" {
  region = var.region
  bucket = aws_s3_bucket.release.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect    = "Deny", Principal = "*", Action = "s3:*",
    Resource  = [aws_s3_bucket.release.arn, "${aws_s3_bucket.release.arn}/*"],
    Condition = { Bool = { "aws:SecureTransport" = "false" } }
  }] })
}
resource "aws_s3_object" "runtime" {
  region             = var.region
  bucket             = aws_s3_bucket.release.id
  key                = "${var.key_prefix}/runtime.zip"
  source             = var.runtime_zip_path
  source_hash        = filebase64sha256(var.runtime_zip_path)
  checksum_algorithm = "SHA256"
  metadata           = { sha256 = filesha256(var.runtime_zip_path), release_id = var.release_id }
  depends_on         = [aws_s3_bucket_versioning.release, aws_s3_bucket_server_side_encryption_configuration.release]
}
resource "aws_s3_object" "dashboard" {
  count              = var.include_dashboard ? 1 : 0
  region             = var.region
  bucket             = aws_s3_bucket.release.id
  key                = "${var.key_prefix}/dashboard.zip"
  source             = var.dashboard_zip_path
  source_hash        = filebase64sha256(var.dashboard_zip_path)
  checksum_algorithm = "SHA256"
  metadata           = { sha256 = filesha256(var.dashboard_zip_path), release_id = var.release_id }
  depends_on         = [aws_s3_bucket_versioning.release, aws_s3_bucket_server_side_encryption_configuration.release]
}
output "bucket" { value = aws_s3_bucket.release.id }
output "runtime_key" { value = aws_s3_object.runtime.key }
output "runtime_version" { value = aws_s3_object.runtime.version_id }
output "dashboard_key" { value = var.include_dashboard ? aws_s3_object.dashboard[0].key : "" }
output "dashboard_version" { value = var.include_dashboard ? aws_s3_object.dashboard[0].version_id : "" }
