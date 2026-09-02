# S3 Bucket for Encrypted Raw Inbound Emails
resource "aws_s3_bucket" "raw_mail" {
  bucket        = "${var.name_prefix}-raw-mail-${var.environment}"
  force_destroy = var.environment == "dev" ? true : false

  tags = {
    Name        = "${var.name_prefix}-raw-mail"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_versioning" "raw_mail" {
  bucket = aws_s3_bucket.raw_mail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "raw_mail" {
  bucket = aws_s3_bucket.raw_mail.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "raw_mail" {
  bucket = aws_s3_bucket.raw_mail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "raw_mail" {
  bucket = aws_s3_bucket.raw_mail.id

  rule {
    id     = "raw-mail-lifecycle"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "GLACIER"
    }

    expiration {
      days = var.raw_mail_retention_days
    }
  }
}

# S3 Bucket for Quarantined Suspicious / Malicious Emails
resource "aws_s3_bucket" "quarantine" {
  bucket        = "${var.name_prefix}-quarantine-${var.environment}"
  force_destroy = var.environment == "dev" ? true : false

  tags = {
    Name        = "${var.name_prefix}-quarantine"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_versioning" "quarantine" {
  bucket = aws_s3_bucket.quarantine.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "quarantine" {
  bucket = aws_s3_bucket.quarantine.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "quarantine" {
  bucket = aws_s3_bucket.quarantine.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "quarantine" {
  bucket = aws_s3_bucket.quarantine.id

  rule {
    id     = "quarantine-expiration"
    status = "Enabled"

    expiration {
      days = var.quarantine_retention_days
    }
  }
}
