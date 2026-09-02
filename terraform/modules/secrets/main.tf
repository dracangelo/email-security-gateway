# KMS Customer Managed Key for Email Gateway Encryption (Fernet Keys, S3, Secrets)
resource "aws_kms_key" "gateway_key" {
  description             = "KMS CMK for ${var.name_prefix}-${var.environment} encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name        = "${var.name_prefix}-kms-key"
    Environment = var.environment
  }
}

resource "aws_kms_alias" "gateway_key_alias" {
  name          = "alias/${var.name_prefix}-${var.environment}"
  target_key_id = aws_kms_key.gateway_key.key_id
}

# AWS Secrets Manager Secret for Application Secrets
resource "aws_secretsmanager_secret" "app_secrets" {
  name                    = "${var.name_prefix}-secrets-${var.environment}"
  kms_key_id              = aws_kms_key.gateway_key.arn
  recovery_window_in_days = var.environment == "dev" ? 0 : 30

  tags = {
    Name        = "${var.name_prefix}-secrets"
    Environment = var.environment
  }
}

# Default initial secret template schema (Values to be populated via Vault/CLI/Console)
resource "aws_secretsmanager_secret_version" "initial_template" {
  secret_id = aws_secretsmanager_secret.app_secrets.id
  secret_string = jsonencode({
    WEBHOOK_SHARED_SECRET         = "placeholder-webhook-secret-generate-with-token-urlsafe"
    ADMIN_SHARED_SECRET           = "placeholder-admin-secret-generate-with-token-urlsafe"
    RAW_MAIL_ENCRYPTION_KEY       = ""
    RELAY_USERNAME                = ""
    RELAY_PASSWORD                = ""
    VT_API_KEY                    = ""
    GSB_API_KEY                   = ""
    QUARANTINE_NOTIFY_WEBHOOK_URL = ""
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}
