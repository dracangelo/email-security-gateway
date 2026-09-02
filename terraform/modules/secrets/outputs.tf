output "kms_key_arn" {
  description = "ARN of the KMS customer managed key"
  value       = aws_kms_key.gateway_key.arn
}

output "kms_key_id" {
  description = "ID of the KMS customer managed key"
  value       = aws_kms_key.gateway_key.key_id
}

output "secrets_manager_secret_arn" {
  description = "ARN of the Secrets Manager secret"
  value       = aws_secretsmanager_secret.app_secrets.arn
}

output "secrets_manager_secret_name" {
  description = "Name of the Secrets Manager secret"
  value       = aws_secretsmanager_secret.app_secrets.name
}
