output "redis_primary_endpoint" {
  description = "Primary endpoint address for ElastiCache Redis"
  value       = module.redis.primary_endpoint_address
}

output "redis_port" {
  description = "Port for ElastiCache Redis"
  value       = module.redis.port
}

output "redis_url" {
  description = "Formatted Redis connection URL"
  value       = "redis://${module.redis.primary_endpoint_address}:${module.redis.port}/0"
}

output "raw_mail_bucket_name" {
  description = "Name of S3 bucket for raw mail storage"
  value       = module.storage.raw_mail_bucket_name
}

output "quarantine_bucket_name" {
  description = "Name of S3 bucket for quarantine storage"
  value       = module.storage.quarantine_bucket_name
}

output "kms_key_arn" {
  description = "ARN of the KMS encryption key"
  value       = module.secrets.kms_key_arn
}

output "secrets_manager_secret_name" {
  description = "Name of the AWS Secrets Manager secret"
  value       = module.secrets.secrets_manager_secret_name
}

output "gateway_iam_role_arn" {
  description = "ARN of the IAM role to annotate on Kubernetes ServiceAccount"
  value       = module.iam.role_arn
}
