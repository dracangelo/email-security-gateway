variable "name_prefix" {
  type        = string
  description = "Prefix used for resource naming"
}

variable "environment" {
  type        = string
  description = "Deployment environment (dev, staging, prod)"
}

variable "oidc_provider_arn" {
  type        = string
  description = "EKS Cluster OIDC Provider ARN for IRSA"
  default     = ""
}

variable "oidc_provider_url" {
  type        = string
  description = "EKS Cluster OIDC Provider URL (without https://)"
  default     = ""
}

variable "service_account_namespace" {
  type        = string
  description = "Kubernetes namespace of the gateway ServiceAccount"
  default     = "default"
}

variable "service_account_name" {
  type        = string
  description = "Kubernetes ServiceAccount name"
  default     = "email-auth-gateway"
}

variable "kms_key_arn" {
  type        = string
  description = "KMS Key ARN to grant decryption permissions"
}

variable "secrets_manager_secret_arn" {
  type        = string
  description = "Secrets Manager Secret ARN to grant read access"
}

variable "s3_bucket_arns" {
  type        = list(string)
  description = "List of S3 bucket ARNs for read/write access"
  default     = []
}
