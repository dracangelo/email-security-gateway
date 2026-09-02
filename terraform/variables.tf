variable "aws_region" {
  type        = string
  description = "AWS region for infrastructure"
  default     = "us-east-1"
}

variable "environment" {
  type        = string
  description = "Environment name (dev, staging, prod)"
  default     = "prod"
}

variable "name_prefix" {
  type        = string
  description = "Resource name prefix"
  default     = "email-auth-gateway"
}

variable "vpc_id" {
  type        = string
  description = "VPC ID where managed resources will be deployed"
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Private subnet IDs for Redis"
}

variable "gateway_security_group_ids" {
  type        = list(string)
  description = "Security group IDs of the gateway Kubernetes worker nodes/pods"
  default     = []
}

variable "redis_node_type" {
  type        = string
  description = "Instance type for Redis nodes"
  default     = "cache.t4g.small"
}

variable "redis_num_nodes" {
  type        = number
  description = "Number of nodes in Redis replication group"
  default     = 2
}

variable "redis_auth_token" {
  type        = string
  description = "Redis AUTH token (optional)"
  sensitive   = true
  default     = ""
}

variable "raw_mail_retention_days" {
  type        = number
  description = "Days to retain raw email files before expiration"
  default     = 90
}

variable "quarantine_retention_days" {
  type        = number
  description = "Days to retain quarantined files before expiration"
  default     = 30
}

variable "oidc_provider_arn" {
  type        = string
  description = "EKS Cluster OIDC provider ARN for IRSA"
  default     = ""
}

variable "oidc_provider_url" {
  type        = string
  description = "EKS Cluster OIDC provider URL (without https://)"
  default     = ""
}

variable "k8s_service_account_namespace" {
  type        = string
  description = "Kubernetes namespace of the gateway service account"
  default     = "default"
}

variable "k8s_service_account_name" {
  type        = string
  description = "Kubernetes service account name"
  default     = "email-auth-gateway"
}
