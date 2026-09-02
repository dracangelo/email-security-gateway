variable "name_prefix" {
  type        = string
  description = "Prefix used for resource naming"
}

variable "environment" {
  type        = string
  description = "Deployment environment (dev, staging, prod)"
}

variable "kms_key_arn" {
  type        = string
  description = "KMS Customer Managed Key ARN for server-side encryption"
}

variable "raw_mail_retention_days" {
  type        = number
  description = "Days before raw email logs are transitioned to Glacier or deleted"
  default     = 90
}

variable "quarantine_retention_days" {
  type        = number
  description = "Days before quarantined email files are expired"
  default     = 30
}
