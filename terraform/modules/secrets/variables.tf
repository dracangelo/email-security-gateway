variable "name_prefix" {
  type        = string
  description = "Prefix used for resource naming"
}

variable "environment" {
  type        = string
  description = "Deployment environment (dev, staging, prod)"
}
