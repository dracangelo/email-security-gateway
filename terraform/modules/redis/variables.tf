variable "name_prefix" {
  type        = string
  description = "Prefix used for resource naming"
}

variable "environment" {
  type        = string
  description = "Deployment environment (dev, staging, prod)"
}

variable "vpc_id" {
  type        = string
  description = "VPC ID where Redis cluster will be provisioned"
}

variable "subnet_ids" {
  type        = list(string)
  description = "List of private subnet IDs for Redis subnet group"
}

variable "allowed_security_group_ids" {
  type        = list(string)
  description = "Security group IDs of client pods/services allowed to connect to Redis"
  default     = []
}

variable "node_type" {
  type        = string
  description = "ElastiCache Redis node instance type"
  default     = "cache.t4g.small"
}

variable "num_cache_clusters" {
  type        = number
  description = "Number of cache clusters (nodes) in the replication group"
  default     = 2
}

variable "auth_token" {
  type        = string
  description = "Redis AUTH token (password) for in-transit encryption"
  sensitive   = true
  default     = ""
}
