terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Backend configuration (configured via CLI or backend-config file)
  # backend "s3" {}
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "EmailAuthGateway"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# 1. KMS & Secrets Module
module "secrets" {
  source      = "./modules/secrets"
  name_prefix = var.name_prefix
  environment = var.environment
}

# 2. Encrypted Storage (S3) Module
module "storage" {
  source                    = "./modules/storage"
  name_prefix               = var.name_prefix
  environment               = var.environment
  kms_key_arn               = module.secrets.kms_key_arn
  raw_mail_retention_days   = var.raw_mail_retention_days
  quarantine_retention_days = var.quarantine_retention_days
}

# 3. Redis Cache & State (ElastiCache) Module
module "redis" {
  source                     = "./modules/redis"
  name_prefix                = var.name_prefix
  environment                = var.environment
  vpc_id                     = var.vpc_id
  subnet_ids                 = var.private_subnet_ids
  allowed_security_group_ids = var.gateway_security_group_ids
  node_type                  = var.redis_node_type
  num_cache_clusters         = var.redis_num_nodes
  auth_token                 = var.redis_auth_token
}

# 4. IAM & Kubernetes Service Account Integration (IRSA) Module
module "iam" {
  source                      = "./modules/iam"
  name_prefix                 = var.name_prefix
  environment                 = var.environment
  oidc_provider_arn           = var.oidc_provider_arn
  oidc_provider_url           = var.oidc_provider_url
  service_account_namespace   = var.k8s_service_account_namespace
  service_account_name        = var.k8s_service_account_name
  kms_key_arn                 = module.secrets.kms_key_arn
  secrets_manager_secret_arn  = module.secrets.secrets_manager_secret_arn
  s3_bucket_arns              = [
    module.storage.raw_mail_bucket_arn,
    module.storage.quarantine_bucket_arn
  ]
}
