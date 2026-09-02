# Staging Environment Variables
environment                  = "staging"
aws_region                   = "us-east-1"
name_prefix                  = "email-gateway-staging"
vpc_id                       = "vpc-0staging123456789"
private_subnet_ids           = ["subnet-0staging111111111", "subnet-0staging222222222"]
gateway_security_group_ids   = ["sg-0staginggateway123"]
redis_node_type              = "cache.t4g.small"
redis_num_nodes              = 2
raw_mail_retention_days      = 30
quarantine_retention_days    = 14
k8s_service_account_namespace = "email-security-staging"
k8s_service_account_name     = "email-auth-gateway-staging"
