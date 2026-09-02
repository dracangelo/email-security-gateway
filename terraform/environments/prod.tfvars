# Production Environment Variables
environment                  = "prod"
aws_region                   = "us-east-1"
name_prefix                  = "email-gateway-prod"
vpc_id                       = "vpc-0prod123456789abc"
private_subnet_ids           = ["subnet-0prod11111111111", "subnet-0prod22222222222", "subnet-0prod33333333333"]
gateway_security_group_ids   = ["sg-0prodgateway123456"]
redis_node_type              = "cache.m7g.large"
redis_num_nodes              = 3
raw_mail_retention_days      = 90
quarantine_retention_days    = 30
k8s_service_account_namespace = "email-security-prod"
k8s_service_account_name     = "email-auth-gateway-prod"
