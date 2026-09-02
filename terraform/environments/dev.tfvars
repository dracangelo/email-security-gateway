# Development Environment Variables
environment                  = "dev"
aws_region                   = "us-east-1"
name_prefix                  = "email-gateway-dev"
vpc_id                       = "vpc-0dev123456789abcd"
private_subnet_ids           = ["subnet-0dev1111111111111", "subnet-0dev2222222222222"]
gateway_security_group_ids   = ["sg-0devgateway1234567"]
redis_node_type              = "cache.t4g.micro"
redis_num_nodes              = 1
raw_mail_retention_days      = 14
quarantine_retention_days    = 7
k8s_service_account_namespace = "email-security-dev"
k8s_service_account_name     = "email-auth-gateway-dev"
