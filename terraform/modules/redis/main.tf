resource "aws_security_group" "redis" {
  name_prefix = "${var.name_prefix}-redis-sg-"
  description = "Security group for Email Auth Gateway ElastiCache Redis"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Redis from gateway pods"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = var.allowed_security_group_ids
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.name_prefix}-redis-sg"
    Environment = var.environment
  }
}

resource "aws_elasticache_subnet_group" "redis" {
  name       = "${var.name_prefix}-redis-subnet-group"
  subnet_ids = var.subnet_ids

  tags = {
    Name        = "${var.name_prefix}-redis-subnet-group"
    Environment = var.environment
  }
}

resource "aws_elasticache_parameter_group" "redis" {
  name   = "${var.name_prefix}-redis-params"
  family = "redis7"

  parameter {
    name  = "maxmemory-policy"
    value = "volatile-lru"
  }

  tags = {
    Environment = var.environment
  }
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id          = "${var.name_prefix}-redis"
  description                   = "Redis cluster for ${var.name_prefix} state, deduplication and caching"
  node_type                     = var.node_type
  num_cache_clusters            = var.num_cache_clusters
  port                          = 6379
  parameter_group_name          = aws_elasticache_parameter_group.redis.name
  subnet_group_name             = aws_elasticache_subnet_group.redis.name
  security_group_ids            = [aws_security_group.redis.id]
  automatic_failover_enabled    = var.num_cache_clusters > 1 ? true : false
  multi_az_enabled              = var.num_cache_clusters > 1 ? true : false
  at_rest_encryption_enabled    = true
  transit_encryption_enabled    = true
  auth_token                    = var.auth_token != "" ? var.auth_token : null

  tags = {
    Name        = "${var.name_prefix}-redis"
    Environment = var.environment
  }
}
