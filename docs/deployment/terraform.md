# Deployment: Terraform (IaC)

## Overview

The `terraform/` directory provides Infrastructure-as-Code for deploying the gateway's AWS dependencies: ElastiCache Redis cluster, S3 quarantine bucket with KMS encryption, VPC networking, IAM roles (IRSA), and Secrets Manager secrets.

---

## Directory Structure

```
terraform/
├── main.tf            # Root module — providers, data sources, module calls
├── variables.tf       # Input variables
├── outputs.tf         # Output values (Redis endpoint, S3 bucket, etc.)
├── environments/
│   ├── staging/       # Staging-specific tfvars
│   └── production/    # Production-specific tfvars
└── modules/
    ├── redis/         # ElastiCache Redis module
    ├── storage/       # S3 + KMS module
    ├── secrets/       # Secrets Manager module
    └── networking/    # VPC, subnets, security groups
```

---

## Prerequisites

- Terraform 1.6+
- AWS CLI configured with sufficient IAM permissions
- An existing EKS cluster (referenced by name in variables)
- An existing VPC

---

## Initial Setup

```bash
cd terraform

# Initialize providers and backend
terraform init \
  -backend-config="bucket=your-tfstate-bucket" \
  -backend-config="key=email-auth-gateway/terraform.tfstate" \
  -backend-config="region=us-east-1"

# Plan (staging)
terraform plan \
  -var-file="environments/staging/terraform.tfvars" \
  -out=staging.tfplan

# Apply (staging)
terraform apply staging.tfplan
```

---

## Input Variables

| Variable | Type | Required | Description |
|---|---|---|---|
| `aws_region` | `string` | Yes | AWS region (e.g. `us-east-1`) |
| `environment` | `string` | Yes | `staging` or `production` |
| `eks_cluster_name` | `string` | Yes | EKS cluster name for IRSA configuration |
| `vpc_id` | `string` | Yes | VPC ID for ElastiCache subnet group |
| `private_subnet_ids` | `list(string)` | Yes | Private subnet IDs for ElastiCache |
| `eks_worker_sg_id` | `string` | Yes | EKS worker node security group ID (Redis ingress) |
| `redis_node_type` | `string` | No | Default: `cache.t3.medium` (staging), `cache.m7g.xlarge` (prod) |
| `redis_num_replicas` | `number` | No | Default: `1` (staging), `2` (prod) |
| `quarantine_bucket_name` | `string` | Yes | S3 bucket name for encrypted quarantine storage |
| `kms_deletion_window_days` | `number` | No | Default: `30` — KMS key deletion window |
| `tags` | `map(string)` | No | Resource tags |

---

## Resources Created

### ElastiCache Redis (`modules/redis/`)

- Multi-AZ replication group with automatic failover
- Transit encryption (TLS) enabled
- At-rest encryption with KMS CMK
- Subnet group in private subnets only
- Security group allowing TCP 6379 from EKS worker nodes only

```hcl
module "redis" {
  source = "./modules/redis"

  cluster_id      = "email-gateway-${var.environment}"
  node_type       = var.redis_node_type
  num_replicas    = var.redis_num_replicas
  subnet_ids      = var.private_subnet_ids
  vpc_id          = var.vpc_id
  allowed_sg_id   = var.eks_worker_sg_id
  kms_key_id      = module.kms.key_id
}
```

### S3 Quarantine Bucket (`modules/storage/`)

- Server-side encryption with KMS CMK
- Versioning enabled (for accidental deletion recovery)
- Lifecycle rules: transition to Glacier after 90 days, expire after 365 days
- Block all public access
- Access logging enabled

```hcl
module "quarantine_storage" {
  source = "./modules/storage"

  bucket_name  = var.quarantine_bucket_name
  kms_key_id   = module.kms.key_id
  environment  = var.environment
}
```

### Secrets Manager (`modules/secrets/`)

Creates secrets for all gateway credentials:

- `prod/email-gateway/webhook-secret`
- `prod/email-gateway/encryption-key`
- `prod/email-gateway/admin-secret`
- `prod/email-gateway/smtp-credentials`
- `prod/email-gateway/api-keys`

```hcl
module "secrets" {
  source      = "./modules/secrets"
  environment = var.environment
  kms_key_id  = module.kms.key_id
}
```

### IAM / IRSA (`main.tf`)

Creates an IAM role for the gateway's Kubernetes service account with permissions:

```json
{
  "Statement": [
    {
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": "arn:aws:secretsmanager:*:*:secret:prod/email-gateway/*"
    },
    {
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::${var.quarantine_bucket_name}",
        "arn:aws:s3:::${var.quarantine_bucket_name}/*"
      ]
    },
    {
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "${module.kms.key_arn}"
    }
  ]
}
```

The trust policy scopes access to the `email-auth-gateway` ServiceAccount in the `email-security-prod` namespace.

---

## Outputs

| Output | Description |
|---|---|
| `redis_endpoint` | ElastiCache primary endpoint (set as `REDIS_URL` in K8s) |
| `quarantine_bucket_name` | S3 bucket name (set as `QUARANTINE_DIR` with `s3://` prefix) |
| `gateway_iam_role_arn` | IAM role ARN (annotate K8s ServiceAccount with this) |
| `kms_key_arn` | KMS key ARN |

---

## Post-Apply Steps

After `terraform apply`, annotate the Kubernetes ServiceAccount for IRSA:

```bash
ROLE_ARN=$(terraform output -raw gateway_iam_role_arn)

kubectl annotate serviceaccount email-auth-gateway \
  -n email-security-prod \
  eks.amazonaws.com/role-arn=$ROLE_ARN
```

Set the Redis endpoint in your Helm values:

```bash
REDIS_URL=$(terraform output -raw redis_endpoint)
helm upgrade email-auth-gateway ./helm/email-auth-gateway \
  --set config.redisUrl="rediss://${REDIS_URL}:6379/0"
```

---

## Destroying Infrastructure

```bash
# Staging only
terraform destroy -var-file="environments/staging/terraform.tfvars"
```

> **Warning**: Destruction removes the Redis cluster (data lost) and will **not** empty the S3 quarantine bucket — S3 bucket destruction with versioning enabled requires manual emptying first. This is intentional to prevent accidental data loss.
