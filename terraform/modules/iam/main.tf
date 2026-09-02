# IAM Role for Kubernetes Service Account (IRSA)
data "aws_iam_policy_document" "assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [var.oidc_provider_arn != "" ? var.oidc_provider_arn : "arn:aws:iam::123456789012:oidc-provider/dummy"]
    }

    condition {
      test     = "StringEquals"
      variable = "${var.oidc_provider_url}:sub"
      values   = ["system:serviceaccount:${var.service_account_namespace}:${var.service_account_name}"]
    }

    condition {
      test     = "StringEquals"
      variable = "${var.oidc_provider_url}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "gateway_pod_role" {
  name_prefix        = "${var.name_prefix}-pod-role-"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json

  tags = {
    Name        = "${var.name_prefix}-pod-role"
    Environment = var.environment
  }
}

# Policy for S3 access, KMS decryption, and Secrets Manager retrieval
data "aws_iam_policy_document" "gateway_policy" {
  # Secrets Manager
  statement {
    sid    = "SecretsManagerRead"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret"
    ]
    resources = [var.secrets_manager_secret_arn]
  }

  # KMS Decryption & Encryption
  statement {
    sid    = "KMSAccess"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey"
    ]
    resources = [var.kms_key_arn]
  }

  # S3 Raw Mail & Quarantine Access
  statement {
    sid    = "S3StorageAccess"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket",
      "s3:DeleteObject"
    ]
    resources = length(var.s3_bucket_arns) > 0 ? concat(
      var.s3_bucket_arns,
      [for arn in var.s3_bucket_arns : "${arn}/*"]
    ) : ["*"]
  }
}

resource "aws_iam_policy" "gateway_policy" {
  name_prefix = "${var.name_prefix}-policy-"
  description = "Least-privilege policy for Email Auth Gateway pods"
  policy      = data.aws_iam_policy_document.gateway_policy.json
}

resource "aws_iam_role_policy_attachment" "attach_gateway_policy" {
  role       = aws_iam_role.gateway_pod_role.name
  policy_arn = aws_iam_policy.gateway_policy.arn
}
