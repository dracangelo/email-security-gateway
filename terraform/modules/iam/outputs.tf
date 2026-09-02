output "role_arn" {
  description = "ARN of the IAM role for the Kubernetes ServiceAccount"
  value       = aws_iam_role.gateway_pod_role.arn
}

output "role_name" {
  description = "Name of the IAM role for the Kubernetes ServiceAccount"
  value       = aws_iam_role.gateway_pod_role.name
}

output "policy_arn" {
  description = "ARN of the IAM policy attached to the role"
  value       = aws_iam_policy.gateway_policy.arn
}
