output "raw_mail_bucket_name" {
  description = "Name of the raw mail S3 bucket"
  value       = aws_s3_bucket.raw_mail.id
}

output "raw_mail_bucket_arn" {
  description = "ARN of the raw mail S3 bucket"
  value       = aws_s3_bucket.raw_mail.arn
}

output "quarantine_bucket_name" {
  description = "Name of the quarantine S3 bucket"
  value       = aws_s3_bucket.quarantine.id
}

output "quarantine_bucket_arn" {
  description = "ARN of the quarantine S3 bucket"
  value       = aws_s3_bucket.quarantine.arn
}
