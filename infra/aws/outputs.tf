output "s3_bucket_name" {
  description = "S3 bucket used for TalonEdge report hosting."
  value       = aws_s3_bucket.site.bucket
}

output "logs_bucket_name" {
  description = "S3 bucket used for CloudFront access logs."
  value       = aws_s3_bucket.logs.bucket
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID."
  value       = aws_cloudfront_distribution.site.id
}

output "cloudfront_url" {
  description = "Public HTTPS URL for the TalonEdge report."
  value       = "https://${aws_cloudfront_distribution.site.domain_name}"
}

output "github_actions_role_arn" {
  description = "IAM role ARN for GitHub Actions OIDC deployment."
  value       = aws_iam_role.github_deploy.arn
}
