variable "aws_region" {
  description = "AWS region for TalonEdge resources. CloudFront certificate defaults require us-east-1 for the distribution control plane."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used for AWS resource naming."
  type        = string
  default     = "talonedge-secure-deploy"
}

variable "github_repo" {
  description = "GitHub repository in owner/repo format, for example AaronGrillot98/TalonEdge-Secure-Deploy."
  type        = string
}
