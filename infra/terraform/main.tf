terraform {
  required_version = ">= 1.6.0"
}

# Portfolio-ready Terraform placeholder.
# Next upgrade: add AWS S3 report bucket, IAM least-privilege role, and CloudWatch log group.

variable "project_name" {
  type    = string
  default = "talonedge"
}

output "project_name" {
  value = var.project_name
}
