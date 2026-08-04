variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS Deployment Region"
}

variable "environment" {
  type        = string
  default     = "prod"
  description = "Deployment environment namespace"
}
variable "hosted_zone_id" {
  type        = string
  description = "Route 53 Hosted Zone ID for custom domain routing"
  default     = "Z0123456789ABCDEF012" # Replace with your actual Route 53 Hosted Zone ID
}