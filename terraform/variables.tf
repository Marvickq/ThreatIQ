variable "region" { type = string }
variable "name" {
  type    = string
  default = "threatiq"
}

# Existing network (this module does not create a VPC).
variable "vpc_id" { type = string }
variable "public_subnet_ids" { type = list(string) }  # ALB
variable "private_subnet_ids" { type = list(string) } # ECS tasks, RDS, ElastiCache (need NAT egress for Nebius/NVD/CISA)

# Images you have already pushed (for example to ECR). Use immutable tags or digests.
variable "api_image" { type = string }
variable "frontend_image" { type = string }

variable "acm_certificate_arn" {
  type        = string
  description = "Certificate for the HTTPS listener. Required: this stack serves only HTTPS."
}
variable "public_url" {
  type        = string
  description = "Public origin of the app, e.g. https://threatiq.example.com (used for CORS)."
}

variable "api_desired_count" {
  type    = number
  default = 2
}
variable "worker_desired_count" {
  type    = number
  default = 1
}
variable "db_instance_class" {
  type    = string
  default = "db.t4g.small"
}
variable "db_multi_az" {
  type    = bool
  default = true
}
variable "redis_node_type" {
  type    = string
  default = "cache.t4g.small"
}

# Secrets YOU create in Secrets Manager (this module never receives their values). Leave null to run without that feature.
variable "nebius_api_key_secret_arn" {
  type    = string
  default = null
}
variable "virustotal_api_key_secret_arn" {
  type    = string
  default = null
}
variable "nvd_api_key_secret_arn" {
  type    = string
  default = null
}

variable "nebius_model" { type = string }
variable "log_retention_days" {
  type    = number
  default = 90
}
variable "allow_private_integration_endpoints" {
  type        = bool
  default     = false
  description = "Allow SIEM endpoints on private ranges (needed for on-premise Wazuh/Elastic). Loopback/metadata stay blocked."
}
