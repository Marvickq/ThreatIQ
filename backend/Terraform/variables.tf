variable "region" {
  type        = string
  description = "AWS region to deploy into."
}

variable "name" {
  type        = string
  default     = "threatiq"
  description = "Name prefix for all resources (max 20 characters; lowercase letters, digits, hyphens)."
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,19}$", var.name))
    error_message = "name must start with a letter and be 2-20 characters of lowercase letters, digits or hyphens."
  }
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Extra tags applied to every resource."
}

# ------------------------------------------------------------------------------------ network (existing)
# This module does not create a VPC.
variable "vpc_id" {
  type        = string
  description = "Existing VPC to deploy into."
}

variable "public_subnet_ids" {
  type        = list(string)
  description = "Public subnets (at least two AZs) for the ALB."
  validation {
    condition     = length(var.public_subnet_ids) >= 2
    error_message = "An ALB needs at least two public subnets in different availability zones."
  }
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Private subnets (at least two AZs) for ECS tasks, RDS and ElastiCache. Tasks need NAT egress for Nebius/NVD/CISA."
  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "RDS and ElastiCache need at least two private subnets in different availability zones."
  }
}

variable "alb_ingress_cidrs" {
  type        = list(string)
  default     = ["0.0.0.0/0"]
  description = "CIDR blocks allowed to reach the ALB on 80 (redirect only) and 443. Narrow this for an internal-only deployment."
}

# ------------------------------------------------------------------------------------ application
# Images you have already pushed (for example to ECR). Use immutable tags or digests.
variable "api_image" {
  type        = string
  description = "API/worker/scheduler image (backend/Dockerfile)."
}

variable "frontend_image" {
  type        = string
  description = "Web image (frontend/Dockerfile)."
}

variable "acm_certificate_arn" {
  type        = string
  description = "Certificate for the HTTPS listener. Required: this stack serves only HTTPS."
}

variable "public_url" {
  type        = string
  description = "Public origin of the app, e.g. https://threatiq.example.com (used for FRONTEND_ORIGIN / CORS)."
  validation {
    condition     = can(regex("^https://[^/]+$", var.public_url))
    error_message = "public_url must be an https origin with no path or trailing slash."
  }
}

variable "api_desired_count" {
  type    = number
  default = 2
}

variable "worker_desired_count" {
  type    = number
  default = 1
}

variable "web_desired_count" {
  type    = number
  default = 2
}

variable "dedicated_scheduler" {
  type        = bool
  default     = true
  description = "Run `python -m app.scheduler` as one separate service and set SCHEDULER_ENABLED=false on the API, so provider polling is not duplicated across API replicas."
}

variable "extra_environment" {
  type        = map(string)
  default     = {}
  description = "Additional NON-SECRET environment variables for the api/worker/scheduler containers (for example LOG_LEVEL). Keys set by this module take precedence. Never put secrets here."
}

# ------------------------------------------------------------------------------------ data stores
variable "db_instance_class" {
  type    = string
  default = "db.t4g.small"
}

variable "db_allocated_storage" {
  type    = number
  default = 50
}

variable "db_max_allocated_storage" {
  type    = number
  default = 500
}

variable "db_multi_az" {
  type    = bool
  default = true
}

variable "db_backup_retention_days" {
  type    = number
  default = 14
}

variable "db_deletion_protection" {
  type    = bool
  default = true
}

variable "db_performance_insights_enabled" {
  type        = bool
  default     = false
  description = "Not every instance class supports Performance Insights; enable only on a supported class."
}

variable "redis_node_type" {
  type    = string
  default = "cache.t4g.small"
}

variable "redis_num_cache_clusters" {
  type        = number
  default     = 2
  description = "Primary plus replicas. Must be at least 2 because automatic failover is enabled."
  validation {
    condition     = var.redis_num_cache_clusters >= 2
    error_message = "automatic failover requires at least 2 cache clusters."
  }
}

variable "artifact_noncurrent_version_expiration_days" {
  type        = number
  default     = 90
  description = "Days before noncurrent versions of artifact objects are deleted."
}

variable "artifact_bucket_force_destroy" {
  type        = bool
  default     = false
  description = "Allow terraform destroy to delete a non-empty artifact bucket."
}

variable "alb_deletion_protection" {
  type    = bool
  default = true
}

# ------------------------------------------------------------------------------------ secrets you create
# Secrets YOU create in Secrets Manager (this module never receives their values). Leave null to run without that feature.
# Each must be the full secret ARN; the secret value is the plain string the app expects.
variable "nebius_api_key_secret_arn" {
  type    = string
  default = null
  validation {
    condition     = var.nebius_api_key_secret_arn == null || can(regex("^arn:aws[a-z-]*:secretsmanager:", var.nebius_api_key_secret_arn))
    error_message = "Must be a Secrets Manager secret ARN."
  }
}

variable "virustotal_api_key_secret_arn" {
  type    = string
  default = null
  validation {
    condition     = var.virustotal_api_key_secret_arn == null || can(regex("^arn:aws[a-z-]*:secretsmanager:", var.virustotal_api_key_secret_arn))
    error_message = "Must be a Secrets Manager secret ARN."
  }
}

variable "nvd_api_key_secret_arn" {
  type    = string
  default = null
  validation {
    condition     = var.nvd_api_key_secret_arn == null || can(regex("^arn:aws[a-z-]*:secretsmanager:", var.nvd_api_key_secret_arn))
    error_message = "Must be a Secrets Manager secret ARN."
  }
}

variable "nvidia_api_key_secret_arn" {
  type        = string
  default     = null
  description = "Optional NVIDIA embeddings key for semantic retrieval (docs/rag.md)."
  validation {
    condition     = var.nvidia_api_key_secret_arn == null || can(regex("^arn:aws[a-z-]*:secretsmanager:", var.nvidia_api_key_secret_arn))
    error_message = "Must be a Secrets Manager secret ARN."
  }
}

# ------------------------------------------------------------------------------------ AI
variable "nebius_model" {
  type        = string
  description = "Nebius Token Factory model id (NEBIUS_MODEL). No default is assumed."
}

variable "nebius_base_url" {
  type    = string
  default = "https://api.tokenfactory.nebius.com/v1"
}

# ------------------------------------------------------------------------------------ Microsoft Entra ID SSO (optional)
# See docs/sso-entra.md. Set all four (client id, tenant id, redirect URI, client secret ARN) or none;
# the application refuses to start with a partial configuration.
variable "entra_client_id" {
  type    = string
  default = ""
}

variable "entra_tenant_id" {
  type        = string
  default     = ""
  description = "Directory (tenant) GUID. Leave empty only with entra_multi_tenant = true."
}

variable "entra_multi_tenant" {
  type    = bool
  default = false
}

variable "entra_redirect_uri" {
  type        = string
  default     = ""
  description = "e.g. https://threatiq.example.com/api/v1/auth/sso/entra/callback (must be https)."
}

variable "entra_client_secret_secret_arn" {
  type    = string
  default = null
  validation {
    condition     = var.entra_client_secret_secret_arn == null || can(regex("^arn:aws[a-z-]*:secretsmanager:", var.entra_client_secret_secret_arn))
    error_message = "Must be a Secrets Manager secret ARN."
  }
}

# ------------------------------------------------------------------------------------ operations
variable "log_retention_days" {
  type    = number
  default = 90
}

variable "allow_private_integration_endpoints" {
  type        = bool
  default     = false
  description = "Allow SIEM endpoints on private ranges (needed for on-premise Wazuh/Elastic). Loopback/metadata stay blocked."
}
