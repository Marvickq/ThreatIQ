terraform {
  required_version = ">= 1.6"

  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.60" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }

  # Store state remotely and encrypted. It will contain generated secrets (database password, SECRET_KEY).
  # Configure with `terraform init -backend-config=...`; no bucket or table names are assumed here.
  # backend "s3" {
  #   bucket         = "..."
  #   key            = "threatiq/terraform.tfstate"
  #   region         = "..."
  #   encrypt        = true
  #   dynamodb_table = "..."
  # }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = merge(var.tags, { Project = "threatiq", ManagedBy = "terraform" })
  }
}
