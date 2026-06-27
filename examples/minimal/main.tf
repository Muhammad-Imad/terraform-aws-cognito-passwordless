# Minimal example
#
# The smallest viable passwordless deployment: email one-time codes backed by
# DynamoDB. No VPC, no Redis, no magic links. Good for dev/qa environments.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

module "passwordless" {
  source = "../../"

  name = "acme-dev"

  # Email channel with one-time codes (the default delivery mode).
  enable_email_channel = true
  ses_from_address     = "no-reply@example.com"
  ses_identity_arn     = "arn:aws:ses:us-east-1:111111111111:identity/example.com"

  # DynamoDB challenge store with TTL — fully serverless.
  challenge_store = "dynamodb"

  log_retention_days = 14

  tags = {
    Environment = "dev"
    Team        = "platform"
  }
}
