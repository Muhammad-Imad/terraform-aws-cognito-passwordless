# Complete example
#
# A production-shaped deployment exercising every moving part of the module:
#   * Email magic links AND SMS one-time codes.
#   * Redis (ElastiCache) challenge store inside a multi-AZ VPC.
#   * VPC-isolated verify Lambda on private subnets.
#   * Magic-link signing key sourced from Secrets Manager.
#   * A verified SES domain identity and an SNS-capable SMS spend limit.
#
# Networking is created inline so the example is self-contained and applies on
# its own. In a real estate you would pass in an existing VPC's subnet IDs.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5"
    }
  }
}

provider "aws" {
  region = var.region
}

data "aws_availability_zones" "available" {
  state = "available"
}

###############################################################################
# Network — a small VPC with two private subnets across distinct AZs.
###############################################################################
resource "aws_vpc" "this" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "acme-passwordless" }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.this.id
  cidr_block        = cidrsubnet(aws_vpc.this.cidr_block, 8, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags              = { Name = "acme-passwordless-private-${count.index}" }
}

# Interface/Gateway endpoints let the VPC-isolated Lambda reach AWS APIs without
# a NAT gateway — cheaper and keeps traffic on the AWS backbone.
resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.dynamodb"
  vpc_endpoint_type = "Gateway"
}

###############################################################################
# Secrets — the magic-link HMAC signing key. Generated here for the example;
# in production this would be rotated and managed out-of-band.
###############################################################################
resource "random_password" "signing_key" {
  length  = 64
  special = false
}

resource "aws_secretsmanager_secret" "signing" {
  name = "acme/passwordless/signing"
}

resource "aws_secretsmanager_secret_version" "signing" {
  secret_id     = aws_secretsmanager_secret.signing.id
  secret_string = jsonencode({ magicLinkSigningKey = random_password.signing_key.result })
}

###############################################################################
# SES identity for outbound email.
###############################################################################
resource "aws_sesv2_email_identity" "domain" {
  email_identity = var.email_domain
}

###############################################################################
# Module under test.
###############################################################################
module "passwordless" {
  source = "../../"

  name = "acme-prod"

  # Email magic links + SMS codes.
  enable_email_channel = true
  enable_sms_channel   = true
  delivery_mode        = "magic_link"
  magic_link_base_url  = "https://app.example.com/auth/callback"

  ses_from_address = "no-reply@${var.email_domain}"
  ses_identity_arn = aws_sesv2_email_identity.domain.arn

  # Redis store inside the VPC, verify Lambda isolated on private subnets.
  challenge_store = "redis"
  redis_node_type = "cache.t4g.micro"
  vpc_id          = aws_vpc.this.id
  vpc_subnet_ids  = aws_subnet.private[*].id

  secrets_manager_secret_arn = aws_secretsmanager_secret.signing.arn

  code_length      = 6
  code_ttl_seconds = 120
  max_attempts     = 3

  log_retention_days  = 90
  lambda_architecture = "arm64"

  tags = {
    Environment = "prod"
    Team        = "platform"
    CostCenter  = "auth"
  }

  depends_on = [aws_secretsmanager_secret_version.signing]
}
