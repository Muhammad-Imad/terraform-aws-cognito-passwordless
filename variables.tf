###############################################################################
# Required
###############################################################################

variable "name" {
  description = "Short name used as a prefix for all created resources (e.g. \"acme-dev\")."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$", var.name))
    error_message = "name must be 3-32 lowercase alphanumeric/hyphen characters and may not start or end with a hyphen."
  }
}

###############################################################################
# Delivery channels
###############################################################################

variable "enable_email_channel" {
  description = "Enable passwordless delivery over email (magic link / one-time code) via SES."
  type        = bool
  default     = true
}

variable "enable_sms_channel" {
  description = "Enable passwordless delivery of a one-time code over SMS via SNS."
  type        = bool
  default     = false
}

variable "ses_from_address" {
  description = "Verified SES identity used as the From address for email challenges. Required when enable_email_channel is true."
  type        = string
  default     = null

  validation {
    condition     = var.ses_from_address == null || can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.ses_from_address))
    error_message = "ses_from_address must be a valid email address."
  }
}

variable "ses_identity_arn" {
  description = "ARN of the SES identity (domain or email) the verify Lambda is permitted to send from. Required when enable_email_channel is true."
  type        = string
  default     = null
}

variable "delivery_mode" {
  description = "How the email challenge is delivered to the user: \"code\" for a numeric one-time code, or \"magic_link\" for a signed click-through link."
  type        = string
  default     = "code"

  validation {
    condition     = contains(["code", "magic_link"], var.delivery_mode)
    error_message = "delivery_mode must be one of: code, magic_link."
  }
}

variable "magic_link_base_url" {
  description = "Base URL used to build magic links, e.g. \"https://app.example.com/auth/callback\". Required when delivery_mode is \"magic_link\"."
  type        = string
  default     = null
}

###############################################################################
# Challenge behaviour
###############################################################################

variable "code_length" {
  description = "Number of digits in the generated one-time code."
  type        = number
  default     = 6

  validation {
    condition     = var.code_length >= 4 && var.code_length <= 10
    error_message = "code_length must be between 4 and 10."
  }
}

variable "code_ttl_seconds" {
  description = "Lifetime of a challenge code/token in seconds before it expires."
  type        = number
  default     = 180

  validation {
    condition     = var.code_ttl_seconds >= 30 && var.code_ttl_seconds <= 900
    error_message = "code_ttl_seconds must be between 30 and 900 (15 minutes)."
  }
}

variable "max_attempts" {
  description = "Maximum number of failed verification attempts allowed before the challenge session fails."
  type        = number
  default     = 3

  validation {
    condition     = var.max_attempts >= 1 && var.max_attempts <= 10
    error_message = "max_attempts must be between 1 and 10."
  }
}

###############################################################################
# Challenge store
###############################################################################

variable "challenge_store" {
  description = "Backing store for short-lived challenge codes: \"dynamodb\" (TTL-based, serverless) or \"redis\" (ElastiCache, sub-millisecond)."
  type        = string
  default     = "dynamodb"

  validation {
    condition     = contains(["dynamodb", "redis"], var.challenge_store)
    error_message = "challenge_store must be one of: dynamodb, redis."
  }
}

variable "dynamodb_billing_mode" {
  description = "Billing mode for the DynamoDB challenge table when challenge_store is \"dynamodb\"."
  type        = string
  default     = "PAY_PER_REQUEST"

  validation {
    condition     = contains(["PAY_PER_REQUEST", "PROVISIONED"], var.dynamodb_billing_mode)
    error_message = "dynamodb_billing_mode must be one of: PAY_PER_REQUEST, PROVISIONED."
  }
}

variable "redis_node_type" {
  description = "ElastiCache node type used when challenge_store is \"redis\"."
  type        = string
  default     = "cache.t4g.micro"
}

variable "redis_endpoint" {
  description = "Override for an existing Redis endpoint (host:port). When null and challenge_store is \"redis\", a replication group is created by this module."
  type        = string
  default     = null
}

###############################################################################
# Networking (VPC isolation for the verify Lambda)
###############################################################################

variable "vpc_id" {
  description = "VPC ID into which the verify Lambda (and optional Redis) is deployed. Required when challenge_store is \"redis\" or when vpc_subnet_ids is set."
  type        = string
  default     = null
}

variable "vpc_subnet_ids" {
  description = "List of private subnet IDs (multi-AZ) for the VPC-isolated verify Lambda. When empty, the verify Lambda runs outside a VPC."
  type        = list(string)
  default     = []
}

###############################################################################
# Secrets
###############################################################################

variable "secrets_manager_secret_arn" {
  description = "ARN of the Secrets Manager secret holding runtime signing material (e.g. the magic-link HMAC key). The module reads but never writes this secret."
  type        = string
  default     = null
}

###############################################################################
# Observability
###############################################################################

variable "log_retention_days" {
  description = "CloudWatch Logs retention in days for the Lambda log groups."
  type        = number
  default     = 30

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.log_retention_days)
    error_message = "log_retention_days must be a value accepted by CloudWatch Logs."
  }
}

variable "lambda_runtime" {
  description = "Node.js runtime for the Lambda triggers."
  type        = string
  default     = "nodejs20.x"
}

variable "lambda_architecture" {
  description = "Instruction set architecture for the Lambda functions."
  type        = string
  default     = "arm64"

  validation {
    condition     = contains(["arm64", "x86_64"], var.lambda_architecture)
    error_message = "lambda_architecture must be one of: arm64, x86_64."
  }
}

variable "tags" {
  description = "Additional tags applied to all resources created by this module."
  type        = map(string)
  default     = {}
}
