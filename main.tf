###############################################################################
# terraform-aws-cognito-passwordless
#
# Reusable module that wires an Amazon Cognito User Pool for the CUSTOM_AUTH
# (passwordless) flow. Composition lives here; the heavy lifting is split into
# cognito.tf, lambda.tf and iam.tf to keep each concern reviewable in isolation.
###############################################################################

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

###############################################################################
# Plan-time guard rails
#
# Terraform variable validation cannot express cross-variable constraints, so
# we surface misconfiguration early with precondition checks rather than at
# apply time (or worse, at runtime inside a Lambda).
###############################################################################

resource "null_resource" "preconditions" {
  lifecycle {
    precondition {
      condition     = var.enable_email_channel || var.enable_sms_channel
      error_message = "At least one delivery channel must be enabled (enable_email_channel or enable_sms_channel)."
    }

    precondition {
      condition     = !var.enable_email_channel || (var.ses_from_address != null && var.ses_identity_arn != null)
      error_message = "ses_from_address and ses_identity_arn are required when enable_email_channel is true."
    }

    precondition {
      condition     = var.delivery_mode != "magic_link" || var.magic_link_base_url != null
      error_message = "magic_link_base_url is required when delivery_mode is \"magic_link\"."
    }

    precondition {
      condition     = var.delivery_mode != "magic_link" || var.secrets_manager_secret_arn != null
      error_message = "secrets_manager_secret_arn is required when delivery_mode is \"magic_link\" (it holds the HMAC signing key)."
    }

    precondition {
      condition     = var.challenge_store != "redis" || (var.vpc_id != null && length(var.vpc_subnet_ids) >= 2)
      error_message = "challenge_store \"redis\" requires vpc_id and at least two private subnets (multi-AZ)."
    }

    precondition {
      condition     = length(var.vpc_subnet_ids) == 0 || var.vpc_id != null
      error_message = "vpc_id must be set when vpc_subnet_ids is provided."
    }
  }
}
