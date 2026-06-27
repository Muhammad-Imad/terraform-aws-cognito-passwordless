###############################################################################
# Cognito User Pool wired for the CUSTOM_AUTH (passwordless) flow.
#
# The pool itself is intentionally minimal — passwords still exist as a fallback
# admin path, but interactive sign-in is driven entirely by the three Lambda
# challenge triggers. This is the additive, backward-compatible part of the
# design: dropping these triggers onto an existing pool does not disturb any
# existing USER_PASSWORD_AUTH or SRP clients.
###############################################################################

resource "aws_cognito_user_pool" "this" {
  name = "${local.prefix}-passwordless"

  # Email is the canonical alias for passwordless; phone is added when SMS is on.
  username_attributes      = local.sms_enabled ? ["email", "phone_number"] : ["email"]
  auto_verified_attributes = compact([local.email_enabled ? "email" : "", local.sms_enabled ? "phone_number" : ""])

  # Passwords remain strong for the admin-recovery path even though end users
  # never type one in the passwordless flow.
  password_policy {
    minimum_length                   = 12
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = true
    temporary_password_validity_days = 1
  }

  # Advanced security flags risky sign-ins; passwordless benefits from it most.
  user_pool_add_ons {
    advanced_security_mode = "ENFORCED"
  }

  # The Lambda config block is what turns a vanilla pool into a passwordless one.
  lambda_config {
    define_auth_challenge          = aws_lambda_function.define_auth_challenge.arn
    create_auth_challenge          = aws_lambda_function.create_auth_challenge.arn
    verify_auth_challenge_response = aws_lambda_function.verify_auth_challenge.arn
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  schema {
    name                     = "email"
    attribute_data_type      = "String"
    required                 = true
    mutable                  = true
    developer_only_attribute = false

    string_attribute_constraints {
      min_length = 1
      max_length = 256
    }
  }

  tags = local.tags
}

# App client that permits the custom auth flow. SRP/refresh are kept enabled so
# existing integrations continue to work unchanged.
resource "aws_cognito_user_pool_client" "this" {
  name         = "${local.prefix}-passwordless-client"
  user_pool_id = aws_cognito_user_pool.this.id

  explicit_auth_flows = [
    "ALLOW_CUSTOM_AUTH",
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
  ]

  generate_secret = false

  access_token_validity  = 60
  id_token_validity      = 60
  refresh_token_validity = 30

  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "days"
  }

  # Do not reveal whether an account exists — important for passwordless UX.
  prevent_user_existence_errors = "ENABLED"
}
