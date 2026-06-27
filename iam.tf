###############################################################################
# IAM — least privilege per Lambda
#
# Each trigger gets its own role with only the permissions that handler needs:
#
#   define  — logs only (pure control logic).
#   create  — logs, store write, SES/SNS send, secret read (for magic-link key).
#   verify  — logs, store read/delete, secret read, plus VPC ENI management.
#
# Resource ARNs are pinned wherever the API supports it; wildcards are confined
# to actions that genuinely do not accept a resource scope.
###############################################################################

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# ---------------------------------------------------------------------------
# Shared building blocks
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "logs_define" {
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.define.arn}:*"]
  }
}

data "aws_iam_policy_document" "logs_create" {
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.create.arn}:*"]
  }
}

data "aws_iam_policy_document" "logs_verify" {
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.verify.arn}:*"]
  }
}

# VPC ENI management is required for any Lambda attached to a VPC. These actions
# do not support resource-level scoping, so they are wildcard by AWS design.
locals {
  vpc_eni_actions = [
    "ec2:CreateNetworkInterface",
    "ec2:DescribeNetworkInterfaces",
    "ec2:DeleteNetworkInterface",
    "ec2:AssignPrivateIpAddresses",
    "ec2:UnassignPrivateIpAddresses",
  ]
}

# ---------------------------------------------------------------------------
# Define role
# ---------------------------------------------------------------------------
resource "aws_iam_role" "define" {
  name               = "${local.prefix}-define-auth-challenge"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy" "define" {
  name   = "logs"
  role   = aws_iam_role.define.id
  policy = data.aws_iam_policy_document.logs_define.json
}

# ---------------------------------------------------------------------------
# Create role
# ---------------------------------------------------------------------------
resource "aws_iam_role" "create" {
  name               = "${local.prefix}-create-auth-challenge"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "create" {
  source_policy_documents = [data.aws_iam_policy_document.logs_create.json]

  # Store write (only the active backend).
  dynamic "statement" {
    for_each = local.store_dynamodb ? [1] : []
    content {
      sid       = "ChallengeStoreWrite"
      effect    = "Allow"
      actions   = ["dynamodb:PutItem"]
      resources = [aws_dynamodb_table.challenge[0].arn]
    }
  }

  # Email delivery via SES, pinned to the supplied identity ARN.
  dynamic "statement" {
    for_each = local.email_enabled ? [1] : []
    content {
      sid       = "SendEmailChallenge"
      effect    = "Allow"
      actions   = ["ses:SendEmail"]
      resources = [var.ses_identity_arn]

      condition {
        test     = "StringEquals"
        variable = "ses:FromAddress"
        values   = [var.ses_from_address]
      }
    }
  }

  # SMS delivery via SNS publish to a phone number (no topic ARN to scope to).
  dynamic "statement" {
    for_each = local.sms_enabled ? [1] : []
    content {
      sid       = "SendSmsChallenge"
      effect    = "Allow"
      actions   = ["sns:Publish"]
      resources = ["*"]

      condition {
        test     = "Bool"
        variable = "aws:SecureTransport"
        values   = ["true"]
      }
    }
  }

  # Magic-link signing key.
  dynamic "statement" {
    for_each = var.secrets_manager_secret_arn != null ? [1] : []
    content {
      sid       = "ReadSigningSecret"
      effect    = "Allow"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = [var.secrets_manager_secret_arn]
    }
  }

  # ENI lifecycle only when this Lambda is VPC-attached (Redis store).
  dynamic "statement" {
    for_each = local.store_redis ? [1] : []
    content {
      sid       = "VpcEniManagement"
      effect    = "Allow"
      actions   = local.vpc_eni_actions
      resources = ["*"]
    }
  }
}

resource "aws_iam_role_policy" "create" {
  name   = "create-auth-challenge"
  role   = aws_iam_role.create.id
  policy = data.aws_iam_policy_document.create.json
}

# ---------------------------------------------------------------------------
# Verify role — store read/delete + secret read + ENI lifecycle.
# ---------------------------------------------------------------------------
resource "aws_iam_role" "verify" {
  name               = "${local.prefix}-verify-auth-challenge"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = local.tags
}

data "aws_iam_policy_document" "verify" {
  source_policy_documents = [data.aws_iam_policy_document.logs_verify.json]

  dynamic "statement" {
    for_each = local.store_dynamodb ? [1] : []
    content {
      sid       = "ChallengeStoreReadDelete"
      effect    = "Allow"
      actions   = ["dynamodb:GetItem", "dynamodb:DeleteItem", "dynamodb:UpdateItem"]
      resources = [aws_dynamodb_table.challenge[0].arn]
    }
  }

  dynamic "statement" {
    for_each = var.secrets_manager_secret_arn != null ? [1] : []
    content {
      sid       = "ReadSigningSecret"
      effect    = "Allow"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = [var.secrets_manager_secret_arn]
    }
  }

  dynamic "statement" {
    for_each = local.use_vpc ? [1] : []
    content {
      sid       = "VpcEniManagement"
      effect    = "Allow"
      actions   = local.vpc_eni_actions
      resources = ["*"]
    }
  }
}

resource "aws_iam_role_policy" "verify" {
  name   = "verify-auth-challenge"
  role   = aws_iam_role.verify.id
  policy = data.aws_iam_policy_document.verify.json
}
