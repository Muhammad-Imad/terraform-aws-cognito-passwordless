###############################################################################
# Lambda challenge triggers
#
# Three single-purpose handlers implement the CUSTOM_AUTH state machine:
#
#   define-auth-challenge  — orchestrates the challenge sequence and enforces
#                            the max-attempts ceiling.
#   create-auth-challenge  — generates the code/token, stores it, sends it over
#                            the configured channel (SES / SNS).
#   verify-auth-challenge  — VPC-isolated; reads the stored code, compares in
#                            constant time, decrements attempts. This is the
#                            only handler that touches the store and secrets.
###############################################################################

data "archive_file" "define" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/define-auth-challenge"
  output_path = "${path.module}/.build/define-auth-challenge.zip"
}

data "archive_file" "create" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/create-auth-challenge"
  output_path = "${path.module}/.build/create-auth-challenge.zip"
}

data "archive_file" "verify" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/verify-auth-challenge"
  output_path = "${path.module}/.build/verify-auth-challenge.zip"
}

# ---------------------------------------------------------------------------
# Log groups — created explicitly so retention is enforced from day one rather
# than defaulting to "never expire" when Lambda lazily creates them.
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "define" {
  name              = "/aws/lambda/${local.prefix}-define-auth-challenge"
  retention_in_days = var.log_retention_days
  tags              = local.tags
}

resource "aws_cloudwatch_log_group" "create" {
  name              = "/aws/lambda/${local.prefix}-create-auth-challenge"
  retention_in_days = var.log_retention_days
  tags              = local.tags
}

resource "aws_cloudwatch_log_group" "verify" {
  name              = "/aws/lambda/${local.prefix}-verify-auth-challenge"
  retention_in_days = var.log_retention_days
  tags              = local.tags
}

# ---------------------------------------------------------------------------
# Define Auth Challenge — pure control logic, no network/IO, no VPC.
# ---------------------------------------------------------------------------
resource "aws_lambda_function" "define_auth_challenge" {
  function_name = "${local.prefix}-define-auth-challenge"
  role          = aws_iam_role.define.arn
  handler       = "index.handler"
  runtime       = var.lambda_runtime
  architectures = [var.lambda_architecture]
  timeout       = 5
  memory_size   = 128

  filename         = data.archive_file.define.output_path
  source_code_hash = data.archive_file.define.output_base64sha256

  environment {
    variables = {
      MAX_ATTEMPTS = tostring(var.max_attempts)
      LOG_LEVEL    = local.common_env.LOG_LEVEL
    }
  }

  depends_on = [aws_cloudwatch_log_group.define]
  tags       = local.tags
}

# ---------------------------------------------------------------------------
# Create Auth Challenge — generates and delivers the code/token.
# Runs in-VPC only if Redis is the store (it must reach the cache).
# ---------------------------------------------------------------------------
resource "aws_lambda_function" "create_auth_challenge" {
  function_name = "${local.prefix}-create-auth-challenge"
  role          = aws_iam_role.create.arn
  handler       = "index.handler"
  runtime       = var.lambda_runtime
  architectures = [var.lambda_architecture]
  timeout       = 10
  memory_size   = 256

  filename         = data.archive_file.create.output_path
  source_code_hash = data.archive_file.create.output_base64sha256

  environment {
    variables = local.common_env
  }

  dynamic "vpc_config" {
    for_each = local.store_redis ? [1] : []
    content {
      subnet_ids         = local.vpc_subnets
      security_group_ids = [aws_security_group.lambda[0].id]
    }
  }

  depends_on = [aws_cloudwatch_log_group.create]
  tags       = local.tags
}

# ---------------------------------------------------------------------------
# Verify Auth Challenge — VPC-isolated. The only handler with store + secret
# access, kept on private multi-AZ subnets with no public egress required.
# ---------------------------------------------------------------------------
resource "aws_lambda_function" "verify_auth_challenge" {
  function_name = "${local.prefix}-verify-auth-challenge"
  role          = aws_iam_role.verify.arn
  handler       = "index.handler"
  runtime       = var.lambda_runtime
  architectures = [var.lambda_architecture]
  timeout       = 10
  memory_size   = 256

  filename         = data.archive_file.verify.output_path
  source_code_hash = data.archive_file.verify.output_base64sha256

  environment {
    variables = local.common_env
  }

  dynamic "vpc_config" {
    for_each = local.use_vpc ? [1] : []
    content {
      subnet_ids         = local.vpc_subnets
      security_group_ids = [aws_security_group.lambda[0].id]
    }
  }

  depends_on = [aws_cloudwatch_log_group.verify]
  tags       = local.tags
}

# ---------------------------------------------------------------------------
# Security group for the VPC-isolated Lambdas. Egress-only; ingress is never
# required because Cognito invokes Lambda over the AWS control plane, not the
# network path.
# ---------------------------------------------------------------------------
resource "aws_security_group" "lambda" {
  count = local.use_vpc ? 1 : 0

  name_prefix = "${local.prefix}-passwordless-lambda-"
  description = "Egress for VPC-isolated passwordless Lambdas"
  vpc_id      = var.vpc_id

  lifecycle {
    create_before_destroy = true
  }

  tags = local.tags
}

resource "aws_vpc_security_group_egress_rule" "lambda_all" {
  count = local.use_vpc ? 1 : 0

  security_group_id = aws_security_group.lambda[0].id
  description       = "Allow Lambda egress to VPC endpoints / AWS APIs"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

# ---------------------------------------------------------------------------
# Permit Cognito to invoke each trigger. Scoped to this pool's ARN so the
# functions cannot be invoked by an unrelated pool.
# ---------------------------------------------------------------------------
resource "aws_lambda_permission" "define" {
  statement_id  = "AllowCognitoInvokeDefine"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.define_auth_challenge.function_name
  principal     = "cognito-idp.amazonaws.com"
  source_arn    = aws_cognito_user_pool.this.arn
}

resource "aws_lambda_permission" "create" {
  statement_id  = "AllowCognitoInvokeCreate"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.create_auth_challenge.function_name
  principal     = "cognito-idp.amazonaws.com"
  source_arn    = aws_cognito_user_pool.this.arn
}

resource "aws_lambda_permission" "verify" {
  statement_id  = "AllowCognitoInvokeVerify"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.verify_auth_challenge.function_name
  principal     = "cognito-idp.amazonaws.com"
  source_arn    = aws_cognito_user_pool.this.arn
}
