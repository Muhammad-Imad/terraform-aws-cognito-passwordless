output "user_pool_id" {
  description = "ID of the Cognito User Pool configured for passwordless auth."
  value       = aws_cognito_user_pool.this.id
}

output "user_pool_arn" {
  description = "ARN of the Cognito User Pool."
  value       = aws_cognito_user_pool.this.arn
}

output "user_pool_endpoint" {
  description = "Endpoint of the Cognito User Pool (used to construct issuer URLs)."
  value       = aws_cognito_user_pool.this.endpoint
}

output "user_pool_client_id" {
  description = "ID of the app client permitted to use the CUSTOM_AUTH flow."
  value       = aws_cognito_user_pool_client.this.id
}

output "challenge_store_type" {
  description = "Backing store selected for challenge codes (dynamodb or redis)."
  value       = var.challenge_store
}

output "challenge_table_name" {
  description = "Name of the DynamoDB challenge table, or null when Redis is used."
  value       = local.store_dynamodb ? aws_dynamodb_table.challenge[0].name : null
}

output "redis_endpoint" {
  description = "Endpoint (host:port) of the Redis challenge store, or null when DynamoDB is used."
  value       = local.store_redis ? local.redis_endpoint : null
}

output "lambda_function_names" {
  description = "Map of the three challenge trigger function names."
  value = {
    define_auth_challenge          = aws_lambda_function.define_auth_challenge.function_name
    create_auth_challenge          = aws_lambda_function.create_auth_challenge.function_name
    verify_auth_challenge_response = aws_lambda_function.verify_auth_challenge.function_name
  }
}

output "lambda_role_arns" {
  description = "Map of the IAM role ARNs assumed by each challenge trigger."
  value = {
    define = aws_iam_role.define.arn
    create = aws_iam_role.create.arn
    verify = aws_iam_role.verify.arn
  }
}

output "lambda_security_group_id" {
  description = "Security group ID attached to the VPC-isolated Lambdas, or null when not in a VPC."
  value       = local.use_vpc ? aws_security_group.lambda[0].id : null
}
