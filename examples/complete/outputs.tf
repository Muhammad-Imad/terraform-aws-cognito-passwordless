output "user_pool_id" {
  description = "Cognito User Pool ID."
  value       = module.passwordless.user_pool_id
}

output "user_pool_client_id" {
  description = "App client ID for the CUSTOM_AUTH flow."
  value       = module.passwordless.user_pool_client_id
}

output "redis_endpoint" {
  description = "Endpoint of the Redis challenge store."
  value       = module.passwordless.redis_endpoint
}

output "lambda_function_names" {
  description = "Names of the three challenge trigger Lambdas."
  value       = module.passwordless.lambda_function_names
}

output "lambda_security_group_id" {
  description = "Security group attached to the VPC-isolated Lambdas."
  value       = module.passwordless.lambda_security_group_id
}
