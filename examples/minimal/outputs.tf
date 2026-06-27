output "user_pool_id" {
  description = "Cognito User Pool ID."
  value       = module.passwordless.user_pool_id
}

output "user_pool_client_id" {
  description = "App client ID for the CUSTOM_AUTH flow."
  value       = module.passwordless.user_pool_client_id
}

output "challenge_table_name" {
  description = "DynamoDB challenge table name."
  value       = module.passwordless.challenge_table_name
}
