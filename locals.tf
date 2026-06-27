locals {
  # Canonical prefix for every resource name this module owns.
  prefix = var.name

  # Resolve which channels are active and validate at plan time.
  email_enabled = var.enable_email_channel
  sms_enabled   = var.enable_sms_channel

  # The verify Lambda is VPC-isolated whenever subnets are supplied, or
  # implicitly when Redis is the store (Redis is reachable only in-VPC).
  use_vpc       = length(var.vpc_subnet_ids) > 0 || var.challenge_store == "redis"
  vpc_subnets   = var.vpc_subnet_ids
  manages_redis = var.challenge_store == "redis" && var.redis_endpoint == null

  # Single source of truth for the store choice consumed by the Lambdas.
  store_dynamodb = var.challenge_store == "dynamodb"
  store_redis    = var.challenge_store == "redis"

  redis_endpoint = local.manages_redis ? "${aws_elasticache_replication_group.challenge[0].primary_endpoint_address}:6379" : var.redis_endpoint

  # Environment shared by the three challenge Lambdas. Each handler reads only
  # what it needs; co-locating keeps configuration drift impossible.
  common_env = {
    CHALLENGE_STORE         = var.challenge_store
    DELIVERY_MODE           = var.delivery_mode
    CODE_LENGTH             = tostring(var.code_length)
    CODE_TTL_SECONDS        = tostring(var.code_ttl_seconds)
    MAX_ATTEMPTS            = tostring(var.max_attempts)
    DDB_TABLE_NAME          = local.store_dynamodb ? aws_dynamodb_table.challenge[0].name : ""
    REDIS_ENDPOINT          = local.store_redis ? local.redis_endpoint : ""
    EMAIL_ENABLED           = tostring(local.email_enabled)
    SMS_ENABLED             = tostring(local.sms_enabled)
    SES_FROM_ADDRESS        = coalesce(var.ses_from_address, "")
    MAGIC_LINK_BASE_URL     = coalesce(var.magic_link_base_url, "")
    SECRET_ARN              = coalesce(var.secrets_manager_secret_arn, "")
    POWERTOOLS_SERVICE_NAME = "${local.prefix}-passwordless"
    LOG_LEVEL               = "INFO"
  }

  tags = merge(
    {
      "Module"    = "terraform-aws-cognito-passwordless"
      "ManagedBy" = "terraform"
      "Component" = "passwordless-auth"
    },
    var.tags,
  )
}
