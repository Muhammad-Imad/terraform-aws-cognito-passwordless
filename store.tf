###############################################################################
# Challenge store
#
# Short-lived challenge codes/tokens are written by the Create Auth Challenge
# Lambda and read by the Verify Auth Challenge Lambda. Two interchangeable
# backends are offered:
#
#   * dynamodb (default) — serverless, TTL-based automatic expiry, no VPC needed.
#   * redis              — ElastiCache replication group, sub-ms reads, in-VPC.
#
# Exactly one backend is provisioned, selected by var.challenge_store.
###############################################################################

# ---------------------------------------------------------------------------
# DynamoDB backend
# ---------------------------------------------------------------------------
resource "aws_dynamodb_table" "challenge" {
  count = local.store_dynamodb ? 1 : 0

  name         = "${local.prefix}-passwordless-challenges"
  billing_mode = var.dynamodb_billing_mode
  hash_key     = "challengeId"

  # Provisioned throughput is only honoured when billing_mode is PROVISIONED;
  # keep modest defaults so the example applies cleanly in either mode.
  read_capacity  = var.dynamodb_billing_mode == "PROVISIONED" ? 5 : null
  write_capacity = var.dynamodb_billing_mode == "PROVISIONED" ? 5 : null

  attribute {
    name = "challengeId"
    type = "S"
  }

  # Native TTL guarantees codes disappear even if a verify never happens.
  ttl {
    attribute_name = "expiresAt"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = local.tags
}

# ---------------------------------------------------------------------------
# Redis (ElastiCache) backend
# ---------------------------------------------------------------------------
resource "aws_elasticache_subnet_group" "challenge" {
  count = local.manages_redis ? 1 : 0

  name       = "${local.prefix}-passwordless-redis"
  subnet_ids = local.vpc_subnets
  tags       = local.tags
}

resource "aws_security_group" "redis" {
  count = local.manages_redis ? 1 : 0

  name_prefix = "${local.prefix}-passwordless-redis-"
  description = "Ingress to the passwordless challenge Redis from the verify Lambda only"
  vpc_id      = var.vpc_id

  lifecycle {
    create_before_destroy = true
  }

  tags = local.tags
}

# Lambda -> Redis on 6379, scoped to the Lambda's own security group.
resource "aws_vpc_security_group_ingress_rule" "redis_from_lambda" {
  count = local.manages_redis ? 1 : 0

  security_group_id            = aws_security_group.redis[0].id
  description                  = "Redis from verify Lambda"
  from_port                    = 6379
  to_port                      = 6379
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.lambda[0].id
}

resource "aws_elasticache_replication_group" "challenge" {
  count = local.manages_redis ? 1 : 0

  replication_group_id = "${local.prefix}-pwdless"
  description          = "Passwordless challenge code store"

  engine                     = "redis"
  node_type                  = var.redis_node_type
  num_cache_clusters         = length(local.vpc_subnets) >= 2 ? 2 : 1
  automatic_failover_enabled = length(local.vpc_subnets) >= 2
  multi_az_enabled           = length(local.vpc_subnets) >= 2

  port               = 6379
  subnet_group_name  = aws_elasticache_subnet_group.challenge[0].name
  security_group_ids = [aws_security_group.redis[0].id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true

  tags = local.tags
}
