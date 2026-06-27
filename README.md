# terraform-aws-cognito-passwordless

[![Terraform](https://img.shields.io/badge/terraform-%3E%3D1.5-7B42BC?logo=terraform&logoColor=white)](https://www.terraform.io)
[![AWS Provider](https://img.shields.io/badge/aws--provider-%3E%3D5.0-FF9900?logo=amazonaws&logoColor=white)](https://registry.terraform.io/providers/hashicorp/aws/latest)
[![Node.js](https://img.shields.io/badge/lambda-node20.x-339933?logo=nodedotjs&logoColor=white)](https://nodejs.org)
[![CI](https://img.shields.io/badge/ci-fmt%20%C2%B7%20validate%20%C2%B7%20tflint%20%C2%B7%20tfsec-2088FF?logo=githubactions&logoColor=white)](.github/workflows/terraform-ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> A reusable, DRY Terraform module that turns an Amazon Cognito User Pool into a **passwordless** identity provider — email magic links, email one-time codes, and SMS OTPs — backed by three least-privilege Lambda challenge triggers and a configurable, TTL-bounded challenge store.

---

## 🧩 How it works

The module configures Cognito's `CUSTOM_AUTH` flow with three single-purpose Lambda triggers. A short-lived secret (numeric OTP or HMAC-signed magic-link token) is generated, stored with a TTL, delivered over the chosen channel, then verified in constant time and consumed on first use.

```mermaid
sequenceDiagram
    actor User
    participant App as Client App
    participant Cognito
    participant Define as Define&nbsp;Auth&nbsp;Challenge
    participant Create as Create&nbsp;Auth&nbsp;Challenge
    participant Store as Challenge&nbsp;Store<br/>(DynamoDB / Redis)
    participant Channel as SES / SNS
    participant Verify as Verify&nbsp;Auth&nbsp;Challenge<br/>(VPC-isolated)

    User->>App: Enter email / phone
    App->>Cognito: InitiateAuth (CUSTOM_AUTH)
    Cognito->>Define: Which challenge next?
    Define-->>Cognito: CUSTOM_CHALLENGE
    Cognito->>Create: Build challenge
    Create->>Create: Generate OTP / signed token
    Create->>Store: PutItem(code, attempts=0, TTL)
    Create->>Channel: SendEmail / Publish SMS
    Channel-->>User: Code or magic link
    Create-->>Cognito: publicChallengeParameters (masked hint)
    Cognito-->>App: Challenge issued

    User->>App: Submit code / click link
    App->>Cognito: RespondToAuthChallenge(answer)
    Cognito->>Verify: Verify answer
    Verify->>Store: GetItem(challengeId)
    Verify->>Verify: constant-time compare + attempt check
    alt correct
        Verify->>Store: DeleteItem (one-time use)
        Verify-->>Cognito: answerCorrect = true
        Cognito->>Define: Which challenge next?
        Define-->>Cognito: issueTokens = true
        Cognito-->>App: ID / Access / Refresh tokens
    else wrong / expired
        Verify->>Store: increment attempts
        Verify-->>Cognito: answerCorrect = false
        Cognito->>Define: Which challenge next?
        Define-->>Cognito: re-challenge or failAuthentication
    end
```

---

## ✨ Features

- **Drop-in `CUSTOM_AUTH` passwordless flow** — three Lambda triggers (Define / Create / Verify) wired to a Cognito User Pool and app client.
- **Multiple channels** — email **magic links**, email **one-time codes**, and **SMS OTPs** (SES + SNS), individually toggleable.
- **Pluggable challenge store** — **DynamoDB** with native TTL (default, fully serverless) or **ElastiCache Redis** (sub-millisecond, in-VPC). Switch via one variable.
- **VPC isolation** — the security-critical verify Lambda runs on private, multi-AZ subnets with an egress-only security group.
- **Least-privilege IAM** — a separate role per Lambda; resource ARNs pinned wherever the AWS API allows; SES scoped by `FromAddress` condition.
- **Secrets Manager integration** — the magic-link HMAC signing key is read at runtime (and cached per execution environment), never baked into env vars.
- **Replay & brute-force resistant** — one-time-use codes, constant-time comparison, per-challenge attempt counters, and a session-level max-attempts ceiling.
- **Observability built in** — explicit CloudWatch Log Groups with enforced retention (no accidental "never expire").
- **Additive & zero-downtime** — attaching these triggers leaves existing SRP / refresh-token clients on the same pool untouched.
- **CI-gated** — `terraform fmt`, `validate`, `tflint`, `tfsec`, and Lambda syntax checks on every PR.

---

## 📥 Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| `name` | Prefix for all created resources (3–32 lowercase alphanumeric/hyphen). | `string` | n/a | yes |
| `enable_email_channel` | Enable email delivery (magic link / code) via SES. | `bool` | `true` | no |
| `enable_sms_channel` | Enable SMS one-time codes via SNS. | `bool` | `false` | no |
| `ses_from_address` | Verified From address. Required when email is enabled. | `string` | `null` | conditional |
| `ses_identity_arn` | SES identity ARN the Lambda may send from. Required when email is enabled. | `string` | `null` | conditional |
| `delivery_mode` | `code` (numeric OTP) or `magic_link` (signed link). | `string` | `"code"` | no |
| `magic_link_base_url` | Base URL for magic links. Required when `delivery_mode = "magic_link"`. | `string` | `null` | conditional |
| `code_length` | Digits in the OTP (4–10). | `number` | `6` | no |
| `code_ttl_seconds` | Challenge lifetime in seconds (30–900). | `number` | `180` | no |
| `max_attempts` | Failed verification attempts before the session fails (1–10). | `number` | `3` | no |
| `challenge_store` | `dynamodb` or `redis`. | `string` | `"dynamodb"` | no |
| `dynamodb_billing_mode` | `PAY_PER_REQUEST` or `PROVISIONED`. | `string` | `"PAY_PER_REQUEST"` | no |
| `redis_node_type` | ElastiCache node type when store is `redis`. | `string` | `"cache.t4g.micro"` | no |
| `redis_endpoint` | Use an existing Redis endpoint (`host:port`) instead of creating one. | `string` | `null` | no |
| `vpc_id` | VPC for the verify Lambda / Redis. Required for `redis` or when subnets are set. | `string` | `null` | conditional |
| `vpc_subnet_ids` | Private multi-AZ subnet IDs for VPC isolation. | `list(string)` | `[]` | no |
| `secrets_manager_secret_arn` | Secret holding `magicLinkSigningKey`. Required for `magic_link`. | `string` | `null` | conditional |
| `log_retention_days` | CloudWatch Logs retention. | `number` | `30` | no |
| `lambda_runtime` | Node.js runtime. | `string` | `"nodejs20.x"` | no |
| `lambda_architecture` | `arm64` or `x86_64`. | `string` | `"arm64"` | no |
| `tags` | Additional tags for all resources. | `map(string)` | `{}` | no |

---

## 📤 Outputs

| Name | Description |
|------|-------------|
| `user_pool_id` | ID of the passwordless Cognito User Pool. |
| `user_pool_arn` | ARN of the User Pool. |
| `user_pool_endpoint` | Pool endpoint (for issuer URLs). |
| `user_pool_client_id` | App client ID permitted to use `CUSTOM_AUTH`. |
| `challenge_store_type` | Selected store (`dynamodb` / `redis`). |
| `challenge_table_name` | DynamoDB table name, or `null` for Redis. |
| `redis_endpoint` | Redis `host:port`, or `null` for DynamoDB. |
| `lambda_function_names` | Map of the three trigger function names. |
| `lambda_role_arns` | Map of the per-Lambda IAM role ARNs. |
| `lambda_security_group_id` | SG attached to VPC-isolated Lambdas, or `null`. |

---

## 🚀 Usage

```hcl
module "passwordless" {
  source = "github.com/muhammad-imad/terraform-aws-cognito-passwordless"

  name = "acme-dev"

  # Email one-time codes, serverless DynamoDB store — no VPC required.
  enable_email_channel = true
  ses_from_address     = "no-reply@example.com"
  ses_identity_arn     = "arn:aws:ses:us-east-1:111111111111:identity/example.com"

  challenge_store    = "dynamodb"
  code_ttl_seconds   = 180
  max_attempts       = 3
  log_retention_days = 30

  tags = {
    Environment = "dev"
    Team        = "platform"
  }
}
```

For magic links + SMS over a Redis store inside a multi-AZ VPC, see
[`examples/complete`](examples/complete). The smallest possible deployment lives
in [`examples/minimal`](examples/minimal).

### Packaging the Lambdas

The triggers are zipped at apply time by `archive_file`. The AWS SDK v3 is
already provided by the `nodejs20.x` runtime, so no install is needed for the
DynamoDB path. If you select `challenge_store = "redis"`, install the `redis`
client into the `create-auth-challenge` and `verify-auth-challenge` directories
before applying:

```bash
( cd lambda/create-auth-challenge && npm install --omit=dev )
( cd lambda/verify-auth-challenge && npm install --omit=dev )
```

---

## 🔐 Security

- **VPC isolation** — the verify Lambda (the only handler that reads secrets and
  the store) runs on private, multi-AZ subnets behind an egress-only security
  group. Cognito invokes it over the AWS control plane, so no inbound network
  path is ever exposed.
- **Least-privilege IAM** — every Lambda has its own role. The define handler
  gets logs only; create gets store-write + SES/SNS + secret-read; verify gets
  store-read/delete + secret-read. Resource ARNs are pinned where the API
  supports it; SES is further constrained with a `ses:FromAddress` condition.
- **Secrets Manager** — the magic-link HMAC key is fetched at runtime and cached
  per execution environment; it is never stored in plaintext environment
  variables or Terraform state.
- **One-time use & constant-time compare** — a correct answer immediately
  deletes the challenge to defeat replay, and answers are compared with
  `crypto.timingSafeEqual` to defeat timing oracles.
- **Brute-force ceilings** — per-challenge attempt counters plus a session-level
  `max_attempts` cap enforced by the define trigger.
- **Encryption everywhere** — DynamoDB SSE + point-in-time recovery; ElastiCache
  encryption at rest and in transit.
- **TFSec in CI** — every change is statically scanned for misconfiguration.

---

## 🧭 Engineering Case Study

**Context.** Several lower environments (dev, qa, staging) each needed the same
passwordless sign-in capability, but every team was hand-rolling Cognito
triggers — inconsistent attempt limits, codes that never expired, secrets baked
into Lambda environment variables, and verify functions sitting on public
subnets. Onboarding a new environment meant copy-pasting a brittle stack.

**Approach.** I extracted the pattern into a single reusable module with safe
defaults and plan-time precondition guards, so an environment is one `module`
block away from a hardened passwordless setup. The challenge store was made
pluggable (serverless DynamoDB for cost-sensitive lower environments, Redis for
latency-sensitive ones) behind one variable, keeping the Lambda code identical
across both. The verify path — the only component touching secrets — was pulled
onto private multi-AZ subnets with least-privilege roles.

**Zero-downtime rollout.** The design is strictly additive: attaching the
`CUSTOM_AUTH` triggers to a pool leaves existing SRP and refresh-token clients
working unchanged, so production could adopt the module without invalidating a
single active session. New environments opted in first; the module proved itself
in dev/qa before any production pool was touched.

**Outcome.** Passwordless auth became a reviewed, CI-gated building block rather
than tribal knowledge — consistent expiry, attempt limits, encryption, and IAM
scoping everywhere, with new environments provisioned in minutes.

*(Generic case study — no employer, client, or proprietary detail included.)*

---

## 📄 License

[MIT](LICENSE) © 2026 Muhammad Imad
