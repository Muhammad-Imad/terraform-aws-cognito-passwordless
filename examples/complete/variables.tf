variable "region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "email_domain" {
  description = "Domain used for the SES identity and the From address."
  type        = string
  default     = "example.com"
}
