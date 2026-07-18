variable "project_id" {
  type        = string
  description = "GCP project that hosts BankVault. Required."
}

variable "region" {
  type        = string
  description = "Region for the bucket, functions, and scheduler."
  default     = "us-central1"
}

variable "allowed_domain" {
  type        = string
  description = "Email domain both requester and approver must belong to."
  default     = "lender.example.com"
}

variable "underwriter_group" {
  type        = string
  description = "Group email whose members are eligible to request a credit-report grant."
  default     = "group:underwriters@lender.example.com"
}

variable "approver_group" {
  type        = string
  description = "Group email whose members can approve a grant request. Must differ from the underwriter group (segregation of duties, ADR-003)."
  default     = "group:underwriting-leads@lender.example.com"
}

variable "credit_reports_bucket_name" {
  type        = string
  description = "Globally unique name for the GCS bucket standing in for the credit-report store. Defaults to a project-scoped name."
  default     = ""
}

variable "demo_application_ids" {
  type        = list(string)
  description = "Loan applications that get a pre-provisioned, object-scoped PAM entitlement. One entitlement per application (ADR-003, architecture.md limitation)."
  default     = ["APP-1001", "APP-1002"]
}

variable "max_grant_minutes" {
  type        = number
  description = "Maximum minutes a credit-report grant can last. PAM caps and expires the grant at this bound (ADR-001, ADR-005)."
  default     = 30

  validation {
    condition     = var.max_grant_minutes > 0 && var.max_grant_minutes <= 120
    error_message = "max_grant_minutes must be between 1 and 120. A privileged credit-report read does not need hours."
  }
}

variable "max_auth_age_seconds" {
  type        = number
  description = "How fresh the underwriter's login must be, in seconds, for the broker to create a grant (ADR-004). Passed to request_broker."
  default     = 300
}

variable "reconcile_schedule" {
  type        = string
  description = "Cron for the detect-only reconcile sweep (ADR-005)."
  default     = "*/15 * * * *"
}

variable "function_source_bucket_name" {
  type        = string
  description = "Bucket that holds the zipped Cloud Function source. Defaults to a project-scoped name."
  default     = ""
}

variable "labels" {
  type        = map(string)
  description = "Extra labels merged onto every labelable resource."
  default     = {}
}
