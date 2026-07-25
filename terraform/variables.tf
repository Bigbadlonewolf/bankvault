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
  description = "How fresh the underwriter's login must be, in seconds, to pass the broker's pre-flight check (ADR-004). Evidence and early rejection only — the broker creates no grants and this is not the enforcement point (ADR-006)."
  default     = 900
}

variable "reconcile_schedule" {
  type        = string
  description = "Cron for the detect-only reconcile sweep (ADR-005)."
  default     = "*/15 * * * *"
}

variable "oidc_issuer" {
  type        = string
  description = "OIDC issuer (iss) the broker requires on the caller's id_token (ADR-002/004). Empty leaves verify_identity fail-closed: every request is denied until a real IdP is wired."
  default     = ""
}

variable "oidc_audience" {
  type        = string
  description = "OIDC audience (aud) the broker requires on the caller's id_token. Empty keeps identity verification fail-closed."
  default     = ""
}

variable "oidc_jwks_uri" {
  type        = string
  description = "JWKS endpoint the broker fetches the RS256 signing key from to verify the id_token signature. Empty keeps identity verification fail-closed."
  default     = ""
}

variable "function_source_bucket_name" {
  type        = string
  description = "Bucket that holds the zipped Cloud Function source. Defaults to a project-scoped name."
  default     = ""
}

variable "platform_logs_worm_bucket_name" {
  type        = string
  description = "Globally unique name for the GCS bucket holding the immutable (WORM) copy of the platform log export. Defaults to a project-scoped name."
  default     = ""
}

variable "platform_log_retention_days" {
  type        = number
  description = "Days the WORM platform-log bucket retains each object. While the retention policy is locked, objects cannot be deleted or overwritten until this many days elapse. Default 7 keeps a demo teardown cheap; set to your regulatory floor in production (e.g. 2555 for a SOX/GLBA seven-year hold)."
  default     = 7

  validation {
    condition     = var.platform_log_retention_days >= 1 && var.platform_log_retention_days <= 3650
    error_message = "platform_log_retention_days must be between 1 and 3650 (ten years)."
  }
}

variable "platform_logs_worm_locked" {
  type        = bool
  description = "Whether to LOCK the WORM bucket's retention policy. Locking is irreversible: once applied, the retention period can only be increased, objects cannot be deleted before it elapses, and the bucket cannot be destroyed until every object ages out. True is what makes the export genuine WORM; set false only for a throwaway demo you intend to tear down before retention expires."
  default     = true
}

variable "labels" {
  type        = map(string)
  description = "Extra labels merged onto every labelable resource."
  default     = {}
}
