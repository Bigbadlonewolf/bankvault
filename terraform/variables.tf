variable "project_id" {
  description = "GCP project ID where BankVault is deployed"
  type        = string
}

variable "region" {
  description = "GCP region for all regional resources (functions, scheduler, bucket)"
  type        = string
  default     = "us-central1"
}

variable "bq_location" {
  description = "BigQuery dataset location (multi-region or region)"
  type        = string
  default     = "US"
}

variable "pii_bucket_name" {
  description = "Name of the GCS bucket representing the loan-origination PII store. Must be globally unique — the default interpolates the project ID."
  type        = string
  default     = ""
}

variable "audit_dataset_id" {
  description = "BigQuery dataset ID for the JIT access audit trail"
  type        = string
  default     = "bankvault_audit"
}

variable "audit_table_id" {
  description = "BigQuery table ID for the access_grants audit ledger"
  type        = string
  default     = "access_grants"
}

variable "platform_logs_dataset_id" {
  description = "BigQuery dataset ID that receives the raw Cloud Logging export (Cloud Function execution logs) via the log sink"
  type        = string
  default     = "bankvault_platform_logs"
}

variable "grant_function_name" {
  description = "Name of the HTTP-triggered Cloud Function that validates and applies time-bound access grants"
  type        = string
  default     = "bankvault-grant-access"
}

variable "revoke_function_name" {
  description = "Name of the Pub/Sub-triggered Cloud Function that sweeps expired grants and revokes IAM bindings"
  type        = string
  default     = "bankvault-revoke-access"
}

variable "revocation_topic_name" {
  description = "Pub/Sub topic that Cloud Scheduler publishes to in order to trigger a revocation sweep"
  type        = string
  default     = "bankvault-revocation-trigger"
}

variable "revocation_schedule" {
  description = "Cron schedule (unix-cron) for the revocation sweep. Default runs every 5 minutes — the gap between window expiry and binding removal on the IAM policy itself; the CEL condition denies access immediately regardless of this schedule."
  type        = string
  default     = "*/5 * * * *"
}

variable "revocation_schedule_timezone" {
  description = "IANA timezone for the Cloud Scheduler cron expression"
  type        = string
  default     = "Etc/UTC"
}

variable "max_grant_duration_minutes" {
  description = "Hard ceiling on how long a single JIT grant window may last, enforced by grant_access regardless of what a caller requests. PCI DSS 7.2 / FFIEC least-privilege guidance: keep the window as short as the business task allows."
  type        = number
  default     = 240
}

variable "allowed_requester_domain" {
  description = "Email domain loan officers must belong to for a grant request to be accepted (e.g. bank.example.com). Set to an empty string to disable the check in a sandbox project."
  type        = string
  default     = ""
}

variable "grant_function_ingress" {
  description = "Ingress setting for the grant_access HTTP function. ALLOW_INTERNAL_ONLY restricts invocation to VPC/Cloud IAP-fronted callers; ALLOW_ALL is for local portfolio testing only."
  type        = string
  default     = "ALLOW_INTERNAL_ONLY"
}

variable "enable_example_jit_grant" {
  description = "When true, provisions one Terraform-managed example time-bound IAM binding on the PII bucket for demo_loan_officer_email, illustrating the CEL condition pattern the functions apply at runtime. Off by default — production grants are created dynamically by grant_access, never by Terraform."
  type        = bool
  default     = false
}

variable "demo_loan_officer_email" {
  description = "Email of the demo principal used only when enable_example_jit_grant is true"
  type        = string
  default     = "loan.officer@example.com"
}

variable "demo_grant_expiry" {
  description = "RFC3339 timestamp used as the CEL condition expiry for the example binding when enable_example_jit_grant is true"
  type        = string
  default     = "2026-12-31T23:59:59Z"
}
