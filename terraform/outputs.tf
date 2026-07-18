output "credit_reports_bucket" {
  description = "The bucket standing in for the credit-report store."
  value       = google_storage_bucket.credit_reports.name
}

output "entitlement_ids" {
  description = "PAM entitlements, one per demo application."
  value       = { for k, e in google_privileged_access_manager_entitlement.credit_report_read : k => e.entitlement_id }
}

output "audit_ledger" {
  description = "Fully-qualified append-only ledger table."
  value       = "${var.project_id}.${google_bigquery_dataset.audit.dataset_id}.${google_bigquery_table.access_grants.table_id}"
}

output "platform_logs_dataset" {
  description = "Independent platform-log export dataset."
  value       = google_bigquery_dataset.platform_logs.dataset_id
}

output "request_broker_uri" {
  description = "Internal URI of the request broker (ALLOW_INTERNAL_ONLY)."
  value       = google_cloudfunctions2_function.request_broker.url
}

output "broker_service_account" {
  value = google_service_account.broker.email
}

output "reconcile_service_account" {
  value = google_service_account.reconcile.email
}
