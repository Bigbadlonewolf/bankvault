output "pii_bucket_name" {
  description = "Name of the loan-origination PII bucket protected by JIT grants"
  value       = google_storage_bucket.loan_origination_pii.name
}

output "grant_function_url" {
  description = "HTTPS URL to invoke grant_access. Not publicly reachable when ingress is ALLOW_INTERNAL_ONLY — invoke via VPC, IAP, or gcloud functions call."
  value       = google_cloudfunctions2_function.grant_access.service_config[0].uri
}

output "grant_sa_email" {
  description = "Service account email used by grant_access"
  value       = google_service_account.grant_sa.email
}

output "revoke_sa_email" {
  description = "Service account email used by revoke_access"
  value       = google_service_account.revoke_sa.email
}

output "revocation_topic_id" {
  description = "Full resource ID of the Pub/Sub topic that triggers a revocation sweep"
  value       = google_pubsub_topic.revocation_trigger.id
}

output "revocation_sweep_schedule" {
  description = "Cron schedule the revocation sweep runs on"
  value       = google_cloud_scheduler_job.revocation_sweep.schedule
}

output "audit_dataset_id" {
  description = "BigQuery dataset holding the access_grants audit ledger"
  value       = google_bigquery_dataset.audit.dataset_id
}

output "audit_table_id" {
  description = "Fully-qualified BigQuery table ID for the audit ledger"
  value       = "${var.project_id}.${google_bigquery_dataset.audit.dataset_id}.${google_bigquery_table.access_grants.table_id}"
}

output "platform_logs_dataset_id" {
  description = "BigQuery dataset receiving the raw Cloud Function execution log export"
  value       = google_bigquery_dataset.platform_logs.dataset_id
}

output "function_source_bucket" {
  description = "GCS bucket holding zipped Cloud Function source"
  value       = google_storage_bucket.function_source.name
}
