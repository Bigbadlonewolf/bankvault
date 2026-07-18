# The second, independent audit layer. Even if a function has a bug and skips its
# ledger write, the platform-level record still exists, produced by GCP itself
# (architecture.md, controls-mapping.md).
resource "google_logging_project_sink" "platform" {
  name    = "bankvault-platform-sink"
  project = var.project_id

  destination = "bigquery.googleapis.com/projects/${var.project_id}/datasets/${google_bigquery_dataset.platform_logs.dataset_id}"

  # Both functions' execution logs plus PAM admin-activity audit logs.
  filter = <<-EOT
    (resource.type = "cloud_run_revision" AND resource.labels.service_name = ("bankvault-request-broker" OR "bankvault-reconcile"))
    OR protoPayload.serviceName = "privilegedaccessmanager.googleapis.com"
  EOT

  unique_writer_identity = true

  bigquery_options {
    use_partitioned_tables = true
  }

  depends_on = [google_bigquery_dataset.platform_logs]
}

# The sink's generated writer identity needs to write to the destination dataset.
resource "google_bigquery_dataset_iam_member" "sink_writer" {
  dataset_id = google_bigquery_dataset.platform_logs.dataset_id
  project    = var.project_id
  role       = "roles/bigquery.dataEditor"
  member     = google_logging_project_sink.platform.writer_identity
}
