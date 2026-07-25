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

# --- Immutable (WORM) copy of the platform export ---------------------------------
#
# The BigQuery export above is queryable but NOT immutable: BQ IAM has no insert-only
# permission, and deletion_protection blocks dropping a table, not rewriting rows
# (bigquery.tf, controls-mapping.md). Anyone with dataEditor on bankvault_platform_logs
# could rewrite history. This bucket closes that gap. A second sink writes the same log
# stream to a GCS bucket whose retention policy is LOCKED, so within the retention window
# no principal — not an operator, not the sink writer, not project-owner — can delete or
# overwrite an object. That is genuine write-once-read-many: the immutable evidence copy
# the docs named as the next step.
#
# The bucket lives here, not in storage.tf, because it exists solely for this export and
# is meaningless without the sink below.
#
# IRREVERSIBLE-ACTION WARNING (retention_policy.is_locked = true, the default):
#   - Locking cannot be undone. The retention period can afterwards only be INCREASED.
#   - `terraform destroy` cannot delete this bucket until every object has aged past
#     platform_log_retention_days. A locked bucket with a 7-year hold survives 7 years.
#   - The 7-day default keeps a demo teardown cheap. Raise it to your regulatory floor
#     (e.g. 2555 for a SOX/GLBA seven-year hold) only when you mean it.
# Set var.platform_logs_worm_locked = false for a throwaway demo you plan to tear down.
resource "google_storage_bucket" "platform_logs_worm" {
  name     = coalesce(var.platform_logs_worm_bucket_name, "${var.project_id}-bankvault-logs-worm")
  location = var.region
  project  = var.project_id

  uniform_bucket_level_access = true # IAM only; required for retention lock to be the whole story
  public_access_prevention    = "enforced"

  retention_policy {
    is_locked        = var.platform_logs_worm_locked
    retention_period = var.platform_log_retention_days * 24 * 60 * 60 # days -> seconds
  }

  labels = local.common_labels

  depends_on = [google_project_service.enabled]
}

resource "google_logging_project_sink" "platform_worm" {
  name    = "bankvault-platform-worm-sink"
  project = var.project_id

  destination = "storage.googleapis.com/${google_storage_bucket.platform_logs_worm.name}"

  # Same filter as the BigQuery sink: both functions' logs plus PAM admin-activity audit.
  filter = <<-EOT
    (resource.type = "cloud_run_revision" AND resource.labels.service_name = ("bankvault-request-broker" OR "bankvault-reconcile"))
    OR protoPayload.serviceName = "privilegedaccessmanager.googleapis.com"
  EOT

  unique_writer_identity = true

  depends_on = [google_storage_bucket.platform_logs_worm]
}

# The sink writer may CREATE objects but nothing here grants delete. Create-only IAM plus
# the locked retention policy means the write path is append-only at two layers, not one:
# even a compromised sink identity cannot rewrite an already-written log object.
resource "google_storage_bucket_iam_member" "worm_sink_writer" {
  bucket = google_storage_bucket.platform_logs_worm.name
  role   = "roles/storage.objectCreator"
  member = google_logging_project_sink.platform_worm.writer_identity
}

# Close the in-window observation gap. PAM logs that a grant was issued, but without a
# DATA_READ audit config the reads an underwriter makes under that grant are not
# recorded anywhere. Enabling DATA_READ for Cloud Storage routes every object read
# inside the grant window into Cloud Logging and the platform export, so what happens
# during the 30 minutes is observed, not just that the grant existed
# (docs/interview-defense.md).
resource "google_project_iam_audit_config" "storage_data_read" {
  project = var.project_id
  service = "storage.googleapis.com"

  audit_log_config {
    log_type = "DATA_READ"
  }
}
