# ── Source bucket ──────────────────────────────────────────────────────────
resource "google_storage_bucket" "function_source" {
  name                        = "${var.project_id}-bankvault-source"
  location                    = var.region
  force_destroy               = true
  uniform_bucket_level_access = true

  labels = local.common_labels

  versioning {
    enabled = true
  }

  depends_on = [google_project_service.apis]
}

data "archive_file" "grant_access_source" {
  type        = "zip"
  source_dir  = "${path.module}/../functions/grant_access"
  output_path = "${path.module}/.build/grant-access-source.zip"
  excludes    = ["__pycache__", "*.pyc", ".pytest_cache"]
}

data "archive_file" "revoke_access_source" {
  type        = "zip"
  source_dir  = "${path.module}/../functions/revoke_access"
  output_path = "${path.module}/.build/revoke-access-source.zip"
  excludes    = ["__pycache__", "*.pyc", ".pytest_cache"]
}

resource "google_storage_bucket_object" "grant_access_source" {
  name   = "grant-access-source-${data.archive_file.grant_access_source.output_md5}.zip"
  bucket = google_storage_bucket.function_source.name
  source = data.archive_file.grant_access_source.output_path
}

resource "google_storage_bucket_object" "revoke_access_source" {
  name   = "revoke-access-source-${data.archive_file.revoke_access_source.output_md5}.zip"
  bucket = google_storage_bucket.function_source.name
  source = data.archive_file.revoke_access_source.output_path
}

# ── grant_access: HTTP-triggered approval workflow engine ────────────────────
resource "google_cloudfunctions2_function" "grant_access" {
  provider    = google-beta
  name        = var.grant_function_name
  location    = var.region
  description = "BankVault: validates a JIT access request and applies a time-bound IAM binding on the loan-origination PII bucket."

  labels = local.common_labels

  build_config {
    runtime     = "python312"
    entry_point = "grant_access"

    source {
      storage_source {
        bucket = google_storage_bucket.function_source.name
        object = google_storage_bucket_object.grant_access_source.name
      }
    }
  }

  service_config {
    min_instance_count             = 0
    max_instance_count             = 10
    available_memory               = "256M"
    timeout_seconds                = 30
    service_account_email          = google_service_account.grant_sa.email
    ingress_settings               = var.grant_function_ingress
    all_traffic_on_latest_revision = true

    environment_variables = {
      PII_BUCKET_NAME            = google_storage_bucket.loan_origination_pii.name
      AUDIT_DATASET              = google_bigquery_dataset.audit.dataset_id
      AUDIT_TABLE                = google_bigquery_table.access_grants.table_id
      SESSION_SECRET_PREFIX      = local.session_secret_prefix
      MAX_GRANT_DURATION_MINUTES = tostring(var.max_grant_duration_minutes)
      ALLOWED_REQUESTER_DOMAIN   = var.allowed_requester_domain
      # GOOGLE_CLOUD_PROJECT is injected automatically by the runtime
    }
  }

  depends_on = [
    google_project_service.apis,
    google_storage_bucket_iam_member.grant_sa_bucket_iam_admin,
    google_project_iam_member.grant_sa_secret_admin_scoped,
    google_bigquery_dataset_iam_member.grant_sa_audit_editor,
    google_project_iam_member.grant_sa_log_writer,
  ]
}

# ── revoke_access: Pub/Sub-triggered revocation sweep ─────────────────────────
resource "google_cloudfunctions2_function" "revoke_access" {
  provider    = google-beta
  name        = var.revoke_function_name
  location    = var.region
  description = "BankVault: sweeps the audit ledger for expired, unrevoked grants and removes their IAM bindings and session secrets."

  labels = local.common_labels

  build_config {
    runtime     = "python312"
    entry_point = "revoke_access"

    source {
      storage_source {
        bucket = google_storage_bucket.function_source.name
        object = google_storage_bucket_object.revoke_access_source.name
      }
    }
  }

  service_config {
    min_instance_count             = 0
    max_instance_count             = 5
    available_memory               = "256M"
    timeout_seconds                = 60
    service_account_email          = google_service_account.revoke_sa.email
    ingress_settings               = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision = true

    environment_variables = {
      PII_BUCKET_NAME       = google_storage_bucket.loan_origination_pii.name
      AUDIT_DATASET         = google_bigquery_dataset.audit.dataset_id
      AUDIT_TABLE           = google_bigquery_table.access_grants.table_id
      SESSION_SECRET_PREFIX = local.session_secret_prefix
    }
  }

  event_trigger {
    trigger_region        = var.region
    event_type            = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic          = google_pubsub_topic.revocation_trigger.id
    retry_policy          = "RETRY_POLICY_RETRY"
    service_account_email = google_service_account.revoke_sa.email
  }

  depends_on = [
    google_project_service.apis,
    google_storage_bucket_iam_member.revoke_sa_bucket_iam_admin,
    google_project_iam_member.revoke_sa_secret_admin_scoped,
    google_bigquery_dataset_iam_member.revoke_sa_audit_editor,
    google_project_iam_member.revoke_sa_bq_job_user,
    google_project_iam_member.revoke_sa_log_writer,
    google_project_iam_member.eventarc_service_agent,
    google_project_iam_member.run_invoker_pubsub,
  ]
}
