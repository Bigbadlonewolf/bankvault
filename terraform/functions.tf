locals {
  entitlement_prefix = "bankvault-credit-report-"
}

# Zip each function's source. archive_file rezips when the source changes; the
# object name carries the hash, so a code change forces a new deploy.
data "archive_file" "request_broker" {
  type        = "zip"
  source_dir  = "${path.module}/../functions/request_broker"
  output_path = "${path.module}/.build/request_broker.zip"
}

data "archive_file" "reconcile" {
  type        = "zip"
  source_dir  = "${path.module}/../functions/reconcile"
  output_path = "${path.module}/.build/reconcile.zip"
}

resource "google_storage_bucket_object" "request_broker_src" {
  name   = "sources/request_broker-${data.archive_file.request_broker.output_md5}.zip"
  bucket = google_storage_bucket.function_source.name
  source = data.archive_file.request_broker.output_path
}

resource "google_storage_bucket_object" "reconcile_src" {
  name   = "sources/reconcile-${data.archive_file.reconcile.output_md5}.zip"
  bucket = google_storage_bucket.function_source.name
  source = data.archive_file.reconcile.output_path
}

resource "google_cloudfunctions2_function" "request_broker" {
  name     = "bankvault-request-broker"
  location = var.region
  project  = var.project_id

  build_config {
    runtime     = "python312"
    entry_point = "handle_request"
    source {
      storage_source {
        bucket = google_storage_bucket.function_source.name
        object = google_storage_bucket_object.request_broker_src.name
      }
    }
  }

  service_config {
    max_instance_count    = 3
    available_memory      = "256M"
    timeout_seconds       = 60
    service_account_email = google_service_account.broker.email

    # Internal only. This is a back-office control plane, not a public endpoint.
    ingress_settings = "ALLOW_INTERNAL_ONLY"

    environment_variables = {
      PROJECT_ID           = var.project_id
      LOCATION             = "global"
      AUDIT_DATASET        = google_bigquery_dataset.audit.dataset_id
      LEDGER_TABLE         = google_bigquery_table.access_grants.table_id
      CREDIT_BUCKET        = local.credit_reports_bucket
      ALLOWED_DOMAIN       = var.allowed_domain
      MAX_AUTH_AGE_SECONDS = tostring(var.max_auth_age_seconds)
      MAX_GRANT_MINUTES    = tostring(var.max_grant_minutes)
      ENTITLEMENT_PREFIX   = local.entitlement_prefix
    }
  }

  labels = local.common_labels

  depends_on = [google_project_service.enabled]
}

# Who may invoke the broker. The function is internal-only (ALLOW_INTERNAL_ONLY) and
# a skippable pre-flight gate rather than a chokepoint (ADR-006), so invocation is not
# the privilege boundary. This grants run.invoker to one dedicated identity and nothing
# else, making the permitted internal caller explicit instead of an implicit
# project-level grant.
resource "google_cloud_run_service_iam_member" "broker_invoker" {
  project  = var.project_id
  location = google_cloudfunctions2_function.request_broker.location
  service  = google_cloudfunctions2_function.request_broker.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.broker_invoker.email}"
}

resource "google_cloudfunctions2_function" "reconcile" {
  name     = "bankvault-reconcile"
  location = var.region
  project  = var.project_id

  build_config {
    runtime     = "python312"
    entry_point = "handle_event"
    source {
      storage_source {
        bucket = google_storage_bucket.function_source.name
        object = google_storage_bucket_object.reconcile_src.name
      }
    }
  }

  service_config {
    max_instance_count    = 1
    available_memory      = "256M"
    timeout_seconds       = 120
    service_account_email = google_service_account.reconcile.email

    environment_variables = {
      PROJECT_ID         = var.project_id
      LOCATION           = "global"
      AUDIT_DATASET      = google_bigquery_dataset.audit.dataset_id
      LEDGER_TABLE       = google_bigquery_table.access_grants.table_id
      PLATFORM_DATASET   = google_bigquery_dataset.platform_logs.dataset_id
      CREDIT_BUCKET      = local.credit_reports_bucket
      ENTITLEMENT_PREFIX = local.entitlement_prefix
    }
  }

  event_trigger {
    trigger_region        = var.region
    event_type            = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic          = google_pubsub_topic.reconcile_trigger.id
    service_account_email = google_service_account.reconcile.email
    retry_policy          = "RETRY_POLICY_RETRY"
  }

  labels = local.common_labels

  depends_on = [google_project_service.enabled]
}
