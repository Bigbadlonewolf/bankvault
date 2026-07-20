# The audit ledger. Append-only by convention (never UPDATE); a grant's lifecycle
# is reconstructed by querying request_id, not by mutating a status column. That
# is what makes it SOX 404 evidence (ADR-005, controls-mapping.md).
resource "google_bigquery_dataset" "audit" {
  dataset_id  = "bankvault_audit"
  project     = var.project_id
  location    = var.region
  description = "BankVault append-only access ledger."

  labels = local.common_labels

  depends_on = [google_project_service.enabled]
}

resource "google_bigquery_table" "access_grants" {
  dataset_id          = google_bigquery_dataset.audit.dataset_id
  table_id            = "access_grants"
  project             = var.project_id
  deletion_protection = true

  time_partitioning {
    type  = "DAY"
    field = "event_time"
  }

  schema = jsonencode([
    { name = "request_id", type = "STRING", mode = "REQUIRED", description = "Correlates all events for one request." },
    { name = "event_time", type = "TIMESTAMP", mode = "REQUIRED", description = "When this event was recorded." },
    { name = "action_type", type = "STRING", mode = "REQUIRED", description = "REQUEST | GRANT | DENY | EXPIRE_FLAG." },
    { name = "requested_by", type = "STRING", mode = "NULLABLE", description = "Underwriter email." },
    { name = "approved_by", type = "STRING", mode = "NULLABLE", description = "Approver email." },
    { name = "application_id", type = "STRING", mode = "NULLABLE", description = "Loan application the access is scoped to." },
    { name = "resource_path", type = "STRING", mode = "NULLABLE", description = "Object prefix the grant pins to." },
    { name = "justification", type = "STRING", mode = "NULLABLE", description = "Requester's written reason." },
    { name = "duration_seconds", type = "INTEGER", mode = "NULLABLE", description = "Requested grant duration." },
    { name = "window_end", type = "TIMESTAMP", mode = "NULLABLE", description = "When the grant is expected to expire." },
    { name = "mfa_auth_time", type = "TIMESTAMP", mode = "NULLABLE", description = "IdP auth_time recorded at pre-flight. Evidence at 15 minutes; enforcement is the ACM reauth binding at 1 hour (ADR-004, ADR-006)." },
    { name = "decision_reason", type = "STRING", mode = "NULLABLE", description = "Why a request was denied, or a flag was raised." },
    { name = "entitlement_name", type = "STRING", mode = "NULLABLE", description = "PAM entitlement the cleared request should be made against. Written on REQUEST rows by the broker (ADR-006)." },
    { name = "pam_grant_name", type = "STRING", mode = "NULLABLE", description = "PAM grant resource name. The broker never sets this; it does not create grants (ADR-006). Populated by reconcile from PAM grant state." },
  ])

  labels = local.common_labels
}

# Dataset for the independent platform-log export (logging.tf routes logs here).
resource "google_bigquery_dataset" "platform_logs" {
  dataset_id  = "bankvault_platform_logs"
  project     = var.project_id
  location    = var.region
  description = "Independent Cloud Logging export: broker, reconcile, and PAM admin-activity audit logs."

  labels = local.common_labels

  depends_on = [google_project_service.enabled]
}

# Broker writes the ledger. Reconcile reads it and appends EXPIRE_FLAG rows.
# Single append-only ledger, so both hold dataEditor on this one dataset; that
# reconcile only ever writes EXPIRE_FLAG rows is a code-level invariant with tests
# behind it (ADR-005), not an IAM boundary.
resource "google_bigquery_dataset_iam_member" "broker_audit_editor" {
  dataset_id = google_bigquery_dataset.audit.dataset_id
  project    = var.project_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.broker.email}"
}

resource "google_bigquery_dataset_iam_member" "reconcile_audit_editor" {
  dataset_id = google_bigquery_dataset.audit.dataset_id
  project    = var.project_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.reconcile.email}"
}

# Reconcile reconstructs grants from the PAM audit logs the sink writes to this
# dataset (ADR-006), so it needs read access. It never writes here; the platform
# export stays an independent record application code cannot alter.
resource "google_bigquery_dataset_iam_member" "reconcile_platform_reader" {
  dataset_id = google_bigquery_dataset.platform_logs.dataset_id
  project    = var.project_id
  role       = "roles/bigquery.dataViewer"
  member     = "serviceAccount:${google_service_account.reconcile.email}"
}
