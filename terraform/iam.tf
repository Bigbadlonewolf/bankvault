# Two service accounts, each scoped to one job. Neither can do the other's.

resource "google_service_account" "broker" {
  account_id   = "bankvault-broker"
  display_name = "BankVault request broker"
  description  = "Runs request_broker: MFA-freshness gate, validation, PAM grant creation, ledger write."
  project      = var.project_id
}

resource "google_service_account" "reconcile" {
  account_id   = "bankvault-reconcile"
  display_name = "BankVault reconcile sweep"
  description  = "Runs the detect-only reconcile job. Reads PAM grant state and the ledger; writes only EXPIRE_FLAG rows (code-level invariant, ADR-005)."
  project      = var.project_id
}

# Broker can read PAM entitlements and grants. The permission to CREATE a grant
# depends on the request model verified per ADR-001 (broker-mediated vs direct).
# Read access is the floor both models need; grant-creation eligibility is on the
# entitlement's eligible_users, not a project role.
resource "google_project_iam_member" "broker_pam_viewer" {
  project = var.project_id
  role    = "roles/privilegedaccessmanager.viewer"
  member  = "serviceAccount:${google_service_account.broker.email}"
}

# Reconcile reads PAM grant state to catch a grant still active past its window.
resource "google_project_iam_member" "reconcile_pam_viewer" {
  project = var.project_id
  role    = "roles/privilegedaccessmanager.viewer"
  member  = "serviceAccount:${google_service_account.reconcile.email}"
}

# Both functions run queries; jobUser lets them start BigQuery jobs. Dataset-level
# data access is bound narrowly in bigquery.tf, not here.
resource "google_project_iam_member" "broker_bq_job" {
  project = var.project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:${google_service_account.broker.email}"
}

resource "google_project_iam_member" "reconcile_bq_job" {
  project = var.project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:${google_service_account.reconcile.email}"
}
