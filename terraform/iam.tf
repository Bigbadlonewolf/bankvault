# Two service accounts, each scoped to one job. Neither can do the other's.

resource "google_service_account" "broker" {
  account_id   = "bankvault-broker"
  display_name = "BankVault request broker"
  description  = "Runs request_broker: pre-flight validation, MFA-freshness check, ledger write. Cannot create PAM grants (ADR-006)."
  project      = var.project_id
}

resource "google_service_account" "reconcile" {
  account_id   = "bankvault-reconcile"
  display_name = "BankVault reconcile sweep"
  description  = "Runs the detect-only reconcile job. Reads PAM grant state and the ledger; writes only EXPIRE_FLAG rows (code-level invariant, ADR-005)."
  project      = var.project_id
}

# Broker gets viewer only, and that is now a settled boundary rather than a pending
# question. PAM attaches a grant's privileges to the calling principal, so a broker that
# could create grants would be elevating its own service account to read credit reports
# — standing access held by a non-human identity (ADR-006). Grant-creation eligibility
# lives on the entitlement's eligible_users, which is the underwriter group.
#
# Do not add a PAM admin or requester role here. That is the decision, not an oversight.
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
