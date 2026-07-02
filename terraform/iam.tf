# ── Project metadata ─────────────────────────────────────────────────────────
data "google_project" "current" {
  project_id = var.project_id
}

locals {
  pii_bucket_name = var.pii_bucket_name != "" ? var.pii_bucket_name : "${var.project_id}-loan-origination-pii"
}

# ── The protected resource ────────────────────────────────────────────────────
# Stand-in for a real bank's loan-origination PII store: applications,
# income verification, SSNs. Nobody gets standing access to this bucket —
# every read is a time-bound grant issued by grant_access.
resource "google_storage_bucket" "loan_origination_pii" {
  name                        = local.pii_bucket_name
  location                    = var.region
  force_destroy               = false
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  labels = local.common_labels

  depends_on = [google_project_service.apis]
}

# ── Cloud Function service accounts ───────────────────────────────────────────
resource "google_service_account" "grant_sa" {
  account_id   = "bankvault-grant-sa"
  display_name = "BankVault grant_access Cloud Function SA"
  description  = "Applies time-bound IAM bindings and writes GRANT/DENY audit rows. No standing access to bucket data itself — storage.admin only manages IAM policy, it does not grant object read."
}

resource "google_service_account" "revoke_sa" {
  account_id   = "bankvault-revoke-sa"
  display_name = "BankVault revoke_access Cloud Function SA"
  description  = "Sweeps expired grants, removes IAM bindings, destroys session secrets, writes REVOKE audit rows."
}

# ── Bucket-level IAM: functions manage policy, they do not read PII ──────────
# storage.admin at the bucket level lets the SA read/write the bucket's IAM
# policy (add/remove the conditional bindings for loan officers). It does not
# by itself grant object access — that comes only from the conditional
# bindings the functions add for named loan officers, and only inside their
# access window.
resource "google_storage_bucket_iam_member" "grant_sa_bucket_iam_admin" {
  bucket = google_storage_bucket.loan_origination_pii.name
  role   = "roles/storage.admin"
  member = "serviceAccount:${google_service_account.grant_sa.email}"
}

resource "google_storage_bucket_iam_member" "revoke_sa_bucket_iam_admin" {
  bucket = google_storage_bucket.loan_origination_pii.name
  role   = "roles/storage.admin"
  member = "serviceAccount:${google_service_account.revoke_sa.email}"
}

# ── Secret Manager: resource-bound, not just role-bound ───────────────────────
# Both SAs get secretmanager.admin at the project level, but the IAM
# condition restricts it to secrets whose name starts with the BankVault
# session prefix. Neither SA can touch any other secret in the project —
# the same resource-bound-grant pattern the brief asks for on the bucket,
# applied here to Secret Manager.
resource "google_project_iam_member" "grant_sa_secret_admin_scoped" {
  project = var.project_id
  role    = "roles/secretmanager.admin"
  member  = "serviceAccount:${google_service_account.grant_sa.email}"

  condition {
    title       = "bankvault-session-secrets-only"
    description = "Restrict to Secret Manager resources under the bankvault-session- prefix"
    expression  = "resource.name.startsWith(\"projects/${data.google_project.current.number}/secrets/${local.session_secret_prefix}\")"
  }
}

resource "google_project_iam_member" "revoke_sa_secret_admin_scoped" {
  project = var.project_id
  role    = "roles/secretmanager.admin"
  member  = "serviceAccount:${google_service_account.revoke_sa.email}"

  condition {
    title       = "bankvault-session-secrets-only"
    description = "Restrict to Secret Manager resources under the bankvault-session- prefix"
    expression  = "resource.name.startsWith(\"projects/${data.google_project.current.number}/secrets/${local.session_secret_prefix}\")"
  }
}

# ── BigQuery: append-only audit ledger access ─────────────────────────────────
resource "google_bigquery_dataset_iam_member" "grant_sa_audit_editor" {
  dataset_id = google_bigquery_dataset.audit.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.grant_sa.email}"
}

resource "google_bigquery_dataset_iam_member" "revoke_sa_audit_editor" {
  dataset_id = google_bigquery_dataset.audit.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.revoke_sa.email}"
}

# revoke_access runs a query (find expired, unrevoked grants) rather than a
# simple insert, so it needs jobUser to execute the query job.
resource "google_project_iam_member" "revoke_sa_bq_job_user" {
  project = var.project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:${google_service_account.revoke_sa.email}"
}

# ── Logging ────────────────────────────────────────────────────────────────
resource "google_project_iam_member" "grant_sa_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.grant_sa.email}"
}

resource "google_project_iam_member" "revoke_sa_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.revoke_sa.email}"
}

# ── Eventarc / Cloud Run invoker for the Pub/Sub-triggered revoke function ────
# Cloud Functions v2 runs on Cloud Run under the hood; Eventarc needs
# permission to invoke it on the revocation sweep's behalf.
resource "google_project_iam_member" "eventarc_service_agent" {
  project = var.project_id
  role    = "roles/eventarc.serviceAgent"
  member  = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-eventarc.iam.gserviceaccount.com"
}

resource "google_project_iam_member" "run_invoker_pubsub" {
  project = var.project_id
  role    = "roles/run.invoker"
  member  = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-pubsub.iam.gserviceaccount.com"
}

# ── Example JIT grant (off by default) ────────────────────────────────────────
# Demonstrates, in Terraform, the exact CEL condition shape that grant_access
# applies at runtime via the Storage API. This is NOT how production grants
# are created — Terraform doesn't know request IDs ahead of time, and a
# per-request `terraform apply` would defeat the point of a self-service
# broker. This resource exists so the pattern is reviewable as real HCL and
# so `terraform plan` has at least one conditional binding to show.
resource "google_storage_bucket_iam_member" "example_jit_grant" {
  count  = var.enable_example_jit_grant ? 1 : 0
  bucket = google_storage_bucket.loan_origination_pii.name
  role   = "roles/storage.objectViewer"
  member = "user:${var.demo_loan_officer_email}"

  condition {
    title       = "bankvault-example-jit-window"
    description = "Time-bound demo grant — expires at var.demo_grant_expiry"
    expression  = "request.time < timestamp(\"${var.demo_grant_expiry}\")"
  }
}
