# ── Revocation trigger topic ──────────────────────────────────────────────────
resource "google_pubsub_topic" "revocation_trigger" {
  name = var.revocation_topic_name

  labels = local.common_labels

  depends_on = [google_project_service.apis]
}

# ── Scheduler service account ─────────────────────────────────────────────────
# Dedicated SA so the scheduler's only capability is "publish to this one
# topic" — it has no access to the bucket, BigQuery, or Secret Manager.
resource "google_service_account" "scheduler_sa" {
  account_id   = "bankvault-scheduler-sa"
  display_name = "BankVault Cloud Scheduler SA"
  description  = "Publishes to the revocation-trigger topic on a fixed schedule. No other permissions."
}

resource "google_pubsub_topic_iam_member" "scheduler_publisher" {
  topic  = google_pubsub_topic.revocation_trigger.name
  role   = "roles/pubsub.publisher"
  member = "serviceAccount:${google_service_account.scheduler_sa.email}"
}

# ── Scheduled revocation sweep ────────────────────────────────────────────────
# The CEL condition on each IAM binding denies access the instant
# request.time crosses window_end — enforcement does not wait on this job.
# This sweep exists to (a) remove the now-inert binding from the bucket's IAM
# policy so it doesn't accumulate indefinitely, (b) destroy the session
# secret, and (c) write the REVOKE row that closes out the audit ledger entry.
resource "google_cloud_scheduler_job" "revocation_sweep" {
  name        = "bankvault-revocation-sweep"
  description = "Triggers revoke_access to sweep expired, unrevoked BankVault grants"
  schedule    = var.revocation_schedule
  time_zone   = var.revocation_schedule_timezone
  region      = var.region

  pubsub_target {
    topic_name = google_pubsub_topic.revocation_trigger.id
    data       = base64encode(jsonencode({ trigger = "scheduled-sweep" }))
  }

  retry_config {
    retry_count = 3
  }

  depends_on = [
    google_project_service.apis,
    google_pubsub_topic_iam_member.scheduler_publisher,
  ]
}
