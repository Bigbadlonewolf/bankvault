data "google_project" "this" {
  project_id = var.project_id
}

resource "google_pubsub_topic" "reconcile_trigger" {
  name    = "bankvault-reconcile-trigger"
  project = var.project_id
  labels  = local.common_labels

  depends_on = [google_project_service.enabled]
}

# Fires the detect-only reconcile sweep on a schedule (ADR-005). The cadence is
# the detection floor, not a containment SLA.
resource "google_cloud_scheduler_job" "reconcile" {
  name      = "bankvault-reconcile"
  project   = var.project_id
  region    = var.region
  schedule  = var.reconcile_schedule
  time_zone = "Etc/UTC"

  pubsub_target {
    topic_name = google_pubsub_topic.reconcile_trigger.id
    data       = base64encode(jsonencode({ trigger = "scheduled" }))
  }

  depends_on = [google_project_service.enabled]
}

# Cloud Scheduler publishes to Pub/Sub as its own Google-managed service agent; an
# OIDC-token block only applies to HTTP targets, not Pub/Sub. The agent gets publisher
# on this one topic so the scheduled job can post its trigger even when the default
# project-level binding is absent.
resource "google_pubsub_topic_iam_member" "scheduler_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.reconcile_trigger.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:service-${data.google_project.this.number}@gcp-sa-cloudscheduler.iam.gserviceaccount.com"
}
