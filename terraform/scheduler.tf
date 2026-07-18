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
