locals {
  credit_reports_bucket = coalesce(
    var.credit_reports_bucket_name,
    "${var.project_id}-credit-reports",
  )
  function_source_bucket = coalesce(
    var.function_source_bucket_name,
    "${var.project_id}-bankvault-fn-src",
  )
}

# Stand-in for the credit-report store. One object per application under an
# objects/<application_id>/ prefix; a PAM entitlement pins each grant to one prefix.
resource "google_storage_bucket" "credit_reports" {
  name     = local.credit_reports_bucket
  location = var.region
  project  = var.project_id

  uniform_bucket_level_access = true # no ACLs; IAM only, so the PAM condition is the whole story
  public_access_prevention    = "enforced"

  versioning {
    enabled = true # a deleted or overwritten credit report is recoverable for audit
  }

  labels = local.common_labels

  depends_on = [google_project_service.enabled]
}

# Bucket for zipped function source. Not public, not versioned by requirement.
resource "google_storage_bucket" "function_source" {
  name     = local.function_source_bucket
  location = var.region
  project  = var.project_id

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  labels = local.common_labels

  depends_on = [google_project_service.enabled]
}
