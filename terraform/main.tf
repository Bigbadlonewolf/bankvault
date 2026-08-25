terraform {
  required_version = ">= 1.6.0"

  required_providers {
    google = {
      source = "hashicorp/google"
      # Verified 2026-08-13: google_privileged_access_manager_entitlement landed in
      # google-beta 5.28.0 and was promoted to the GA provider in 5.38.0, so the
      # previous ">= 5.30.0" floor admitted eight GA minors that do not have the
      # resource at all. 7.41.0 is what .terraform.lock.hcl already resolved and
      # validates against; the major is bounded because v8 has no upgrade guide yet.
      version = "~> 7.41"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

locals {
  common_labels = merge(
    {
      project    = "bankvault"
      managed_by = "terraform"
      data_class = "glba-npi"
    },
    var.labels,
  )

  # APIs BankVault depends on. Enabling is idempotent.
  required_apis = [
    "privilegedaccessmanager.googleapis.com",
    "iam.googleapis.com",
    "storage.googleapis.com",
    "bigquery.googleapis.com",
    "cloudfunctions.googleapis.com",
    "run.googleapis.com",
    "cloudbuild.googleapis.com",
    "artifactregistry.googleapis.com",
    "cloudscheduler.googleapis.com",
    "pubsub.googleapis.com",
    "logging.googleapis.com",
    "eventarc.googleapis.com",
  ]
}

resource "google_project_service" "enabled" {
  for_each = toset(local.required_apis)

  project = var.project_id
  service = each.value

  disable_on_destroy = false
}
