terraform {
  required_version = ">= 1.6"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }

  # Week 1: local state. Migrate to a GCS backend before this leaves a single
  # laptop — local state has no locking and no history.
  #
  # backend "gcs" {
  #   bucket = "your-tfstate-bucket"
  #   prefix = "bankvault"
  # }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

# Required APIs for the JIT broker: IAM conditions, Cloud Functions v2 (runs
# on Cloud Run + Eventarc), Pub/Sub + Scheduler for the revocation sweep,
# BigQuery for the audit trail, Secret Manager for session tokens.
resource "google_project_service" "apis" {
  for_each = toset([
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "cloudfunctions.googleapis.com",
    "cloudbuild.googleapis.com",
    "run.googleapis.com",
    "eventarc.googleapis.com",
    "artifactregistry.googleapis.com",
    "pubsub.googleapis.com",
    "cloudscheduler.googleapis.com",
    "bigquery.googleapis.com",
    "bigquerydatatransfer.googleapis.com",
    "secretmanager.googleapis.com",
    "storage.googleapis.com",
    "logging.googleapis.com",
  ])

  service            = each.value
  disable_on_destroy = false
}

locals {
  common_labels = {
    environment = "prod"
    project     = "bankvault"
    managed_by  = "terraform"
  }

  # Prefix used for every request-scoped Secret Manager secret the grant
  # function creates at runtime. iam.tf scopes the grant SA's secret-admin
  # role to this prefix via an IAM condition — Terraform never creates these
  # secrets itself, since it doesn't know request IDs ahead of time.
  session_secret_prefix = "bankvault-session-"
}
