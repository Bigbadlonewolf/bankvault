# One PAM entitlement per demo application. Each pins roles/storage.objectViewer
# to that application's object prefix through the entitlement condition, so a grant
# issued for APP-1001 cannot read APP-1002's file. PAM owns approval and expiry:
# max_request_duration caps and auto-expires the grant, which is why no custom
# revocation function exists in this repo (ADR-001).
#
# Time-bounding is PAM's grant duration, NOT a request.time CEL clause. The
# condition_expression is static per entitlement (object scope only); that is a
# property of PAM entitlements, and it is why scope is per-application rather than
# per-request. Unbounded application sets are a documented limitation (architecture.md).
resource "google_privileged_access_manager_entitlement" "credit_report_read" {
  for_each = toset(var.demo_application_ids)

  entitlement_id       = "bankvault-credit-report-${lower(each.value)}"
  location             = "global"
  parent               = "projects/${var.project_id}"
  max_request_duration = "${var.max_grant_minutes * 60}s"

  eligible_users {
    principals = [var.underwriter_group]
  }

  requester_justification_config {
    # A written justification is mandatory on every request; it lands in the ledger.
    unstructured {}
  }

  privileged_access {
    gcp_iam_access {
      resource      = "//cloudresourcemanager.googleapis.com/projects/${var.project_id}"
      resource_type = "cloudresourcemanager.googleapis.com/Project"

      role_bindings {
        role = "roles/storage.objectViewer"
        # Object-scope pin. The literal `_` is required by the GCS CEL resource-name
        # format; it is not a placeholder. This grant can read only this application's
        # objects in the credit-reports bucket.
        condition_expression = "resource.name.startsWith(\"projects/_/buckets/${local.credit_reports_bucket}/objects/${each.value}/\")"
      }
    }
  }

  approval_workflow {
    manual_approvals {
      require_approver_justification = true

      steps {
        approvals_needed = 1

        approvers {
          principals = [var.approver_group]
        }
      }
    }
  }

  depends_on = [
    google_project_service.enabled,
    google_storage_bucket.credit_reports,
  ]
}
