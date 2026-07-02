"""Unit tests for functions/grant_access/main.py. All GCP clients are mocked —
no network calls, no real project required.
"""

import importlib.util
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

# Env vars must exist before the module is imported (module reads them at
# import time via os.environ[...]).
os.environ.setdefault("GOOGLE_CLOUD_PROJECT", "test-project")
os.environ.setdefault("PII_BUCKET_NAME", "test-project-loan-origination-pii")
os.environ.setdefault("AUDIT_DATASET", "bankvault_audit")
os.environ.setdefault("AUDIT_TABLE", "access_grants")
os.environ.setdefault("SESSION_SECRET_PREFIX", "bankvault-session-")
os.environ.setdefault("MAX_GRANT_DURATION_MINUTES", "240")
os.environ.setdefault("ALLOWED_REQUESTER_DOMAIN", "bank.example.com")

# Loaded under a unique module name (not "main") so this file can coexist
# with tests/test_revoke_access.py, which imports a different main.py.
_MAIN_PATH = os.path.join(os.path.dirname(__file__), "..", "functions", "grant_access", "main.py")
_spec = importlib.util.spec_from_file_location("grant_access_main", _MAIN_PATH)
main = importlib.util.module_from_spec(_spec)
sys.modules["grant_access_main"] = main
_spec.loader.exec_module(main)


def _valid_payload(**overrides) -> dict:
    payload = {
        "requested_by": "officer@bank.example.com",
        "approved_by": "manager@bank.example.com",
        "justification": "Processing loan application LN-4471",
        "duration_minutes": 60,
    }
    payload.update(overrides)
    return payload


# ── validate_request ────────────────────────────────────────────────────────


class TestValidateRequest(unittest.TestCase):
    def test_valid_request_has_no_errors(self):
        self.assertEqual(main.validate_request(_valid_payload()), [])

    def test_missing_requested_by(self):
        payload = _valid_payload()
        del payload["requested_by"]
        errors = main.validate_request(payload)
        self.assertTrue(any("requested_by is required" in e for e in errors))

    def test_wrong_domain_rejected(self):
        payload = _valid_payload(requested_by="officer@notthebank.com")
        errors = main.validate_request(payload)
        self.assertTrue(any("domain" in e for e in errors))

    def test_missing_approved_by(self):
        payload = _valid_payload()
        del payload["approved_by"]
        errors = main.validate_request(payload)
        self.assertTrue(any("approved_by is required" in e for e in errors))

    def test_self_approval_rejected(self):
        payload = _valid_payload(approved_by="officer@bank.example.com")
        errors = main.validate_request(payload)
        self.assertTrue(any("segregation of duties" in e for e in errors))

    def test_missing_justification(self):
        payload = _valid_payload()
        del payload["justification"]
        errors = main.validate_request(payload)
        self.assertTrue(any("justification is required" in e for e in errors))

    def test_duration_exceeds_cap(self):
        payload = _valid_payload(duration_minutes=500)
        errors = main.validate_request(payload)
        self.assertTrue(any("exceeds the 240-minute cap" in e for e in errors))

    def test_zero_duration_rejected(self):
        payload = _valid_payload(duration_minutes=0)
        errors = main.validate_request(payload)
        self.assertTrue(any("must be positive" in e for e in errors))

    def test_non_integer_duration_rejected(self):
        payload = _valid_payload(duration_minutes="soon")
        errors = main.validate_request(payload)
        self.assertTrue(any("must be an integer" in e for e in errors))

    def test_empty_payload_has_multiple_errors(self):
        errors = main.validate_request({})
        self.assertGreaterEqual(len(errors), 3)


# ── build_condition_expression ─────────────────────────────────────────────


class TestBuildConditionExpression(unittest.TestCase):
    def test_time_only_condition(self):
        window_end = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        expr = main.build_condition_expression(window_end, None)
        self.assertEqual(expr, 'request.time < timestamp("2026-01-01T12:00:00Z")')

    def test_time_and_resource_condition(self):
        window_end = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        expr = main.build_condition_expression(window_end, "LN-4471")
        self.assertIn('request.time < timestamp("2026-01-01T12:00:00Z")', expr)
        self.assertIn("&&", expr)
        self.assertIn(
            f'resource.name.startsWith("projects/_/buckets/{main.PII_BUCKET_NAME}/objects/applications/LN-4471")',
            expr,
        )


# ── apply_iam_binding ───────────────────────────────────────────────────────


class TestApplyIamBinding(unittest.TestCase):
    @patch("grant_access_main.storage.Client")
    def test_appends_conditional_binding_and_sets_policy_v3(self, MockClient):
        mock_bucket = MagicMock()
        mock_policy = MagicMock()
        mock_policy.bindings = []
        mock_bucket.get_iam_policy.return_value = mock_policy
        MockClient.return_value.bucket.return_value = mock_bucket

        main.apply_iam_binding("officer@bank.example.com", 'request.time < timestamp("2026-01-01T12:00:00Z")')

        mock_bucket.get_iam_policy.assert_called_once_with(requested_policy_version=3)
        self.assertEqual(mock_policy.version, 3)
        self.assertEqual(len(mock_policy.bindings), 1)

        binding = mock_policy.bindings[0]
        self.assertEqual(binding["role"], "roles/storage.objectViewer")
        self.assertIn("user:officer@bank.example.com", binding["members"])
        self.assertEqual(binding["condition"]["expression"], 'request.time < timestamp("2026-01-01T12:00:00Z")')

        mock_bucket.set_iam_policy.assert_called_once_with(mock_policy)

    @patch("grant_access_main.storage.Client")
    def test_does_not_disturb_existing_bindings(self, MockClient):
        existing_binding = {"role": "roles/storage.admin", "members": {"serviceAccount:sa@test.iam"}}
        mock_bucket = MagicMock()
        mock_policy = MagicMock()
        mock_policy.bindings = [existing_binding]
        mock_bucket.get_iam_policy.return_value = mock_policy
        MockClient.return_value.bucket.return_value = mock_bucket

        main.apply_iam_binding("officer@bank.example.com", "request.time < timestamp(\"2026-01-01T12:00:00Z\")")

        self.assertEqual(len(mock_policy.bindings), 2)
        self.assertIn(existing_binding, mock_policy.bindings)


# ── create_session_secret ───────────────────────────────────────────────────


class TestCreateSessionSecret(unittest.TestCase):
    @patch("grant_access_main.secrets.token_urlsafe", return_value="fake-token")
    @patch("grant_access_main.secretmanager.SecretManagerServiceClient")
    def test_creates_secret_with_expected_id_and_adds_version(self, MockClient, mock_token):
        mock_secret = MagicMock()
        mock_secret.name = "projects/test-project/secrets/bankvault-session-abc123"
        MockClient.return_value.create_secret.return_value = mock_secret

        secret_name = main.create_session_secret("abc123")

        self.assertEqual(secret_name, mock_secret.name)

        create_kwargs = MockClient.return_value.create_secret.call_args.kwargs["request"]
        self.assertEqual(create_kwargs["secret_id"], "bankvault-session-abc123")
        self.assertEqual(create_kwargs["parent"], "projects/test-project")

        add_version_kwargs = MockClient.return_value.add_secret_version.call_args.kwargs["request"]
        self.assertEqual(add_version_kwargs["parent"], mock_secret.name)
        self.assertEqual(add_version_kwargs["payload"]["data"], b"fake-token")


# ── write_audit_row ─────────────────────────────────────────────────────────


class TestWriteAuditRow(unittest.TestCase):
    @patch("grant_access_main.bigquery.Client")
    def test_inserts_row_with_expected_fields(self, MockClient):
        MockClient.return_value.insert_rows_json.return_value = []
        now = datetime.now(timezone.utc)

        main.write_audit_row(
            request_id="req-1",
            action_type="GRANT",
            requested_by="officer@bank.example.com",
            resource="gs://bucket",
            event_timestamp=now,
            approved_by="manager@bank.example.com",
        )

        table_id, rows = MockClient.return_value.insert_rows_json.call_args.args
        self.assertEqual(table_id, main.AUDIT_TABLE_ID)
        self.assertEqual(rows[0]["request_id"], "req-1")
        self.assertEqual(rows[0]["action_type"], "GRANT")
        self.assertEqual(rows[0]["approved_by"], "manager@bank.example.com")
        self.assertIsNone(rows[0]["revoked_at"])

    @patch("grant_access_main.bigquery.Client")
    def test_raises_when_bigquery_reports_errors(self, MockClient):
        MockClient.return_value.insert_rows_json.return_value = [{"index": 0, "errors": ["bad row"]}]
        now = datetime.now(timezone.utc)

        with self.assertRaises(Exception):
            main.write_audit_row(
                request_id="req-1",
                action_type="GRANT",
                requested_by="officer@bank.example.com",
                resource="gs://bucket",
                event_timestamp=now,
            )

    def test_write_audit_row_safe_swallows_failure(self):
        with patch("grant_access_main.write_audit_row", side_effect=main.GoogleAPIError("boom")):
            # Should not raise
            main._write_audit_row_safe(
                request_id="req-1",
                action_type="DENY",
                requested_by="officer@bank.example.com",
                resource="gs://bucket",
                event_timestamp=datetime.now(timezone.utc),
            )


# ── process_grant_request (end-to-end, all clients mocked) ─────────────────


class TestProcessGrantRequest(unittest.TestCase):
    @patch("grant_access_main.write_audit_row")
    @patch("grant_access_main.create_session_secret", return_value="projects/test-project/secrets/bankvault-session-x")
    @patch("grant_access_main.apply_iam_binding")
    def test_valid_request_is_granted(self, mock_apply, mock_secret, mock_audit):
        result = main.process_grant_request(_valid_payload())

        self.assertEqual(result["status"], "GRANTED")
        self.assertEqual(result["requested_by"], "officer@bank.example.com")
        mock_apply.assert_called_once()
        mock_secret.assert_called_once()

        audit_kwargs = mock_audit.call_args.kwargs
        self.assertEqual(audit_kwargs["action_type"], "GRANT")
        self.assertEqual(audit_kwargs["approved_by"], "manager@bank.example.com")

    @patch("grant_access_main.write_audit_row")
    @patch("grant_access_main.create_session_secret")
    @patch("grant_access_main.apply_iam_binding")
    def test_invalid_request_is_denied_and_does_not_touch_iam(self, mock_apply, mock_secret, mock_audit):
        payload = _valid_payload(approved_by="officer@bank.example.com")  # self-approval

        result = main.process_grant_request(payload)

        self.assertEqual(result["status"], "DENIED")
        mock_apply.assert_not_called()
        mock_secret.assert_not_called()

        audit_kwargs = mock_audit.call_args.kwargs
        self.assertEqual(audit_kwargs["action_type"], "DENY")
        self.assertIn("segregation of duties", audit_kwargs["denial_reason"])

    @patch("grant_access_main.write_audit_row")
    @patch("grant_access_main.create_session_secret")
    @patch("grant_access_main.apply_iam_binding")
    def test_granted_window_respects_duration(self, mock_apply, mock_secret, mock_audit):
        result = main.process_grant_request(_valid_payload(duration_minutes=30))

        start = datetime.fromisoformat(result["window_start"])
        end = datetime.fromisoformat(result["window_end"])
        self.assertAlmostEqual((end - start).total_seconds(), timedelta(minutes=30).total_seconds(), delta=2)

    @patch("grant_access_main.write_audit_row")
    @patch("grant_access_main.create_session_secret", return_value="projects/test-project/secrets/bankvault-session-x")
    @patch("grant_access_main.apply_iam_binding")
    def test_loan_application_id_produces_resource_bound_resource_field(self, mock_apply, mock_secret, mock_audit):
        result = main.process_grant_request(_valid_payload(loan_application_id="LN-9001"))
        self.assertIn("LN-9001", result["resource"])
        self.assertIn("&&", result["iam_condition_expression"])


if __name__ == "__main__":
    unittest.main()
