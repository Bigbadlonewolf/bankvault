"""Unit tests for functions/revoke_access/main.py. All GCP clients are
mocked — no network calls, no real project required.
"""

import importlib.util
import os
import sys
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from google.api_core.exceptions import NotFound

os.environ.setdefault("GOOGLE_CLOUD_PROJECT", "test-project")
os.environ.setdefault("PII_BUCKET_NAME", "test-project-loan-origination-pii")
os.environ.setdefault("AUDIT_DATASET", "bankvault_audit")
os.environ.setdefault("AUDIT_TABLE", "access_grants")
os.environ.setdefault("SESSION_SECRET_PREFIX", "bankvault-session-")

# Loaded under a unique module name (not "main") so this file can coexist
# with tests/test_grant_access.py, which imports a different main.py.
_MAIN_PATH = os.path.join(os.path.dirname(__file__), "..", "functions", "revoke_access", "main.py")
_spec = importlib.util.spec_from_file_location("revoke_access_main", _MAIN_PATH)
main = importlib.util.module_from_spec(_spec)
sys.modules["revoke_access_main"] = main
_spec.loader.exec_module(main)


def _grant_row(**overrides) -> dict:
    row = {
        "request_id": "req-1",
        "requested_by": "officer@bank.example.com",
        "resource": "gs://test-project-loan-origination-pii/applications/LN-4471",
        "window_end": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "iam_condition_expression": 'request.time < timestamp("2026-01-01T00:00:00Z")',
        "session_secret_name": "projects/test-project/secrets/bankvault-session-req-1",
    }
    row.update(overrides)
    return row


# ── find_expired_unrevoked_grants ───────────────────────────────────────────


class TestFindExpiredUnrevokedGrants(unittest.TestCase):
    @patch("revoke_access_main.bigquery.Client")
    def test_returns_query_rows_as_dicts(self, MockClient):
        fake_row = _grant_row()
        mock_result = MagicMock()
        mock_result.result.return_value = [fake_row]
        MockClient.return_value.query.return_value = mock_result

        rows = main.find_expired_unrevoked_grants(datetime.now(timezone.utc))

        self.assertEqual(rows, [fake_row])
        MockClient.return_value.query.assert_called_once()
        query_text = MockClient.return_value.query.call_args.args[0]
        self.assertIn("NOT EXISTS", query_text)
        self.assertIn(main.AUDIT_TABLE_ID, query_text)


# ── remove_iam_binding ───────────────────────────────────────────────────────


class TestRemoveIamBinding(unittest.TestCase):
    @patch("revoke_access_main.storage.Client")
    def test_removes_matching_binding_only(self, MockClient):
        matching_condition = 'request.time < timestamp("2026-01-01T00:00:00Z")'
        matching_binding = {
            "role": "roles/storage.objectViewer",
            "members": {"user:officer@bank.example.com"},
            "condition": {"expression": matching_condition},
        }
        other_binding = {
            "role": "roles/storage.admin",
            "members": {"serviceAccount:sa@test.iam"},
        }
        mock_bucket = MagicMock()
        mock_policy = MagicMock()
        mock_policy.bindings = [matching_binding, other_binding]
        mock_bucket.get_iam_policy.return_value = mock_policy
        MockClient.return_value.bucket.return_value = mock_bucket

        removed = main.remove_iam_binding("officer@bank.example.com", matching_condition)

        self.assertTrue(removed)
        self.assertEqual(mock_policy.bindings, [other_binding])
        mock_bucket.set_iam_policy.assert_called_once_with(mock_policy)

    @patch("revoke_access_main.storage.Client")
    def test_returns_false_and_does_not_set_policy_when_no_match(self, MockClient):
        other_binding = {
            "role": "roles/storage.admin",
            "members": {"serviceAccount:sa@test.iam"},
        }
        mock_bucket = MagicMock()
        mock_policy = MagicMock()
        mock_policy.bindings = [other_binding]
        mock_bucket.get_iam_policy.return_value = mock_policy
        MockClient.return_value.bucket.return_value = mock_bucket

        removed = main.remove_iam_binding("officer@bank.example.com", 'request.time < timestamp("2026-01-01T00:00:00Z")')

        self.assertFalse(removed)
        mock_bucket.set_iam_policy.assert_not_called()

    @patch("revoke_access_main.storage.Client")
    def test_condition_mismatch_is_not_removed(self, MockClient):
        # Same user, different (older) grant's condition — must not remove
        # a *different* active grant for the same loan officer.
        other_grant_binding = {
            "role": "roles/storage.objectViewer",
            "members": {"user:officer@bank.example.com"},
            "condition": {"expression": 'request.time < timestamp("2099-01-01T00:00:00Z")'},
        }
        mock_bucket = MagicMock()
        mock_policy = MagicMock()
        mock_policy.bindings = [other_grant_binding]
        mock_bucket.get_iam_policy.return_value = mock_policy
        MockClient.return_value.bucket.return_value = mock_bucket

        removed = main.remove_iam_binding("officer@bank.example.com", 'request.time < timestamp("2026-01-01T00:00:00Z")')

        self.assertFalse(removed)
        self.assertEqual(mock_policy.bindings, [other_grant_binding])


# ── delete_session_secret ───────────────────────────────────────────────────


class TestDeleteSessionSecret(unittest.TestCase):
    @patch("revoke_access_main.secretmanager.SecretManagerServiceClient")
    def test_deletes_secret(self, MockClient):
        main.delete_session_secret("projects/test-project/secrets/bankvault-session-req-1")
        MockClient.return_value.delete_secret.assert_called_once_with(
            request={"name": "projects/test-project/secrets/bankvault-session-req-1"}
        )

    @patch("revoke_access_main.secretmanager.SecretManagerServiceClient")
    def test_already_deleted_secret_does_not_raise(self, MockClient):
        MockClient.return_value.delete_secret.side_effect = NotFound("gone")
        # Should not raise
        main.delete_session_secret("projects/test-project/secrets/bankvault-session-req-1")


# ── write_revoke_row ─────────────────────────────────────────────────────────


class TestWriteRevokeRow(unittest.TestCase):
    @patch("revoke_access_main.bigquery.Client")
    def test_inserts_revoke_row(self, MockClient):
        MockClient.return_value.insert_rows_json.return_value = []
        now = datetime.now(timezone.utc)

        main.write_revoke_row(
            request_id="req-1",
            requested_by="officer@bank.example.com",
            resource="gs://bucket/applications/LN-4471",
            revoked_at=now,
            event_timestamp=now,
        )

        table_id, rows = MockClient.return_value.insert_rows_json.call_args.args
        self.assertEqual(table_id, main.AUDIT_TABLE_ID)
        self.assertEqual(rows[0]["action_type"], "REVOKE")
        self.assertEqual(rows[0]["request_id"], "req-1")
        self.assertIsNotNone(rows[0]["revoked_at"])

    @patch("revoke_access_main.bigquery.Client")
    def test_raises_when_bigquery_reports_errors(self, MockClient):
        MockClient.return_value.insert_rows_json.return_value = [{"index": 0, "errors": ["bad row"]}]
        now = datetime.now(timezone.utc)

        with self.assertRaises(Exception):
            main.write_revoke_row(
                request_id="req-1",
                requested_by="officer@bank.example.com",
                resource="gs://bucket",
                revoked_at=now,
                event_timestamp=now,
            )


# ── revoke_grant (orchestration, all clients mocked) ────────────────────────


class TestRevokeGrant(unittest.TestCase):
    @patch("revoke_access_main.write_revoke_row")
    @patch("revoke_access_main.delete_session_secret")
    @patch("revoke_access_main.remove_iam_binding", return_value=True)
    def test_happy_path_calls_everything(self, mock_remove, mock_delete_secret, mock_write_revoke):
        now = datetime.now(timezone.utc)
        main.revoke_grant(_grant_row(), now)

        mock_remove.assert_called_once_with("officer@bank.example.com", _grant_row()["iam_condition_expression"])
        mock_delete_secret.assert_called_once_with(_grant_row()["session_secret_name"])
        mock_write_revoke.assert_called_once()
        self.assertEqual(mock_write_revoke.call_args.kwargs["request_id"], "req-1")

    @patch("revoke_access_main.write_revoke_row")
    @patch("revoke_access_main.delete_session_secret")
    @patch("revoke_access_main.remove_iam_binding", return_value=False)
    def test_missing_binding_still_writes_revoke_row(self, mock_remove, mock_delete_secret, mock_write_revoke):
        # Idempotency: if the binding is already gone, the sweep still
        # closes out the ledger row rather than getting stuck retrying.
        now = datetime.now(timezone.utc)
        main.revoke_grant(_grant_row(), now)
        mock_write_revoke.assert_called_once()

    @patch("revoke_access_main.write_revoke_row")
    @patch("revoke_access_main.delete_session_secret")
    @patch("revoke_access_main.remove_iam_binding", return_value=True)
    def test_no_secret_name_skips_secret_deletion(self, mock_remove, mock_delete_secret, mock_write_revoke):
        now = datetime.now(timezone.utc)
        main.revoke_grant(_grant_row(session_secret_name=None), now)
        mock_delete_secret.assert_not_called()
        mock_write_revoke.assert_called_once()


# ── revoke_access (Pub/Sub entrypoint) ──────────────────────────────────────


class TestRevokeAccessEntrypoint(unittest.TestCase):
    @patch("revoke_access_main.revoke_grant")
    @patch("revoke_access_main.find_expired_unrevoked_grants")
    def test_sweeps_all_expired_grants(self, mock_find, mock_revoke_grant):
        mock_find.return_value = [_grant_row(request_id="req-1"), _grant_row(request_id="req-2")]

        fake_event = MagicMock()
        main.revoke_access(fake_event)

        self.assertEqual(mock_revoke_grant.call_count, 2)

    @patch("revoke_access_main.revoke_grant")
    @patch("revoke_access_main.find_expired_unrevoked_grants", return_value=[])
    def test_no_expired_grants_is_a_noop(self, mock_find, mock_revoke_grant):
        fake_event = MagicMock()
        main.revoke_access(fake_event)
        mock_revoke_grant.assert_not_called()


if __name__ == "__main__":
    unittest.main()
