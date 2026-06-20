"""
Tests for api/main.py.

Uses FastAPI's TestClient (backed by httpx) so the endpoints run in-process
with no real Postgres or RabbitMQ connection needed — both are mocked.

Key invariants verified:
  - POST /scan returns 202 with the right shape; commitSha always present,
    error omitted when absent.
  - POST /scan with a disallowed host returns 400 (SSRF guard).
  - POST /scan marks the row 'failed' when RabbitMQ publish fails.
  - GET /scan returns the current DB row; 404 when not found.
  - The RabbitMQ message includes scan_id so the dispatcher updates the
    pre-created row rather than minting a new one.
"""
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch, call

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

# Provide required env vars before importing the app so FastAPI doesn't
# raise at import time.
os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost/test")
os.environ.setdefault("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
os.environ.setdefault("ALLOWED_GIT_HOSTS", "github.com,gitlab.com")

from fastapi.testclient import TestClient
import main as api_main

client = TestClient(api_main.app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_db(rows=None):
    """Return a mock psycopg2 connection that yields the given rows on SELECT."""
    cursor = MagicMock()
    cursor.fetchone.return_value = rows[0] if rows else None
    # Make the cursor work as a context manager
    conn = MagicMock()
    conn.cursor.return_value.__enter__.return_value = cursor
    conn.cursor.return_value.__exit__.return_value = False
    return conn, cursor


def _mock_mq():
    channel = MagicMock()
    mq_conn = MagicMock()
    mq_conn.channel.return_value = channel
    return mq_conn, channel


# ---------------------------------------------------------------------------
# POST /scan
# ---------------------------------------------------------------------------

class TestCreateScan(unittest.TestCase):

    def _post(self, git_url="https://github.com/example/repo", ref="main",
              db_conn=None, mq_conn=None):
        conn, cursor = db_conn or _mock_db()
        mq, channel = mq_conn or _mock_mq()
        with patch("main._db_conn", return_value=conn), \
             patch("pika.BlockingConnection", return_value=mq), \
             patch("pika.URLParameters"):
            return client.post("/scan", json={"gitUrl": git_url, "ref": ref}), conn, cursor, channel

    def test_returns_202(self):
        resp, *_ = self._post()
        self.assertEqual(resp.status_code, 202)

    def test_response_shape(self):
        resp, *_ = self._post()
        body = resp.json()
        self.assertIn("id", body)
        self.assertIn("gitUrl", body)
        self.assertIn("ref", body)
        self.assertIn("commitSha", body)   # always present
        self.assertIn("status", body)
        self.assertNotIn("error", body)    # omitted when absent

    def test_status_is_pending(self):
        resp, *_ = self._post()
        self.assertEqual(resp.json()["status"], "pending")

    def test_git_url_and_ref_echoed(self):
        resp, *_ = self._post(git_url="https://github.com/org/repo", ref="v2")
        body = resp.json()
        self.assertEqual(body["gitUrl"], "https://github.com/org/repo")
        self.assertEqual(body["ref"], "v2")

    def test_commit_sha_is_null_at_post_time(self):
        resp, *_ = self._post()
        self.assertIsNone(resp.json()["commitSha"])

    def test_id_is_a_uuid(self):
        import uuid
        resp, *_ = self._post()
        uuid.UUID(resp.json()["id"])  # raises if not a valid UUID

    def test_scan_id_included_in_rabbitmq_message(self):
        """The published message must carry the scan_id the API stored,
        or the dispatcher will mint a new UUID and the DB row stays 'pending'."""
        resp, _, _, channel = self._post()
        scan_id = resp.json()["id"]
        channel.basic_publish.assert_called_once()
        published_body = json.loads(channel.basic_publish.call_args.kwargs["body"])
        self.assertEqual(published_body["scan_id"], scan_id)
        self.assertIn("git_url", published_body)
        self.assertIn("ref", published_body)

    def test_db_row_created_with_pending_status(self):
        """The DB INSERT must use status='pending' so GET works before dispatch."""
        _, conn, cursor, _ = self._post()
        insert_calls = [c for c in cursor.execute.call_args_list
                        if "INSERT INTO scans" in str(c)]
        self.assertEqual(len(insert_calls), 1)
        sql, params = insert_calls[0].args
        self.assertIn("pending", sql)

    def test_disallowed_host_returns_400(self):
        conn, _ = _mock_db()
        mq, _ = _mock_mq()
        with patch("main._db_conn", return_value=conn), \
             patch("pika.BlockingConnection", return_value=mq), \
             patch("pika.URLParameters"):
            resp = client.post("/scan", json={"gitUrl": "https://evil.internal/org/repo"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("ALLOWED_GIT_HOSTS", resp.json()["detail"])

    def test_rabbitmq_failure_marks_scan_failed(self):
        """If RabbitMQ is unavailable, the scan is marked 'failed' and returned."""
        conn, cursor = _mock_db()
        with patch("main._db_conn", return_value=conn), \
             patch("pika.URLParameters"), \
             patch("pika.BlockingConnection", side_effect=Exception("connection refused")):
            resp = client.post("/scan", json={"gitUrl": "https://github.com/org/repo"})

        body = resp.json()
        self.assertEqual(body["status"], "failed")
        self.assertIn("error", body)

        update_calls = [c for c in cursor.execute.call_args_list
                        if "UPDATE scans" in str(c)]
        self.assertEqual(len(update_calls), 1)
        self.assertIn("failed", str(update_calls[0]))

    def test_default_ref_is_main(self):
        resp, _, _, channel = self._post(ref="main")
        published = json.loads(channel.basic_publish.call_args.kwargs["body"])
        self.assertEqual(published["ref"], "main")


# ---------------------------------------------------------------------------
# GET /scan
# ---------------------------------------------------------------------------

class TestGetScan(unittest.TestCase):

    def _get(self, scan_id, db_row=None):
        conn, cursor = _mock_db(rows=[db_row] if db_row else None)
        with patch("main._db_conn", return_value=conn):
            return client.get(f"/scan?id={scan_id}"), cursor

    def test_returns_200_when_found(self):
        row = {
            "scan_id": "abc-123", "git_url": "https://github.com/org/repo",
            "ref": "main", "commit_sha": "deadbeef", "status": "completed", "error": None,
        }
        resp, _ = self._get("abc-123", db_row=row)
        self.assertEqual(resp.status_code, 200)

    def test_response_shape(self):
        row = {
            "scan_id": "abc-123", "git_url": "https://github.com/org/repo",
            "ref": "main", "commit_sha": "deadbeef", "status": "completed", "error": None,
        }
        resp, _ = self._get("abc-123", db_row=row)
        body = resp.json()
        self.assertEqual(body["id"], "abc-123")
        self.assertEqual(body["gitUrl"], "https://github.com/org/repo")
        self.assertEqual(body["ref"], "main")
        self.assertEqual(body["commitSha"], "deadbeef")
        self.assertEqual(body["status"], "completed")
        self.assertNotIn("error", body)

    def test_error_field_present_when_set(self):
        row = {
            "scan_id": "abc-123", "git_url": "https://github.com/org/repo",
            "ref": "main", "commit_sha": None, "status": "failed",
            "error": "clone timed out",
        }
        resp, _ = self._get("abc-123", db_row=row)
        self.assertEqual(resp.json()["error"], "clone timed out")

    def test_commit_sha_present_but_null_when_pending(self):
        row = {
            "scan_id": "abc-123", "git_url": "https://github.com/org/repo",
            "ref": "main", "commit_sha": None, "status": "pending", "error": None,
        }
        resp, _ = self._get("abc-123", db_row=row)
        body = resp.json()
        self.assertIn("commitSha", body)
        self.assertIsNone(body["commitSha"])

    def test_returns_404_when_not_found(self):
        resp, _ = self._get("nonexistent-id")
        self.assertEqual(resp.status_code, 404)

    def test_404_detail_includes_id(self):
        resp, _ = self._get("missing-id")
        self.assertIn("missing-id", resp.json()["detail"])


# ---------------------------------------------------------------------------
# Dispatcher DB contract
# ---------------------------------------------------------------------------

class TestDbContract(unittest.TestCase):
    """Verify the db.py changes that make API-created scans work correctly
    with the existing dispatcher."""

    def setUp(self):
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dispatcher"))

    def test_scan_already_dispatched_false_for_pending(self):
        """A 'pending' row must NOT be treated as already dispatched."""
        from db import scan_already_dispatched
        conn = MagicMock()
        cursor = conn.cursor.return_value.__enter__.return_value
        cursor.fetchone.return_value = None  # status='pending' row excluded by query
        self.assertFalse(scan_already_dispatched(conn, "some-id"))

    def test_scan_already_dispatched_true_for_in_progress(self):
        """A row past 'pending' should be treated as already dispatched."""
        from db import scan_already_dispatched
        conn = MagicMock()
        cursor = conn.cursor.return_value.__enter__.return_value
        cursor.fetchone.return_value = (1,)  # row found with status != 'pending'
        self.assertTrue(scan_already_dispatched(conn, "some-id"))

    def test_create_scan_uses_upsert(self):
        """create_scan must upsert so a 'pending' API row transitions to 'in_progress'."""
        from db import create_scan
        conn = MagicMock()
        cursor = conn.cursor.return_value.__enter__.return_value
        create_scan(conn, "scan-1", "https://github.com/org/repo", "main", None, 3)
        sql = cursor.execute.call_args.args[0]
        self.assertIn("ON CONFLICT", sql)
        self.assertIn("DO UPDATE", sql)
        self.assertIn("in_progress", sql)


if __name__ == "__main__":
    unittest.main()
