"""
Tests for scanner/publish_result.py.

Covers the chain of failures that prevented SCA results from being recorded:
  1. json.loads(args.summary) must not raise for any valid summary string.
  2. The scan_units DB row must be updated regardless of whether this is the
     last unit finishing.
  3. A scan.results RabbitMQ message must be published after every unit.

The root cause was that summarize.py was crashing (AttributeError on list JSON),
causing the entrypoint to abort before publish_result.py was ever called. These
tests verify that when publish_result.py IS called, it handles its inputs correctly.
"""
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))
import publish_result

_ENV = {
    "DATABASE_URL": "postgresql://test:test@localhost/test",
    "RABBITMQ_URL": "amqp://guest:guest@localhost:5672/",
}

_BASE_ARGV = [
    "publish_result.py",
    "--scan-id", "scan-abc-123",
    "--project-path", "backend",
    "--scan-type", "sca",
    "--status", "completed",
    "--object-key", "scans/scan-abc-123/backend/sca.json",
    "--cli-version", "1.1290.2",
]


def _make_conn(completed_units=1, expected_units=2, vuln_rows=None, git_info=None):
    """Build a mock psycopg2 connection whose cursor returns canned DB responses."""
    cursor = MagicMock()
    # fetchone() is called once (UPDATE scans RETURNING) or twice (+ SELECT git_url)
    # depending on whether this unit is the last. Side-effect list handles both.
    cursor.fetchone.side_effect = [
        (completed_units, expected_units),
        git_info or ("https://github.com/example/repo", "main"),
    ]
    cursor.fetchall.return_value = vuln_rows or []

    conn = MagicMock()
    conn.cursor.return_value.__enter__.return_value = cursor
    conn.cursor.return_value.__exit__.return_value = False
    return conn, cursor


def _run(argv_extra, conn, summary_str="{}"):
    """Invoke publish_result.main() with the given --summary and mocked deps."""
    argv = _BASE_ARGV + ["--summary", summary_str] + argv_extra
    channel = MagicMock()
    pika_conn = MagicMock()
    pika_conn.channel.return_value = channel

    with patch("sys.argv", argv), \
         patch.dict(os.environ, _ENV), \
         patch("psycopg2.connect", return_value=conn), \
         patch("pika.URLParameters"), \
         patch("pika.BlockingConnection", return_value=pika_conn):
        publish_result.main()

    return channel


class TestSummaryParsing(unittest.TestCase):
    """json.loads(args.summary) must succeed for all summary strings the
    shell can produce — including the '{}' fallback from ${4:-{}}."""

    def _assert_no_json_error(self, summary_str):
        conn, _ = _make_conn()
        _run([], conn, summary_str)  # raises if json.loads fails

    def test_valid_severity_counts(self):
        self._assert_no_json_error(
            json.dumps({"critical": 0, "high": 2, "medium": 1, "low": 0})
        )

    def test_empty_object_shell_fallback(self):
        """'{}' is what ${4:-{}} produces when SUMMARY is empty."""
        self._assert_no_json_error("{}")

    def test_all_zero_counts(self):
        """All-zero summary from summarize.py's fallback path must parse cleanly."""
        self._assert_no_json_error(
            json.dumps({"critical": 0, "high": 0, "medium": 0, "low": 0})
        )


class TestDatabaseUpdate(unittest.TestCase):
    """The scan_units row must be updated in the DB after every unit finishes."""

    def test_scan_unit_status_updated(self):
        conn, cursor = _make_conn(completed_units=1, expected_units=3)
        summary = json.dumps({"critical": 0, "high": 1, "medium": 0, "low": 0})
        _run([], conn, summary)

        update_calls = [
            c for c in cursor.execute.call_args_list
            if "UPDATE scan_units" in str(c)
        ]
        self.assertEqual(len(update_calls), 1, "expected exactly one UPDATE scan_units")
        params = update_calls[0].args[1]
        self.assertEqual(params[0], "completed")       # status
        self.assertEqual(params[5], "scan-abc-123")    # scan_id
        self.assertEqual(params[6], "backend")         # project_path
        self.assertEqual(params[7], "sca")             # scan_type

    def test_vuln_summary_stored_as_json(self):
        """The summary dict is serialised to JSON before being written to the DB."""
        conn, cursor = _make_conn()
        summary = json.dumps({"critical": 0, "high": 3, "medium": 0, "low": 1})
        _run([], conn, summary)

        update_calls = [
            c for c in cursor.execute.call_args_list
            if "UPDATE scan_units" in str(c)
        ]
        params = update_calls[0].args[1]
        stored = json.loads(params[2])  # vuln_summary column value
        self.assertEqual(stored["high"], 3)
        self.assertEqual(stored["low"], 1)

    def test_failed_status_is_written(self):
        """A failed scan unit still updates the DB so the scan doesn't get stuck."""
        conn, cursor = _make_conn()
        _run(["--status", "failed"], conn)

        update_calls = [
            c for c in cursor.execute.call_args_list
            if "UPDATE scan_units" in str(c)
        ]
        self.assertEqual(len(update_calls), 1)
        params = update_calls[0].args[1]
        self.assertEqual(params[0], "failed")


class TestRabbitMQPublish(unittest.TestCase):
    """A scan.results message must be published after each unit, and a
    scan.completed message once after the last unit."""

    def test_result_message_published(self):
        conn, _ = _make_conn(completed_units=1, expected_units=2)
        channel = _run([], conn)

        channel.basic_publish.assert_called()
        first_body = json.loads(channel.basic_publish.call_args_list[0].kwargs["body"])
        self.assertEqual(first_body["scan_id"], "scan-abc-123")
        self.assertEqual(first_body["scan_type"], "sca")
        self.assertEqual(first_body["status"], "completed")

    def test_completed_message_published_for_last_unit(self):
        """scan.completed is published when completed_units == expected_units."""
        conn, cursor = _make_conn(
            completed_units=2,
            expected_units=2,
            vuln_rows=[("sca", {"critical": 0, "high": 1, "medium": 0, "low": 0})],
            git_info=("https://github.com/example/repo", "main"),
        )
        channel = _run([], conn)

        bodies = [json.loads(c.kwargs["body"]) for c in channel.basic_publish.call_args_list]
        completion_msgs = [b for b in bodies if b.get("event") == "scan.completed"]
        self.assertEqual(len(completion_msgs), 1)
        self.assertEqual(completion_msgs[0]["scan_id"], "scan-abc-123")

    def test_no_completed_message_for_non_last_unit(self):
        """scan.completed is NOT published when other units are still in progress."""
        conn, _ = _make_conn(completed_units=1, expected_units=3)
        channel = _run([], conn)

        bodies = [json.loads(c.kwargs["body"]) for c in channel.basic_publish.call_args_list]
        completion_msgs = [b for b in bodies if b.get("event") == "scan.completed"]
        self.assertEqual(len(completion_msgs), 0)


if __name__ == "__main__":
    unittest.main()
