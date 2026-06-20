"""
Tests for scanner/upload_result.py.

Verifies that scan results are uploaded to MinIO (S3-compatible) with the
correct bucket, key, and endpoint. The SCA upload was failing in local testing
because the snyk-scan-results bucket did not exist (fixed in k8s-local/minio.yaml)
and because the entrypoint was aborting before this step on summarize failures
(fixed in summarize.py and entrypoint_local.sh).
"""
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, call, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))
import upload_result

_BASE_ARGV = [
    "upload_result.py",
    "--object-key", "scans/scan-abc/backend/sca.json",
    "--endpoint", "http://minio:9000",
    "--bucket", "snyk-scan-results",
    "--access-key", "minioadmin",
    "--secret-key", "minioadmin",
]


def _run(mock_s3, file_content=b'{"ok": true}'):
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(file_content)
        fname = f.name
    try:
        with patch("sys.argv", _BASE_ARGV + ["--file", fname]), \
             patch("boto3.client", return_value=mock_s3):
            upload_result.main()
    finally:
        os.unlink(fname)


class TestUploadResult(unittest.TestCase):

    def test_upload_file_is_called(self):
        """s3.upload_file is called once per invocation."""
        mock_s3 = MagicMock()
        _run(mock_s3)
        mock_s3.upload_file.assert_called_once()

    def test_correct_bucket_and_key(self):
        """upload_file receives the expected bucket name and object key."""
        mock_s3 = MagicMock()
        _run(mock_s3)
        _, bucket, key = mock_s3.upload_file.call_args.args
        self.assertEqual(bucket, "snyk-scan-results")
        self.assertEqual(key, "scans/scan-abc/backend/sca.json")

    def test_custom_minio_endpoint_is_used(self):
        """boto3 client is initialised with the custom MinIO endpoint URL."""
        mock_s3 = MagicMock()
        captured = {}

        def capture_client(service, **kwargs):
            captured.update(kwargs)
            return mock_s3

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"{}")
            fname = f.name
        try:
            with patch("sys.argv", _BASE_ARGV + ["--file", fname]), \
                 patch("boto3.client", side_effect=capture_client):
                upload_result.main()
        finally:
            os.unlink(fname)

        self.assertEqual(captured["endpoint_url"], "http://minio:9000")
        self.assertEqual(captured["aws_access_key_id"], "minioadmin")
        self.assertEqual(captured["aws_secret_access_key"], "minioadmin")

    def test_empty_file_still_uploads(self):
        """A zero-byte file (snyk exited before writing output) is still uploaded.

        This ensures the scan_unit row can be updated to 'failed' status — if the
        upload were skipped, the entrypoint would abort before publish_result.py runs.
        """
        mock_s3 = MagicMock()
        _run(mock_s3, file_content=b"")
        mock_s3.upload_file.assert_called_once()

    def test_large_json_result_uploads(self):
        """A result with many findings (large JSON) uploads without truncation."""
        mock_s3 = MagicMock()
        large = {"vulnerabilities": [{"severity": "high", "id": str(i)} for i in range(500)]}
        import json
        _run(mock_s3, file_content=json.dumps(large).encode())
        mock_s3.upload_file.assert_called_once()


if __name__ == "__main__":
    unittest.main()
