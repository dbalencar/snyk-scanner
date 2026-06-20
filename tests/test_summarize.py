"""
Tests for scanner/summarize.py.

Covers the bug where snyk test --json returns a JSON array instead of an object
when multiple projects are detected in one directory. Previously this caused:

    AttributeError: 'list' object has no attribute 'get'

in summarize_sca_or_iac(), which was not caught by the narrow except clause,
causing the summarize step to fail silently and the downstream publish_result.py
to receive an empty summary string.
"""
import json
import os
import sys
import tempfile
import unittest
from io import StringIO
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))
from summarize import SEVERITIES, main, summarize_sca_or_iac, summarize_sast

ZERO = {s: 0 for s in SEVERITIES}


class TestSummarizeSCAOrIAC(unittest.TestCase):
    """Unit tests for summarize_sca_or_iac()."""

    def test_standard_object_output(self):
        """Standard snyk test --json output is a JSON object."""
        data = {
            "vulnerabilities": [
                {"severity": "critical"},
                {"severity": "high"},
                {"severity": "high"},
                {"severity": "medium"},
            ]
        }
        result = summarize_sca_or_iac(data)
        self.assertEqual(result, {"critical": 1, "high": 2, "medium": 1, "low": 0})

    def test_list_multi_project_output(self):
        """snyk test --json returns an array when multiple projects are detected.

        Previously raised: AttributeError: 'list' object has no attribute 'get'
        The fix normalises data to a list of items before iterating.
        """
        data = [
            {"vulnerabilities": [{"severity": "high"}, {"severity": "low"}]},
            {"vulnerabilities": [{"severity": "critical"}]},
        ]
        result = summarize_sca_or_iac(data)
        self.assertEqual(result, {"critical": 1, "high": 1, "medium": 0, "low": 1})

    def test_empty_list_returns_zeros(self):
        result = summarize_sca_or_iac([])
        self.assertEqual(result, ZERO)

    def test_no_vulnerabilities_key_returns_zeros(self):
        result = summarize_sca_or_iac({"ok": True, "dependencyCount": 42})
        self.assertEqual(result, ZERO)

    def test_unknown_severity_is_ignored(self):
        data = {"vulnerabilities": [{"severity": "informational"}, {"severity": "high"}]}
        result = summarize_sca_or_iac(data)
        self.assertEqual(result["high"], 1)
        self.assertEqual(sum(result.values()), 1)

    def test_list_with_missing_vulnerabilities_key(self):
        """Items in the array that lack a 'vulnerabilities' key don't crash."""
        data = [{"ok": True}, {"vulnerabilities": [{"severity": "medium"}]}]
        result = summarize_sca_or_iac(data)
        self.assertEqual(result["medium"], 1)


class TestSummarizeSAST(unittest.TestCase):
    """Unit tests for summarize_sast() (SARIF format)."""

    def test_sarif_level_mapping(self):
        data = {
            "runs": [{
                "results": [
                    {"level": "error"},
                    {"level": "warning"},
                    {"level": "warning"},
                    {"level": "note"},
                ]
            }]
        }
        result = summarize_sast(data)
        self.assertEqual(result, {"critical": 0, "high": 1, "medium": 2, "low": 1})

    def test_empty_sarif_returns_zeros(self):
        self.assertEqual(summarize_sast({}), ZERO)

    def test_unknown_level_is_ignored(self):
        data = {"runs": [{"results": [{"level": "none"}]}]}
        self.assertEqual(summarize_sast(data), ZERO)


class TestMainFallback(unittest.TestCase):
    """Integration tests for main() — verify the fallback path when snyk output
    is empty, non-JSON, or otherwise unreadable."""

    def _run_main(self, file_content, scan_type="sca"):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(file_content)
            fname = f.name
        try:
            with patch("sys.argv", ["summarize.py", "--file", fname, "--scan-type", scan_type]), \
                 patch("sys.stdout", new_callable=StringIO) as mock_out:
                main()
                return json.loads(mock_out.getvalue())
        finally:
            os.unlink(fname)

    def test_empty_file_returns_zero_counts(self):
        """Empty OUT_FILE (snyk produced no output) falls back to all zeros."""
        self.assertEqual(self._run_main(""), ZERO)

    def test_non_json_error_text_returns_zero_counts(self):
        """Snyk auth-error text (not JSON) falls back to all zeros."""
        self.assertEqual(
            self._run_main("Error: unable to authenticate, please run `snyk auth`"),
            ZERO,
        )

    def test_valid_sca_object_produces_counts(self):
        data = {"vulnerabilities": [{"severity": "high"}, {"severity": "medium"}]}
        result = self._run_main(json.dumps(data), "sca")
        self.assertEqual(result["high"], 1)
        self.assertEqual(result["medium"], 1)

    def test_list_json_aggregates_without_error(self):
        """List JSON (multi-project) is aggregated cleanly via main()."""
        data = [
            {"vulnerabilities": [{"severity": "critical"}]},
            {"vulnerabilities": [{"severity": "high"}]},
        ]
        result = self._run_main(json.dumps(data), "sca")
        self.assertEqual(result["critical"], 1)
        self.assertEqual(result["high"], 1)

    def test_output_is_always_valid_json(self):
        """main() always writes valid JSON to stdout — no matter what the input is."""
        for content in ["", "{}", "not json", "null", "[]"]:
            with self.subTest(content=content):
                result = self._run_main(content)
                self.assertIsInstance(result, dict)
                self.assertTrue(all(k in result for k in SEVERITIES))


if __name__ == "__main__":
    unittest.main()
