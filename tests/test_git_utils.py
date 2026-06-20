"""
Tests for dispatcher/git_utils.py URL helpers.

Covers the SSH→HTTPS conversion and token injection that enable private repo
cloning without SSH keys in the scan-job Pod.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dispatcher"))

# Stub Config so git_utils can be imported without real env vars
import types
config_stub = types.ModuleType("config")
config_stub.Config = type("Config", (), {"GIT_TOKEN": "", "CLONE_DEPTH": 1,
                                         "CLONE_TIMEOUT_SECONDS": 60,
                                         "ALLOWED_GIT_HOSTS": []})()
sys.modules.setdefault("config", config_stub)

from git_utils import ssh_to_https, _inject_token


class TestSshToHttps(unittest.TestCase):

    def test_converts_scp_style_url(self):
        result = ssh_to_https("git@gitlab.dell.com:devsecops/ai-soc/appsec-ai-harness.git")
        self.assertEqual(result, "https://gitlab.dell.com/devsecops/ai-soc/appsec-ai-harness.git")

    def test_converts_github_scp_url(self):
        result = ssh_to_https("git@github.com:octocat/Hello-World.git")
        self.assertEqual(result, "https://github.com/octocat/Hello-World.git")

    def test_noop_for_https(self):
        url = "https://github.com/octocat/Hello-World.git"
        self.assertEqual(ssh_to_https(url), url)

    def test_noop_for_file_url(self):
        url = "file:///tmp/local-repo"
        self.assertEqual(ssh_to_https(url), url)

    def test_noop_for_http(self):
        url = "http://internal.host/org/repo.git"
        self.assertEqual(ssh_to_https(url), url)


class TestInjectToken(unittest.TestCase):

    def test_injects_oauth2_token(self):
        url = "https://gitlab.dell.com/org/repo.git"
        result = _inject_token(url, "glpat-abc123")
        self.assertEqual(result, "https://oauth2:glpat-abc123@gitlab.dell.com/org/repo.git")

    def test_noop_when_token_empty(self):
        url = "https://gitlab.dell.com/org/repo.git"
        self.assertEqual(_inject_token(url, ""), url)

    def test_noop_when_already_has_credentials(self):
        url = "https://oauth2:existing@gitlab.dell.com/org/repo.git"
        self.assertEqual(_inject_token(url, "newtoken"), url)

    def test_noop_for_non_https(self):
        url = "file:///tmp/repo"
        self.assertEqual(_inject_token(url, "token"), url)

    def test_preserves_port(self):
        url = "https://gitlab.internal:8443/org/repo.git"
        result = _inject_token(url, "tok")
        self.assertIn(":8443", result)
        self.assertIn("oauth2:tok@", result)

    def test_scp_converted_then_token_injected(self):
        """The two helpers compose: convert SSH then inject token."""
        url = ssh_to_https("git@gitlab.dell.com:org/repo.git")
        result = _inject_token(url, "mytoken")
        self.assertEqual(result, "https://oauth2:mytoken@gitlab.dell.com/org/repo.git")


class TestBuildJobWiresGitToken(unittest.TestCase):
    """Verify build_job passes GIT_TOKEN to the Pod so the entrypoint can use it."""

    def setUp(self):
        os.environ.setdefault("K8S_NAMESPACE", "default")
        os.environ.setdefault("JOB_IMAGE_PREFIX", "localhost/snyk-scan-job")
        os.environ.setdefault("JOB_TTL_SECONDS_AFTER_FINISHED", "3600")
        os.environ.setdefault("JOB_BACKOFF_LIMIT", "1")
        os.environ.setdefault("JOB_ACTIVE_DEADLINE_SECONDS", "1800")
        os.environ["GIT_TOKEN"] = "test-token-xyz"

    def test_git_token_env_var_in_pod(self):
        # reload config so it picks up the env var we just set
        import importlib
        import config as cfg_mod
        importlib.reload(cfg_mod)
        import k8s_jobs_local
        importlib.reload(k8s_jobs_local)

        job = k8s_jobs_local.build_job(
            scan_id="test-scan",
            git_url="https://gitlab.dell.com/org/repo.git",
            ref="main",
            image_tag="python",
            project_path="",
            scan_types=["sca"],
        )
        container = job.spec.template.spec.containers[0]
        env_names = {e.name: e.value for e in container.env}
        self.assertIn("GIT_TOKEN", env_names)
        self.assertEqual(env_names["GIT_TOKEN"], "test-token-xyz")


if __name__ == "__main__":
    unittest.main()
