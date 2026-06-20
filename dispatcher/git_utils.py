import shutil
import tempfile
from urllib.parse import urlparse

import git

from config import Config


class DisallowedGitHostError(Exception):
    pass


def assert_host_allowed(git_url: str) -> None:
    """Raise if git_url's host isn't on the configured allowlist.

    scan.requests messages carry an attacker-influenced URL in some deployments
    (e.g. triggered by a webhook relay); without this check the dispatcher is an
    SSRF primitive that will happily clone http://169.254.169.254/... or any
    internal host reachable from the cluster.
    """
    parsed = urlparse(git_url)
    host = parsed.hostname
    # git@host:org/repo.git scp-style URLs have no scheme; urlparse won't
    # extract a hostname for them, so handle that form explicitly.
    if host is None and "@" in git_url and ":" in git_url:
        host = git_url.split("@", 1)[1].split(":", 1)[0]

    if not host or host not in Config.ALLOWED_GIT_HOSTS:
        raise DisallowedGitHostError(f"git host '{host}' is not in ALLOWED_GIT_HOSTS")


def shallow_clone(git_url: str, ref: str) -> str:
    """Clones git_url at ref into a fresh temp dir, returns its path.

    Caller is responsible for cleaning up the returned directory.
    """
    assert_host_allowed(git_url)

    dest = tempfile.mkdtemp(prefix="scan-clone-")
    try:
        repo = git.Repo.clone_from(
            git_url,
            dest,
            depth=Config.CLONE_DEPTH,
            branch=ref,
            single_branch=True,
        )
        repo.close()
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    return dest


def get_commit_sha(clone_path: str) -> str:
    repo = git.Repo(clone_path)
    sha = repo.head.commit.hexsha
    repo.close()
    return sha


def cleanup(path: str) -> None:
    shutil.rmtree(path, ignore_errors=True)
