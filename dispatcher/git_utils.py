import shutil
import tempfile
from urllib.parse import urlparse, urlunparse

import git

from config import Config


class DisallowedGitHostError(Exception):
    pass


def ssh_to_https(git_url: str) -> str:
    """Convert scp-style SSH URL to HTTPS. No-op for already-HTTPS or file:// URLs."""
    if git_url.startswith("git@"):
        rest = git_url[4:]  # strip "git@"
        host, path = rest.split(":", 1)
        return f"https://{host}/{path}"
    return git_url


def _inject_token(git_url: str, token: str) -> str:
    """Return the URL with an oauth2 token prepended to the netloc.

    No-op when token is empty, the URL is not HTTPS, or credentials are already present.
    The token-bearing URL must not be logged or stored — use only at clone time.
    """
    if not token or not git_url.startswith("https://"):
        return git_url
    parsed = urlparse(git_url)
    if parsed.username:
        return git_url  # already has credentials
    netloc = f"oauth2:{token}@{parsed.hostname}"
    if parsed.port:
        netloc += f":{parsed.port}"
    return urlunparse(parsed._replace(netloc=netloc))


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
    clone_url = _inject_token(git_url, Config.GIT_TOKEN)

    dest = tempfile.mkdtemp(prefix="scan-clone-")
    try:
        repo = git.Repo.clone_from(
            clone_url,
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
