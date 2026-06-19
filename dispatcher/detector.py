"""Detects project stacks and applicable Snyk scan types within a repo clone.

Detection is file-presence based and operates per top-level (and one level
of nested) directory so monorepos with multiple ecosystems fan out into
one unit per project_path rather than one scan of the whole tree.
"""
import os
from dataclasses import dataclass, field

# Marker file -> (snyk job image tag, priority). Every entry uses the same
# shape so detect() doesn't need to branch on type. Priority picks the best
# dependency file when several are present in one directory: lock files (3,
# fully resolved) > manifests (2) > loose requirement files (1).
SCA_MARKERS = {
    # Python lock files (highest priority for dependency resolution)
    "uv.lock": ("python", 3),
    "poetry.lock": ("python", 3),
    "Pipfile.lock": ("python", 3),

    # Python manifest files
    "pyproject.toml": ("python", 2),
    "requirements.txt": ("python", 1),
    "Pipfile": ("python", 1),
    "setup.py": ("python", 1),
    "setup.cfg": ("python", 1),

    # Other ecosystems
    "go.mod": ("golang", 2),
    "package.json": ("node", 2),
    "pom.xml": ("maven", 2),
    "build.gradle": ("gradle", 2),
    "build.gradle.kts": ("gradle", 2),
    "Gemfile": ("ruby", 2),
    "composer.json": ("php", 2),
}

# Dependency files Snyk's CLI can't read directly — the scan job must
# convert them to a supported format before running `snyk test`.
# See scanner/entrypoint.sh.
UNSUPPORTED_BY_SNYK = {"uv.lock"}

CSPROJ_SUFFIXES = (".csproj", ".sln")

IAC_MARKERS_EXT = (".tf",)
IAC_MARKERS_FILES = {"Chart.yaml"}  # Helm chart root

CONTAINER_MARKER = "Dockerfile"

# Directories we never want to descend into or treat as project roots.
IGNORED_DIRS = {".git", "node_modules", "vendor", ".venv", "dist", "build", "target"}

MAX_DEPTH = 2  # repo root + one level of subdirectories


@dataclass
class ProjectUnit:
    project_path: str          # relative to repo root, "" for root
    image_tag: str             # which snyk/snyk:<tag> base image to use
    scan_types: set = field(default_factory=set)  # subset of {sca, sast, iac, container}
    dependency_file: str = ""  # specific dependency file detected for SCA


def _has_csproj(files: list[str]) -> bool:
    return any(f.endswith(CSPROJ_SUFFIXES) for f in files)


def _has_iac(files: list[str]) -> bool:
    if any(f.endswith(IAC_MARKERS_EXT) for f in files):
        return True
    return bool(IAC_MARKERS_FILES & set(files))


def detect(repo_root: str) -> list[ProjectUnit]:
    units: dict[str, ProjectUnit] = {}

    for dirpath, dirnames, filenames in os.walk(repo_root):
        rel = os.path.relpath(dirpath, repo_root)
        rel = "" if rel == "." else rel
        depth = 0 if rel == "" else rel.count(os.sep) + 1

        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        if depth >= MAX_DEPTH:
            dirnames[:] = []

        # Find the best marker based on priority (highest wins; ties keep
        # whichever was found first, which is fine since within a priority
        # tier any match is equally valid for picking the image tag).
        best_marker = None
        best_tag = None
        best_priority = 0

        for marker, (tag, priority) in SCA_MARKERS.items():
            if marker in filenames and priority > best_priority:
                best_marker = marker
                best_tag = tag
                best_priority = priority

        image_tag = best_tag
        
        if image_tag is None and _has_csproj(filenames):
            image_tag = "dotnet"

        if image_tag is not None:
            unit = units.setdefault(rel, ProjectUnit(project_path=rel, image_tag=image_tag, dependency_file=best_marker or ""))
            unit.scan_types.add("sca")
            unit.scan_types.add("sast")

        if CONTAINER_MARKER in filenames:
            unit = units.setdefault(
                rel, ProjectUnit(project_path=rel, image_tag=image_tag or "linux")
            )
            unit.scan_types.add("container")

        if _has_iac(filenames):
            unit = units.setdefault(
                rel, ProjectUnit(project_path=rel, image_tag=image_tag or "linux")
            )
            unit.scan_types.add("iac")

    return list(units.values())
