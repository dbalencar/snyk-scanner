"""Detects project stacks and applicable Snyk scan types within a repo clone.

Detection is file-presence based and operates per top-level (and one level
of nested) directory so monorepos with multiple ecosystems fan out into
one unit per project_path rather than one scan of the whole tree.
"""
import os
from dataclasses import dataclass, field

# Marker file -> (snyk job image tag, ecosystem label)
SCA_MARKERS = {
    "go.mod": "golang",
    "package.json": "node",
    "requirements.txt": "python",
    "Pipfile": "python",
    "pyproject.toml": "python",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "Gemfile": "ruby",
    "composer.json": "php",
}

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

        image_tag = None
        for marker, tag in SCA_MARKERS.items():
            if marker in filenames:
                image_tag = tag
                break
        if image_tag is None and _has_csproj(filenames):
            image_tag = "dotnet"

        if image_tag is not None:
            unit = units.setdefault(rel, ProjectUnit(project_path=rel, image_tag=image_tag))
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
