"""Immutable build and traffic-process identity for operator diagnostics."""

from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.resources
import json
import os
import re
import stat
import subprocess
import sys
import threading
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

BUILD_METADATA_RESOURCE = "_build_identity.json"
DEV_MODE_ENV = "SAFEYOLO_DEV_MODE"
DEV_SOURCE_ROOTS_ENV = "SAFEYOLO_DEV_SOURCE_ROOTS"

_RUNTIME_IDENTITY: RuntimeIdentity | None = None
_IDENTITY_LOCK = threading.Lock()

_ROOT_LABEL = re.compile(r"^[a-z][a-z0-9_-]*$")
_IMMUTABLE_REVISION = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_RELEVANT_SUFFIXES = frozenset({".py", ".pyi", ".yaml", ".yml", ".toml", ".j2"})
_EXCLUDED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "htmlcov",
        "node_modules",
    }
)


class EvidenceState(StrEnum):
    """Whether a claimed identity field is backed by usable evidence."""

    KNOWN = "known"
    UNKNOWN = "unknown"


class IdentityProvenance(StrEnum):
    """Where the source revision claim came from."""

    BUILD_ENVIRONMENT = "build-environment"
    BUILD_CHECKOUT = "build-checkout"
    DEV_CHECKOUT = "dev-checkout"
    UNKNOWN = "unknown"


class RuntimeMode(StrEnum):
    PRODUCTION = "production"
    DEV = "dev"


class WorkingTreeState(StrEnum):
    CLEAN = "clean"
    DIRTY = "dirty"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class BuildIdentity:
    """Package/build identity, immutable for a running process."""

    package_version: str
    source_revision: str | None
    build_identifier: str | None
    provenance: IdentityProvenance
    state: EvidenceState


@dataclass(frozen=True)
class SourceFingerprint:
    """Content identity for the selected SafeYolo/PDP source roots."""

    state: EvidenceState
    digest: str | None
    file_count: int
    error: str | None = None


@dataclass(frozen=True)
class DevSourceIdentity:
    """Checkout and content evidence captured for an explicit dev run."""

    roots: dict[str, str]
    revision: str | None
    revision_state: EvidenceState
    working_tree: WorkingTreeState
    fingerprint: SourceFingerprint


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    started_at: str
    start_token: str | None
    start_token_state: EvidenceState


@dataclass(frozen=True)
class RuntimeIdentity:
    """The identity snapshot bound to one traffic process generation."""

    schema_version: int
    mode: RuntimeMode
    build: BuildIdentity
    process: ProcessIdentity
    source: DevSourceIdentity | None

    def to_dict(self) -> dict:
        return asdict(self)


def _installed_package_version() -> str:
    try:
        return importlib.metadata.version("safeyolo")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def load_stamped_build_identity() -> BuildIdentity:
    """Read wheel-time metadata without consulting git or a source checkout."""
    package_version = _installed_package_version()
    try:
        resource = importlib.resources.files("safeyolo").joinpath(BUILD_METADATA_RESOURCE)
        raw = json.loads(resource.read_text(encoding="utf-8"))
        if raw.get("schema_version") != 1:
            raise ValueError("unsupported build identity schema")
        stamped_version = raw.get("package_version")
        revision = raw.get("source_revision")
        build_identifier = raw.get("build_identifier")
        provenance = IdentityProvenance(raw.get("provenance", "unknown"))
        state = EvidenceState(raw.get("state", "unknown"))
        if not isinstance(stamped_version, str) or not stamped_version:
            raise ValueError("missing package version")
        if revision is not None and not isinstance(revision, str):
            raise ValueError("invalid source revision")
        if revision is not None and not _IMMUTABLE_REVISION.fullmatch(revision):
            raise ValueError("source revision is not an immutable object id")
        if build_identifier is not None and not isinstance(build_identifier, str):
            raise ValueError("invalid build identifier")
        if (state is EvidenceState.KNOWN) != (revision is not None):
            raise ValueError("inconsistent source revision evidence")
        return BuildIdentity(
            package_version=stamped_version,
            source_revision=revision,
            build_identifier=build_identifier,
            provenance=provenance,
            state=state,
        )
    except (FileNotFoundError, OSError, TypeError, ValueError, json.JSONDecodeError):
        return BuildIdentity(
            package_version=package_version,
            source_revision=None,
            build_identifier=None,
            provenance=IdentityProvenance.UNKNOWN,
            state=EvidenceState.UNKNOWN,
        )


def _unknown_fingerprint(error: str) -> SourceFingerprint:
    return SourceFingerprint(
        state=EvidenceState.UNKNOWN,
        digest=None,
        file_count=0,
        error=error,
    )


def _normalise_roots(
    roots: Mapping[str, str | os.PathLike[str]],
) -> tuple[dict[str, Path] | None, str | None]:
    if not roots:
        return None, "source-roots-missing"
    result: dict[str, Path] = {}
    for label, value in sorted(roots.items()):
        if not isinstance(label, str) or not _ROOT_LABEL.fullmatch(label):
            return None, "source-root-label-invalid"
        try:
            candidate = Path(value)
        except TypeError:
            return None, "source-root-invalid"
        try:
            if candidate.is_symlink():
                return None, f"source-root-symlink:{label}"
            resolved = candidate.resolve(strict=True)
        except OSError:
            return None, f"source-root-unreadable:{label}"
        if not resolved.is_dir():
            return None, f"source-root-not-directory:{label}"
        result[label] = resolved
    return result, None


def _relevant_source_file(path: Path) -> bool:
    return path.name == "py.typed" or path.suffix.lower() in _RELEVANT_SUFFIXES


def _read_source_file(path: Path) -> bytes:
    file_stat = path.lstat()
    if stat.S_ISLNK(file_stat.st_mode):
        raise OSError("source symlink")
    if not stat.S_ISREG(file_stat.st_mode):
        raise OSError("source is not a regular file")
    if file_stat.st_mode & 0o444 == 0:
        raise PermissionError("source has no read bits")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened_stat = os.fstat(descriptor)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise OSError("opened source is not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            return source.read()
    finally:
        os.close(descriptor)


def fingerprint_source_roots(
    roots: Mapping[str, str | os.PathLike[str]],
) -> SourceFingerprint:
    """Hash stable root-relative identities and contents without following links."""
    normalised, error = _normalise_roots(roots)
    if normalised is None:
        return _unknown_fingerprint(error or "source-roots-invalid")

    digest = hashlib.sha256(b"safeyolo-source-generation-v1\0")
    file_count = 0
    for label, root in sorted(normalised.items()):
        walk_errors: list[OSError] = []
        for current, directory_names, file_names in os.walk(
            root,
            topdown=True,
            followlinks=False,
            onerror=walk_errors.append,
        ):
            current_path = Path(current)
            retained_directories = []
            for directory_name in sorted(directory_names):
                directory_path = current_path / directory_name
                if directory_path.is_symlink():
                    return _unknown_fingerprint(f"source-symlink:{label}/{directory_path.relative_to(root).as_posix()}")
                if directory_name in _EXCLUDED_DIRECTORIES:
                    continue
                retained_directories.append(directory_name)
            directory_names[:] = retained_directories

            for file_name in sorted(file_names):
                path = current_path / file_name
                if not _relevant_source_file(path):
                    continue
                relative = path.relative_to(root).as_posix()
                if path.is_symlink():
                    return _unknown_fingerprint(f"source-symlink:{label}/{relative}")
                try:
                    content = _read_source_file(path)
                except OSError:
                    return _unknown_fingerprint(f"source-unreadable:{label}/{relative}")
                identity = f"{label}/{relative}".encode()
                digest.update(len(identity).to_bytes(8, "big"))
                digest.update(identity)
                digest.update(len(content).to_bytes(8, "big"))
                digest.update(content)
                file_count += 1
        if walk_errors:
            return _unknown_fingerprint(f"source-unreadable:{label}")
    if file_count == 0:
        return _unknown_fingerprint("source-files-missing")
    return SourceFingerprint(
        state=EvidenceState.KNOWN,
        digest=digest.hexdigest(),
        file_count=file_count,
    )


def _run_git(directory: Path, *arguments: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(directory), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def process_start_token(process_id: int) -> str | None:
    """Return an OS-backed token that changes when a PID is reused."""
    if sys.platform.startswith("linux"):
        try:
            stat_text = Path(f"/proc/{process_id}/stat").read_text()
            # The command field can contain spaces or parentheses. Fields after
            # its final ')' begin at stat field 3; starttime is field 22.
            fields_after_command = stat_text.rsplit(")", 1)[1].split()
            start_ticks = fields_after_command[19]
            boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        except (IndexError, OSError):
            return None
        return f"linux:{boot_id}:{process_id}:{start_ticks}"

    try:
        result = subprocess.run(
            ["ps", "-o", "lstart=", "-p", str(process_id)],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    started = result.stdout.strip()
    return (
        f"ps:{process_id}:{started}"
        if result.returncode == 0 and started
        else None
    )


def _status_path_is_relevant(path_text: str) -> bool:
    # Porcelain rename records use ``old -> new``. Either side being relevant
    # makes the selected generation dirty.
    candidates = path_text.split(" -> ")
    for candidate in candidates:
        path = Path(candidate.strip().strip('"'))
        if any(part in _EXCLUDED_DIRECTORIES for part in path.parts):
            continue
        if _relevant_source_file(path):
            return True
    return False


def _checkout_evidence(
    roots: Mapping[str, str | os.PathLike[str]],
) -> tuple[str | None, EvidenceState, WorkingTreeState]:
    normalised, _ = _normalise_roots(roots)
    if normalised is None:
        return None, EvidenceState.UNKNOWN, WorkingTreeState.UNKNOWN

    repositories: set[Path] = set()
    for root in normalised.values():
        top_level = _run_git(root, "rev-parse", "--show-toplevel")
        if not top_level:
            return None, EvidenceState.UNKNOWN, WorkingTreeState.UNKNOWN
        try:
            repositories.add(Path(top_level).resolve(strict=True))
        except OSError:
            return None, EvidenceState.UNKNOWN, WorkingTreeState.UNKNOWN
    if len(repositories) != 1:
        return None, EvidenceState.UNKNOWN, WorkingTreeState.UNKNOWN

    repository = repositories.pop()
    revision = _run_git(repository, "rev-parse", "--verify", "HEAD")
    if not revision:
        return None, EvidenceState.UNKNOWN, WorkingTreeState.UNKNOWN
    try:
        pathspecs = [root.relative_to(repository).as_posix() for root in normalised.values()]
    except ValueError:
        return None, EvidenceState.UNKNOWN, WorkingTreeState.UNKNOWN
    status_output = _run_git(
        repository,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--",
        *sorted(pathspecs),
    )
    if status_output is None:
        return revision, EvidenceState.KNOWN, WorkingTreeState.UNKNOWN
    dirty = any(len(line) > 3 and _status_path_is_relevant(line[3:]) for line in status_output.splitlines())
    return (
        revision,
        EvidenceState.KNOWN,
        WorkingTreeState.DIRTY if dirty else WorkingTreeState.CLEAN,
    )


def capture_dev_source_identity(
    roots: Mapping[str, str | os.PathLike[str]],
) -> DevSourceIdentity:
    """Capture current dev evidence, rejecting a source that moves mid-read."""
    normalised, error = _normalise_roots(roots)
    rendered_roots = (
        {label: str(path) for label, path in normalised.items()}
        if normalised is not None
        else {str(label): str(value) for label, value in roots.items()}
    )
    if normalised is None:
        return DevSourceIdentity(
            roots=rendered_roots,
            revision=None,
            revision_state=EvidenceState.UNKNOWN,
            working_tree=WorkingTreeState.UNKNOWN,
            fingerprint=_unknown_fingerprint(error or "source-roots-invalid"),
        )

    checkout_before = _checkout_evidence(normalised)
    fingerprint_before = fingerprint_source_roots(normalised)
    checkout_after = _checkout_evidence(normalised)
    fingerprint_after = fingerprint_source_roots(normalised)
    if checkout_before != checkout_after or fingerprint_before != fingerprint_after:
        return DevSourceIdentity(
            roots=rendered_roots,
            revision=None,
            revision_state=EvidenceState.UNKNOWN,
            working_tree=WorkingTreeState.UNKNOWN,
            fingerprint=_unknown_fingerprint("source-changed-during-capture"),
        )

    revision, revision_state, working_tree = checkout_after
    return DevSourceIdentity(
        roots=rendered_roots,
        revision=revision,
        revision_state=revision_state,
        working_tree=working_tree,
        fingerprint=fingerprint_after,
    )


def initialize_runtime_identity(
    *,
    dev_mode: bool,
    source_roots: Mapping[str, str | os.PathLike[str]] | None = None,
    process_started_at: str | None = None,
    process_id: int | None = None,
) -> RuntimeIdentity:
    """Create the process snapshot once; later admin requests only read it."""
    global _RUNTIME_IDENTITY
    with _IDENTITY_LOCK:
        if _RUNTIME_IDENTITY is not None:
            return _RUNTIME_IDENTITY

        stamped = load_stamped_build_identity()
        source = None
        if dev_mode:
            source = capture_dev_source_identity(source_roots or {})
            revision_known = source.revision_state is EvidenceState.KNOWN and source.revision is not None
            build = BuildIdentity(
                package_version=stamped.package_version,
                source_revision=source.revision if revision_known else None,
                build_identifier=stamped.build_identifier,
                provenance=(IdentityProvenance.DEV_CHECKOUT if revision_known else IdentityProvenance.UNKNOWN),
                state=(EvidenceState.KNOWN if revision_known else EvidenceState.UNKNOWN),
            )
            mode = RuntimeMode.DEV
        else:
            build = stamped
            mode = RuntimeMode.PRODUCTION

        pid = os.getpid() if process_id is None else process_id
        start_token = process_start_token(pid)
        _RUNTIME_IDENTITY = RuntimeIdentity(
            schema_version=1,
            mode=mode,
            build=build,
            process=ProcessIdentity(
                pid=pid,
                started_at=process_started_at or datetime.now(UTC).isoformat(),
                start_token=start_token,
                start_token_state=(EvidenceState.KNOWN if start_token is not None else EvidenceState.UNKNOWN),
            ),
            source=source,
        )
        return _RUNTIME_IDENTITY


def initialize_runtime_identity_from_environment() -> RuntimeIdentity:
    """Initialise from the trusted parent-process launch environment."""
    dev_mode = os.environ.get(DEV_MODE_ENV) == "1"
    roots: dict[str, str] = {}
    if dev_mode:
        try:
            decoded = json.loads(os.environ.get(DEV_SOURCE_ROOTS_ENV, "{}"))
            if isinstance(decoded, dict) and all(
                isinstance(key, str) and isinstance(value, str) for key, value in decoded.items()
            ):
                roots = decoded
        except json.JSONDecodeError:
            roots = {}
    return initialize_runtime_identity(dev_mode=dev_mode, source_roots=roots)


def get_runtime_identity() -> RuntimeIdentity | None:
    """Return the already-captured traffic generation without recomputing it."""
    return _RUNTIME_IDENTITY


def _reset_runtime_identity_for_tests() -> None:
    global _RUNTIME_IDENTITY
    with _IDENTITY_LOCK:
        _RUNTIME_IDENTITY = None
