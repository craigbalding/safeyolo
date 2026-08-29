"""Runtime/build identity and dev source-generation acceptance coverage."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import pytest

from safeyolo.runtime_identity import (
    BuildIdentity,
    EvidenceState,
    IdentityProvenance,
    RuntimeMode,
    SourceFingerprint,
    WorkingTreeState,
    _reset_runtime_identity_for_tests,
    capture_dev_source_identity,
    fingerprint_source_roots,
    get_runtime_identity,
    initialize_runtime_identity,
)

pytestmark = pytest.mark.assurance_boundary

REPO_ROOT = Path(__file__).resolve().parents[2]


def _source_roots(tmp_path: Path) -> dict[str, Path]:
    safeyolo = tmp_path / "cli" / "src" / "safeyolo"
    pdp = tmp_path / "pdp"
    safeyolo.mkdir(parents=True)
    pdp.mkdir()
    (safeyolo / "__init__.py").write_text("VALUE = 1\n")
    (pdp / "__init__.py").write_text("VALUE = 2\n")
    return {"safeyolo": safeyolo, "pdp": pdp}


def _git(directory: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(directory), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _initialise_git_checkout(tmp_path: Path) -> dict[str, Path]:
    roots = _source_roots(tmp_path)
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "identity-test@example.invalid")
    _git(tmp_path, "config", "user.name", "Identity Test")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "initial")
    return roots


def test_fingerprint_is_ordered_content_identity_not_mtime(tmp_path):
    roots = _source_roots(tmp_path)
    extra = roots["safeyolo"] / "nested"
    extra.mkdir()
    (extra / "z.py").write_text("Z = 1\n")
    (extra / "a.yaml").write_text("key: value\n")

    first = fingerprint_source_roots({"safeyolo": roots["safeyolo"], "pdp": roots["pdp"]})
    os.utime(extra / "z.py", None)
    second = fingerprint_source_roots({"pdp": roots["pdp"], "safeyolo": roots["safeyolo"]})

    assert first.state is EvidenceState.KNOWN
    assert second.digest == first.digest
    assert second.file_count == first.file_count


def test_relevant_changes_but_irrelevant_files_and_caches_do_not_drift(tmp_path):
    roots = _source_roots(tmp_path)
    baseline = fingerprint_source_roots(roots)

    (roots["safeyolo"] / "notes.txt").write_text("operator notes\n")
    cache = roots["safeyolo"] / "__pycache__"
    cache.mkdir()
    (cache / "module.pyc").write_bytes(b"cache")
    assert fingerprint_source_roots(roots).digest == baseline.digest

    (roots["safeyolo"] / "__init__.py").write_text("VALUE = 3\n")
    assert fingerprint_source_roots(roots).digest != baseline.digest


def test_symlinks_and_path_traversal_labels_fail_closed(tmp_path):
    roots = _source_roots(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text("SECRET = 1\n")
    (roots["safeyolo"] / "linked.py").symlink_to(outside)

    linked = fingerprint_source_roots(roots)
    traversing = fingerprint_source_roots({"../escape": roots["pdp"]})

    assert linked.state is EvidenceState.UNKNOWN
    assert linked.error.startswith("source-symlink:")
    assert traversing.state is EvidenceState.UNKNOWN
    assert traversing.error == "source-root-label-invalid"


def test_unreadable_and_deleted_sources_are_unknown(tmp_path, monkeypatch):
    roots = _source_roots(tmp_path)
    source = roots["safeyolo"] / "__init__.py"
    source.chmod(0)
    unreadable = fingerprint_source_roots(roots)
    assert unreadable.state is EvidenceState.UNKNOWN
    assert unreadable.error.startswith("source-unreadable:")

    source.chmod(0o644)
    import safeyolo.runtime_identity as identity_module

    original_read = identity_module._read_source_file

    def delete_before_read(path: Path) -> bytes:
        if path == source:
            path.unlink()
        return original_read(path)

    monkeypatch.setattr(identity_module, "_read_source_file", delete_before_read)
    deleted = fingerprint_source_roots(roots)
    assert deleted.state is EvidenceState.UNKNOWN
    assert deleted.error.startswith("source-unreadable:")


def test_checkout_evidence_distinguishes_clean_dirty_and_committed_revision(
    tmp_path,
):
    roots = _initialise_git_checkout(tmp_path)
    clean = capture_dev_source_identity(roots)
    assert clean.revision_state is EvidenceState.KNOWN
    assert clean.working_tree is WorkingTreeState.CLEAN

    (roots["safeyolo"] / "notes.txt").write_text("irrelevant\n")
    irrelevant = capture_dev_source_identity(roots)
    assert irrelevant.working_tree is WorkingTreeState.CLEAN
    assert irrelevant.fingerprint.digest == clean.fingerprint.digest

    source = roots["safeyolo"] / "__init__.py"
    source.write_text("VALUE = 9\n")
    dirty = capture_dev_source_identity(roots)
    assert dirty.revision == clean.revision
    assert dirty.working_tree is WorkingTreeState.DIRTY
    assert dirty.fingerprint.digest != clean.fingerprint.digest

    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "change relevant source")
    committed = capture_dev_source_identity(roots)
    assert committed.revision != clean.revision
    assert committed.working_tree is WorkingTreeState.CLEAN
    assert committed.fingerprint.digest == dirty.fingerprint.digest


def test_capture_rejects_source_that_changes_between_samples(tmp_path, monkeypatch):
    import safeyolo.runtime_identity as identity_module

    roots = _initialise_git_checkout(tmp_path)
    known = fingerprint_source_roots(roots)
    changed = SourceFingerprint(
        state=EvidenceState.KNOWN,
        digest="f" * 64,
        file_count=known.file_count,
    )
    samples = iter([known, changed])
    monkeypatch.setattr(
        identity_module,
        "fingerprint_source_roots",
        lambda selected_roots: next(samples),
    )

    captured = capture_dev_source_identity(roots)

    assert captured.revision_state is EvidenceState.UNKNOWN
    assert captured.working_tree is WorkingTreeState.UNKNOWN
    assert captured.fingerprint.state is EvidenceState.UNKNOWN
    assert captured.fingerprint.error == "source-changed-during-capture"


def test_production_initialisation_does_not_use_git_or_scan(monkeypatch):
    import safeyolo.runtime_identity as identity_module

    stamped = BuildIdentity(
        package_version="7.8.9",
        source_revision="a" * 40,
        build_identifier="release-12",
        provenance=IdentityProvenance.BUILD_ENVIRONMENT,
        state=EvidenceState.KNOWN,
    )
    monkeypatch.setattr(identity_module, "load_stamped_build_identity", lambda: stamped)
    monkeypatch.setattr(
        identity_module,
        "_run_git",
        lambda *args, **kwargs: pytest.fail("production invoked git"),
    )
    monkeypatch.setattr(
        identity_module,
        "fingerprint_source_roots",
        lambda *args, **kwargs: pytest.fail("production scanned source"),
    )
    _reset_runtime_identity_for_tests()

    identity = initialize_runtime_identity(dev_mode=False, source_roots={})

    assert identity.mode is RuntimeMode.PRODUCTION
    assert identity.build == stamped
    assert identity.source is None


def test_process_snapshot_is_immutable_after_source_changes(tmp_path, monkeypatch):
    import safeyolo.runtime_identity as identity_module

    roots = _source_roots(tmp_path)
    monkeypatch.setattr(
        identity_module,
        "load_stamped_build_identity",
        lambda: BuildIdentity(
            package_version="0.1.0",
            source_revision=None,
            build_identifier=None,
            provenance=IdentityProvenance.UNKNOWN,
            state=EvidenceState.UNKNOWN,
        ),
    )
    _reset_runtime_identity_for_tests()
    running = initialize_runtime_identity(
        dev_mode=True,
        source_roots=roots,
        process_started_at="2026-01-01T00:00:00+00:00",
        process_id=123,
    )
    original_digest = running.source.fingerprint.digest
    (roots["pdp"] / "__init__.py").write_text("VALUE = 99\n")

    assert get_runtime_identity() is running
    assert get_runtime_identity().source.fingerprint.digest == original_digest
    assert fingerprint_source_roots(roots).digest != original_digest


def _subprocess_dev_identity(roots: dict[str, Path]) -> dict:
    environment = os.environ.copy()
    environment["SAFEYOLO_DEV_MODE"] = "1"
    environment["SAFEYOLO_DEV_SOURCE_ROOTS"] = json.dumps({label: str(path) for label, path in roots.items()})
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import json; "
                "from safeyolo.runtime_identity import "
                "initialize_runtime_identity_from_environment as init; "
                "print(json.dumps(init().to_dict(), sort_keys=True))"
            ),
        ],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    return json.loads(result.stdout)


def test_real_subprocess_restart_converges_to_changed_source(tmp_path):
    roots = _initialise_git_checkout(tmp_path)
    first = _subprocess_dev_identity(roots)
    first_digest = first["source"]["fingerprint"]["digest"]

    (roots["pdp"] / "core.py").write_text("CHANGED = True\n")
    current = capture_dev_source_identity(roots)
    assert current.fingerprint.digest != first_digest

    time.sleep(0.02)
    restarted = _subprocess_dev_identity(roots)
    assert restarted["source"]["fingerprint"]["digest"] == (current.fingerprint.digest)
    assert restarted["process"]["started_at"] != first["process"]["started_at"]
    assert restarted["process"]["start_token"] != first["process"]["start_token"]


def test_isolated_wheel_carries_stamped_identity_without_git(tmp_path):
    output = tmp_path / "dist"
    environment = os.environ.copy()
    environment["SAFEYOLO_BUILD_REVISION"] = "B" * 40
    environment["SAFEYOLO_BUILD_ID"] = "ci-run-401"
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(output)],
        cwd=REPO_ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    wheel = next(output.glob("*.whl"))
    installed = tmp_path / "installed"
    with zipfile.ZipFile(wheel) as archive:
        assert "safeyolo/_build_identity.json" in archive.namelist()
        archive.extractall(installed)

    script = (
        "import json, sys; sys.path.insert(0, sys.argv[1]); "
        "import safeyolo.runtime_identity as identity; "
        "identity._run_git = lambda *a, **k: (_ for _ in ()).throw("
        "RuntimeError('git forbidden')); "
        "identity.fingerprint_source_roots = lambda *a, **k: (_ for _ in ())"
        ".throw(RuntimeError('scan forbidden')); "
        "print(json.dumps(identity.initialize_runtime_identity("
        "dev_mode=False).to_dict(), sort_keys=True))"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(installed)],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": str(tmp_path / "no-tools")},
    )
    identity = json.loads(result.stdout)
    assert identity["mode"] == "production"
    assert identity["build"] == {
        "build_identifier": "ci-run-401",
        "package_version": "0.1.0",
        "provenance": "build-environment",
        "source_revision": "b" * 40,
        "state": "known",
    }


def test_wheel_build_rejects_a_mutable_revision_name(tmp_path):
    result = subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(tmp_path / "dist")],
        cwd=REPO_ROOT,
        env={**os.environ, "SAFEYOLO_BUILD_REVISION": "main"},
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "SAFEYOLO_BUILD_REVISION must be" in result.stderr
