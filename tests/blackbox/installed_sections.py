"""Prepare one installed product and run sections with separate writable state.

Use a disposable host from a clean checkout. systrap runs isolation, workloads,
access, lifecycle and host continuity. KVM runs isolation, guest ingress and
workloads. Physical Apple Silicon VZ runs isolation, access, lifecycle and
host continuity. Each section retains its own report and logs. No hosted
proxy or host-continuity result is an isolation result.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[2]
SECTIONS = {
    "systrap": ("isolation", "workloads", "access", "lifecycle", "continuity"),
    "kvm": ("isolation", "ingress", "workloads"),
    "vz": ("isolation", "access", "lifecycle", "continuity"),
}
# run-tests.sh reserves this result for failed cleanup when invoked by this
# loop. Its ordinary public infrastructure/cleanup exit remains 2.
INNER_CLEANUP_FAILURE_EXIT = 3


def copy_prepared_nats(source: Path, root: Path) -> None:
    """Reuse only verified binary bytes; credentials/JetStream stay private."""
    shutil.copytree(source / "data/coord/nats/bin", root / "data/coord/nats/bin")


def prepare_native_instance(source: Path, root: Path) -> None:
    """Create fresh native state and reuse the prepared immutable inputs."""
    subprocess.run([str(source / "bin/safeyolo"), "--root", str(root), "init"],
                   check=True, timeout=10)
    for name in ("bin", "assets", "lib", "libexec", "share"):
        if not (source / name).exists():
            continue
        target = root / name
        if target.exists():
            target.rmdir()  # Only an empty initialization directory may be replaced.
        target.symlink_to(source / name, target_is_directory=True)


def owned_processes(root: Path) -> list[dict]:
    """Remember live processes named by this instance before invoking stop."""
    if __package__:
        from .installed_host_smoke import _pid_alive, _process_start_token
    else:
        from installed_host_smoke import _pid_alive, _process_start_token

    processes = []
    for pattern in ("agents/*/container.pid", "agents/*/vm.pid", "data/proxy-process.json",
                    "data/coord/nats/process.json"):
        for path in root.glob(pattern):
            content = path.read_text()
            pid = json.loads(content)["pid"] if path.suffix == ".json" else int(content.strip())
            if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
                raise ValueError(f"invalid owned process PID in {path}")
            if _pid_alive(pid):
                token = _process_start_token(pid)
                if token is None:
                    raise ValueError(f"cannot observe owned process start identity: {path}")
                processes.append({"pid": pid, "start_token": token})
    return processes


def surviving_processes(processes: list[dict]) -> list[str]:
    if __package__:
        from .installed_host_smoke import _pid_alive, _process_start_token
    else:
        from installed_host_smoke import _pid_alive, _process_start_token

    failures = []
    for row in processes:
        if _pid_alive(row["pid"]):
            current = _process_start_token(row["pid"])
            if current is None:
                failures.append(f"cannot verify owned process {row['pid']} stopped")
            elif current == row["start_token"]:
                failures.append(f"owned process {row['pid']} is still live")
    return failures


def cleanup_instance(cli: Path, root: Path, *, owner: bool = False) -> list[str]:
    """Stop only this section's agents/proxy and report surviving owned state."""
    env = os.environ.copy()
    env.update(SAFEYOLO_CONFIG_DIR=str(root), SAFEYOLO_LOGS_DIR=str(root / "logs"),
               SAFEYOLO_COORD_DATA_DIR=str(root / "data/coord"),
               SAFEYOLO_SUBNET_BASE="76" if owner else "75")
    failures = []
    try:
        processes = owned_processes(root)
    except (OSError, ValueError, KeyError) as exc:
        failures.append(f"owned process inspection: {exc}")
        processes = []
    if (root / "config.toml").is_file():
        agents = ("bbowner",) if owner else ("bbtest", "bbpeer")
        for agent in agents:
            if (root / "agents" / agent).is_dir():
                try:
                    result = subprocess.run([str(cli), "--root", str(root), "agent", "stop", agent], env=env,
                                            capture_output=True, timeout=60, check=False)
                    if result.returncode:
                        failures.append(f"agent stop {agent} exited {result.returncode}")
                except (OSError, subprocess.SubprocessError) as exc:
                    failures.append(f"agent stop {agent}: {exc}")
        try:
            result = subprocess.run([str(cli), "--root", str(root), "stop"], env=env, capture_output=True,
                                    timeout=60, check=False)
            if result.returncode:
                failures.append(f"proxy stop exited {result.returncode}")
        except (OSError, subprocess.SubprocessError) as exc:
            failures.append(f"proxy stop: {exc}")
    for pattern in (
        # Native stop retains the inactive proxy identity receipt. The owned
        # process snapshot above checks that it stopped even if the file goes.
        "agents/*/container.pid", "agents/*/vm.pid",
        "data/ready.json", "data/proxy.pid", "data/sockets/*/proxy.sock",
        "data/coord/nats/process.json", "sinkhole.pid", "native-parent.pid",
    ):
        failures.extend(str(path) for path in root.glob(pattern))
    failures.extend(surviving_processes(processes))
    return failures


def run_sections(lane: str, sections: tuple[str, ...], checkout: Path, revision: str,
                 directory: Path, artifacts: Path) -> int:
    """Prepare once; continue after a failed assertion only after owned cleanup."""
    source = directory / "prepared"
    env = os.environ.copy()
    for name in ("SAFEYOLO_RUST_PROXY", "SAFEYOLO_PYTHON_SOURCE", "SAFEYOLO_PDP_DIR",
                 "SAFEYOLO_TEST_CERT_DIR", "SAFEYOLO_TEST_KEY_DIR"):
        env.pop(name, None)
    env.update(SAFEYOLO_CONFIG_DIR=str(source), SAFEYOLO_LOGS_DIR=str(source / "logs"),
               SAFEYOLO_COORD_DATA_DIR=str(source / "data/coord"),
               SAFEYOLO_NATS_TEST_INSTANCE=uuid.uuid4().hex, CARGO_BUILD_JOBS="1")
    report = {"source_revision": revision, "lane": lane, "preparation": {}, "sections": []}
    artifacts.mkdir(parents=True, exist_ok=True)
    report_path = artifacts / "installed-sections.json"

    def save():
        report_path.write_text(json.dumps(report, indent=2) + "\n")

    try:
        prepared = subprocess.run(
            [str(REPOSITORY / "tests/blackbox/run-lane.sh"), lane,
             "--install-checkout", str(checkout), "--prepare-only"],
            cwd=REPOSITORY, env=env, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        report["preparation"] = {"exit": 2, "error": str(exc), "config_dir": str(source)}
        save()
        return 2
    report["preparation"] = {"exit": prepared.returncode, "config_dir": str(source)}
    save()
    if prepared.returncode:
        print(f"Product preparation failed (exit {prepared.returncode}); no sections ran")
        return 2
    cli = source / "bin/safeyolo"
    env["PATH"] = os.pathsep.join((str(source / "bin"), str(REPOSITORY / ".venv/bin"), env["PATH"]))
    env["PYTHONPATH"] = os.pathsep.join((str(REPOSITORY / "tests/reference"), str(REPOSITORY)))
    env["SAFEYOLO_BLACKBOX_INSTALL_CHECKOUT"] = str(checkout)
    env["SAFEYOLO_BLACKBOX_PREPARED_CONFIG_DIR"] = str(source)
    # All sections use the prepared installation, including supplied bundles.
    env["SAFEYOLO_NATIVE_CLI"] = str(cli)
    if lane == "systrap":
        env["SAFEYOLO_RUNSC_PLATFORM"] = "systrap"
    else:
        env.pop("SAFEYOLO_RUNSC_PLATFORM", None)
    overall = 0
    for section in sections:
        instance = directory / section
        section_artifacts = artifacts / section
        section_env = dict(env, SAFEYOLO_TEST_CONFIG_DIR=str(instance), SAFEYOLO_TEST_AGENT="bbtest",
                           SAFEYOLO_BLACKBOX_SECTION_RUN="1",
                           SAFEYOLO_BLACKBOX_ARTIFACTS_DIR=str(section_artifacts),
                           SAFEYOLO_COORD_DATA_DIR=str(instance / "data/coord"),
                           SAFEYOLO_NATS_TEST_INSTANCE=uuid.uuid4().hex,
                           SAFEYOLO_LIFECYCLE_OWNER_CONFIG_DIR=str(directory / "lifecycle-owner"),
                           SAFEYOLO_LIFECYCLE_SOURCE_CONFIG_DIR=str(source))
        section_artifacts.mkdir(parents=True, exist_ok=True)
        args = [str(REPOSITORY / "tests/blackbox/run-tests.sh"), "--expect-platform", lane,
                "--proxy-impl", "rust"]
        if section != "isolation":
            args += ["--" + section]
        if section in {"ingress", "workloads", "access", "lifecycle"}:
            args += ["--install-commit", revision]
        if section == "continuity":
            args = [str(REPOSITORY / ".venv/bin/python"),
                    str(REPOSITORY / "tests/blackbox/installed_state_transition.py"),
                    "--native", "--cli", str(cli), "--install-commit", revision,
                    "--state-parent", str(directory), "--config-dir", str(instance),
                    "--prepared-config", str(source),
                    "--output", str(section_artifacts / "installed-continuity.json")]
        print(f"=== Installed {section}: {instance} ===", flush=True)
        error = None
        try:
            result = subprocess.run(args, cwd=REPOSITORY, env=section_env, check=False)
            section_exit = result.returncode
        except (OSError, subprocess.SubprocessError) as exc:
            error = str(exc)
            section_exit = 2
        finally:
            failures = cleanup_instance(cli, instance)
            if section == "lifecycle":
                failures += cleanup_instance(cli, directory / "lifecycle-owner", owner=True)
        if section != "continuity" and section_exit == INNER_CLEANUP_FAILURE_EXIT:
            # An inner stop can remove its markers while leaving a process
            # live. A later empty inspection cannot clear that known failure.
            failures.insert(0, "section runner reported an owned cleanup failure")
            section_exit = 2
        row = {"section": section, "config_dir": str(instance), "prepared_config_dir": str(source),
               "exit": section_exit, "result": "cleanup_failure" if failures else
               "passed" if section_exit == 0 else
               "assertion_failure" if section_exit == 1 else "preparation_failure",
               "cleanup": "stopped" if not failures else "failed", "cleanup_failures": failures}
        if error is not None:
            row["error"] = error
        report["sections"].append(row)
        save()
        if failures:
            print(f"Owned cleanup failed for {section}: {failures}; remaining sections did not run")
            return 2
        if section_exit:
            overall = max(overall, 1 if section_exit == 1 else 2)
    return overall


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lane", choices=SECTIONS)
    parser.add_argument("--section", action="append", choices=sorted({s for v in SECTIONS.values() for s in v}))
    parser.add_argument("--install-commit", help="exact commit; defaults to this checkout's HEAD")
    parser.add_argument("--install-checkout", type=Path, default=REPOSITORY)
    parser.add_argument("--artifacts", type=Path, default=Path(os.environ.get(
        "SAFEYOLO_BLACKBOX_ARTIFACTS_DIR", REPOSITORY / "tests/blackbox/artifacts")))
    args = parser.parse_args()
    checkout = args.install_checkout.resolve()
    revision = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
    expected = args.install_commit or revision
    if re.fullmatch("[0-9a-f]{40}", expected) is None or revision != expected:
        parser.error("install checkout must contain the exact full selected commit")
    if subprocess.check_output(["git", "-C", str(checkout), "status", "--porcelain"], text=True).strip():
        parser.error("installed source checkout must be clean")
    sections = tuple(args.section or SECTIONS[args.lane])
    if any(section not in SECTIONS[args.lane] for section in sections) or len(set(sections)) != len(sections):
        parser.error("sections must be distinct and supported by the selected lane")
    # Keep downloaded/build inputs on disk-backed storage. Each invocation owns
    # a new parent; failed section logs remain available for diagnosis.
    # Short roots also keep configured UDS paths within macOS's pathname limit.
    directory = Path(tempfile.mkdtemp(prefix=f"sy-{args.lane}-", dir=Path.home()))
    print(f"Prepared product and section state: {directory}", flush=True)
    return run_sections(args.lane, sections, checkout, revision, directory, args.artifacts.resolve())


if __name__ == "__main__":
    # This bootstrap starts before run-lane.sh creates the test environment.
    # Reuse the checkout's stdlib process-identity helper in this parent only;
    # installed CLI subprocesses retain their isolated package imports.
    sys.path.insert(0, str(REPOSITORY / "tests/reference"))
    raise SystemExit(main())
