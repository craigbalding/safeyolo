"""Prepare one installed product and run sections with separate writable state.

Use a disposable host from a clean checkout. systrap runs isolation, workloads,
access, lifecycle and host continuity. KVM runs isolation, guest ingress and
workloads. Physical Apple Silicon VZ runs isolation, access, lifecycle and
host continuity. Each section retains its own report and logs. No hosted
proxy or host-continuity result is an isolation result.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import uuid
import zipfile
from datetime import UTC, datetime
from importlib import import_module
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
PYTEST_SUITES = ("native", "security", "identity", "isolation", "root-isolation", "lifecycle")
VZ_CONTINUITY_DEFAULTS = {"origin-host": "127.0.0.2", "origin-bind": "127.0.0.1", "http-port": 46373,
                          "https-port": 46374, "oauth-port": 46375, "admin-port": 46371}


def check_vz_ports() -> list[str]:
    """Check the six allocated IPv4 fixture ports without signalling an owner."""
    failures = []
    for port in range(46370, 46376):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                failures.append(f"VZ fixture port {port} is unavailable")
    return failures


def copy_prepared_nats(source: Path, root: Path) -> None:
    """Reuse only verified binary bytes; credentials/JetStream stay private."""
    shutil.copytree(source / "data/coord/nats/bin", root / "data/coord/nats/bin")


def owned_processes(root: Path) -> list[dict]:
    """Remember live processes named by this instance before invoking stop."""
    if __package__:
        from .installed_host_smoke import _pid_alive, _process_start_token
    else:
        from installed_host_smoke import _pid_alive, _process_start_token

    processes = []
    for pattern in ("agents/*/container.pid", "agents/*/vm.pid", "agents/*/vm-supervisor.json", "data/proxy-rust.json",
                    "data/coord/nats/nats.pid.json"):
        for path in root.glob(pattern):
            if path.name == "vm.pid" and (path.parent / "vm-supervisor.json").is_file():
                continue  # The receipt binds the helper PID to its recorded start identity.
            content = path.read_text()
            receipt = json.loads(content) if path.suffix == ".json" else {"pid": int(content.strip())}
            pids = [receipt["pid"]]
            if path.name == "vm-supervisor.json" and receipt.get("helper_pid") is not None:
                pids.append(receipt["helper_pid"])
            for pid in pids:
                if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
                    raise ValueError(f"invalid owned process PID in {path}")
                if _pid_alive(pid):
                    token = _process_start_token(pid)
                    if token is None:
                        raise ValueError(f"cannot observe owned process start identity: {path}")
                    if path.name == "vm-supervisor.json":
                        field = "start_token" if pid == receipt["pid"] else "helper_start_token"
                        recorded = receipt.get(field)
                        if not isinstance(recorded, str) or not recorded:
                            raise ValueError(f"missing VZ supervision start identity: {path}")
                        if token != recorded:
                            continue  # A reused foreign PID is not this section's process.
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
    if (root / "config.yaml").is_file():
        agents = ("bbowner",) if owner else ("bbtest", "bbpeer")
        for agent in agents:
            if (root / "agents" / agent).is_dir():
                try:
                    result = subprocess.run([str(cli), "agent", "stop", agent], env=env,
                                            capture_output=True, timeout=60, check=False)
                    if result.returncode:
                        failures.append(f"agent stop {agent} exited {result.returncode}")
                except (OSError, subprocess.SubprocessError) as exc:
                    failures.append(f"agent stop {agent}: {exc}")
        try:
            result = subprocess.run([str(cli), "stop"], env=env, capture_output=True,
                                    timeout=60, check=False)
            if result.returncode:
                failures.append(f"proxy stop exited {result.returncode}")
        except (OSError, subprocess.SubprocessError) as exc:
            failures.append(f"proxy stop: {exc}")
    for pattern in (
        "agents/*/container.pid", "agents/*/vm.pid", "agents/*/vm-supervisor.json", "data/proxy-rust.json",
        "data/proxy-readiness.json", "data/proxy.pid", "data/sockets/*/proxy.sock",
        "data/coord/nats/nats.pid.json", "sinkhole.pid", "native-parent.pid",
    ):
        failures.extend(str(path) for path in root.glob(pattern))
    failures.extend(surviving_processes(processes))
    return failures


def pytest_summary(data: dict) -> dict:
    """Select observed outcomes without arbitrary nested annotations."""
    return {name: data[name] for name in (
        "schema_version", "run_id", "source_revision", "suite", "started_at", "finished_at",
        "exit", "collected", "deselected", "collection_errors", "omitted_cases",
    )} | {
        "counts": {name: data["counts"][name] for name in ("passed", "failed", "skipped", "unexecuted")
                   if name in data["counts"]},
        "cases": [{name: case[name] for name in ("test", "case_sha256", "outcome", "phase")}
                  for case in data["cases"]],
    }


def installed_runtime_summary(data: dict) -> dict:
    """Retain observed identities without instance paths or added annotations."""
    return {name: data[name] for name in (
        "run_id", "source_revision", "captured_at", "isolation_platform", "native_sha256", "wheel_source_revision",
    )} | {
        "host": {name: data["host"][name] for name in ("system", "machine")},
        "process": {name: data["process"][name] for name in ("pid", "start_token", "instance_id")},
    }


def installed_runtime_observation(artifacts: Path, report: dict, started_at: str, finished_at: str) -> tuple[dict | None, list[str]]:
    """Bind the named attached observation to this section and selected build.

    The attached probe authenticates the live process before section cleanup.
    Reading its report does not independently prove physical host ownership.
    """
    if __package__:
        from .installed_host_smoke import SmokeError, _read_json, _validate_marker
    else:
        from installed_host_smoke import SmokeError, _read_json, _validate_marker
    platform_probe = import_module(f"{__package__}.assert-platform" if __package__ else "assert-platform")
    try:
        # Never read a special file or follow a report symlink into instance state.
        for name in ("installed-rust-runtime.json", "doctor.json"):
            if not stat.S_ISREG((artifacts / name).lstat().st_mode):
                raise ValueError("observation must be a regular report")
        data = _read_json(artifacts / "installed-rust-runtime.json", "installed runtime")
        doctor = _read_json(artifacts / "doctor.json", "installed platform")
        if (not isinstance(doctor.get("checks"), list)
                or any(not isinstance(check, dict) for check in doctor["checks"])):
            raise ValueError("invalid platform checks")
        actual_platform, _message = platform_probe.reported_platform(doctor)
        if (data["status"] != "attached_ready" or data["run_id"] != report["run_id"]
                or data["source_revision"] != report["source_revision"]
                or data["build_identity"]["source_revision"] != report["source_revision"]
                or data["build_identity"]["state"] != "known" or actual_platform != report["lane"]):
            raise ValueError("mismatched installed identity")
        captured = datetime.fromisoformat(data["captured_at"])
        if (captured.tzinfo is None
                or not datetime.fromisoformat(started_at) <= captured <= datetime.fromisoformat(finished_at)):
            raise ValueError("stale installed observation")
        host = data["host"]
        system = "Darwin" if report["lane"] == "vz" else "Linux"
        if (host["system"] != system or host["system"] != platform.system()
                or host["machine"] != platform.machine()):
            raise ValueError("mismatched installed host")
        native_sha256 = data["candidate"]["sha256"]
        if native_sha256 != report["preparation"]["native_sha256"]:
            raise ValueError("native executable differs from the prepared selected build")
        runtime = data["runtime"]
        receipt, readiness, authenticated = runtime["receipt"], runtime["readiness"], runtime["authenticated_runtime_identity"]
        pid = runtime["pid"]
        if (runtime["status"] != "ready" or type(pid) is not int or pid <= 1
                or type(receipt["pid"]) is not int or receipt["pid"] != pid
                or not isinstance(readiness, dict)):
            raise ValueError("invalid process identity")
        _validate_marker(readiness, pid)
        if (authenticated["status"] != "authenticated" or type(authenticated["schema_version"]) is not int
                or authenticated["schema_version"] != 1
                or authenticated["instance_id"] != readiness["instance_id"]
                or re.fullmatch(r"[0-9a-f]{32}", authenticated["instance_id"]) is None):
            raise ValueError("invalid authenticated process identity")
        token_pattern = (rf"darwin:{pid}:[0-9]+:[0-9]+" if system == "Darwin"
                         else rf"linux:[0-9a-f]{{8}}(?:-[0-9a-f]{{4}}){{3}}-[0-9a-f]{{12}}:{pid}:[0-9]+")
        if re.fullmatch(token_pattern, receipt["start_token"]) is None:
            raise ValueError("invalid process start identity")
        packaged = Path(data["cli"]["package_location"]).parent / "bin/safeyolo-proxy"
        if (Path(data["candidate"]["path"]) != packaged
                or Path(runtime["actual_executable"]) != packaged):
            raise ValueError("runtime did not observe the installed wheel's native executable")
    except (SmokeError, OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        # Do not copy raw paths, exception text or a malformed field to publication.
        return None, [f"installed runtime/platform observation unavailable or invalid ({type(exc).__name__})"]
    return {"run_id": data["run_id"], "source_revision": data["source_revision"],
            "wheel_source_revision": data["build_identity"]["source_revision"], "captured_at": data["captured_at"],
            "isolation_platform": actual_platform, "native_sha256": native_sha256,
            "host": {"system": system, "machine": host["machine"]},
            "process": {"pid": pid, "start_token": receipt["start_token"], "instance_id": authenticated["instance_id"]}}, []


def publication_summary(report: dict) -> dict:
    """Project the owned runner report; private reports and logs stay private.

    This is an installed-section summary, not an independent host teardown or
    durable-publication receipt. A controller must also bind the expected run
    and source identities and require the complete paired hardware results.
    """
    preparation = report["preparation"]
    selected_preparation = {name: preparation[name] for name in (
        "exit", "input_index_sha256", "source_revision", "wheel_sha256", "native_sha256",
    ) if name in preparation}
    if "vm_helper" in preparation:
        selected_preparation["vm_helper"] = {name: preparation["vm_helper"][name] for name in (
            "git_sha", "git_dirty", "architecture", "build_profile",
        )}
    if "boot_inputs" in preparation:
        selected_preparation["boot_inputs"] = {
            name: {field: preparation["boot_inputs"][name][field] for field in ("source_revision", "sha256")}
            for name in ("Image", "initramfs.cpio.gz", "rootfs-base.ext4")
        }
    sections = []
    for row in report["sections"]:
        selected = {name: row[name] for name in (
            "section", "executed", "started_at", "finished_at", "exit", "result", "cleanup",
        )}
        selected["cleanup_failure_count"] = len(row["cleanup_failures"])
        selected["evidence_failure_count"] = len(row["evidence_failures"])
        if row.get("installed_runtime") is not None:
            selected["installed_runtime"] = installed_runtime_summary(row["installed_runtime"])
        if row["section"] == "isolation":
            selected["pytest"] = [pytest_summary(data) for data in row["pytest"]]
        sections.append(selected)
    return {"schema_version": 1, **{name: report[name] for name in (
        "source_revision", "lane", "run_id", "started_at", "finished_at", "exit",
        "requested_sections", "unexecuted_sections",
    )}, "full_section_selection": set(report["requested_sections"]) == set(SECTIONS[report["lane"]]),
            "preparation": selected_preparation, "sections": sections}


def pytest_observations(artifacts: Path, run_id: str, revision: str) -> tuple[list[dict], list[str]]:
    """Require this invocation's retained outcomes, without copying raw output."""
    observations, failures = [], []
    for suite in PYTEST_SUITES:
        try:
            path = artifacts / f"pytest-{suite}.json"
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError("observation must be a regular report")
            data = json.loads(path.read_text())
        except (OSError, ValueError) as exc:
            failures.append(f"{suite}: retained pytest observations unavailable ({type(exc).__name__})")
            continue
        if (not isinstance(data, dict) or data.get("run_id") != run_id
                or data.get("source_revision") != revision or data.get("suite") != suite):
            failures.append(f"{suite}: retained pytest observations have stale or mismatched identity")
            continue
        try:
            if type(data.get("schema_version")) is not int or data["schema_version"] != 1:
                raise ValueError("unsupported observation schema")
            if not all(isinstance(data.get(name), str) for name in ("started_at", "finished_at")):
                raise ValueError("missing observation timestamps")
            started = datetime.fromisoformat(data["started_at"])
            finished = datetime.fromisoformat(data["finished_at"])
            if started.tzinfo is None or finished.tzinfo is None or finished < started:
                raise ValueError("invalid observation timestamps")
        except ValueError:
            failures.append(f"{suite}: retained pytest observations have invalid schema or timestamps")
            continue
        counts = data.get("counts")
        cases = data.get("cases")
        if (any(type(data.get(name)) is not int or data[name] < 0
                for name in ("exit", "collected", "deselected", "collection_errors", "omitted_cases"))
                or not isinstance(counts, dict) or not isinstance(cases, list)
                or any(name not in {"passed", "failed", "skipped", "unexecuted"}
                       or type(count) is not int or count < 0 for name, count in counts.items())
                or sum(counts.values()) != data["collected"]
                or len(cases) + data["omitted_cases"] != data["collected"]
                or any(not isinstance(case, dict)
                       or not {"test", "case_sha256", "outcome", "phase"}.issubset(case)
                       or not isinstance(case.get("test"), str)
                       or re.fullmatch(r"[A-Za-z0-9_.:-]{1,300}", case["test"]) is None
                       or re.fullmatch(r"[0-9a-f]{64}", str(case.get("case_sha256"))) is None
                       or case.get("outcome") not in ("passed", "failed", "skipped", "unexecuted")
                       or case.get("phase") not in (None, "setup", "call", "teardown") for case in cases)
                or (not data["omitted_cases"] and dict(collections.Counter(case["outcome"] for case in cases)) != counts)):
            failures.append(f"{suite}: retained pytest observations are malformed or partial")
            continue
        # Only the outcome schema is carried into the section report. Never
        # copy captures, exception text, parameter values or added JSON fields.
        observations.append(pytest_summary(data))
        if (not data.get("collected") or data.get("deselected") or data.get("collection_errors")
                or data.get("omitted_cases") or data.get("counts", {}).get("unexecuted")):
            failures.append(f"{suite}: pytest collection or execution is incomplete")
    return observations, failures


def run_sections(lane: str, sections: tuple[str, ...], checkout: Path, revision: str,
                 directory: Path, artifacts: Path, *, staged_inputs: Path | None = None,
                 staged_sha256: str | None = None, python: Path | None = None,
                 continuity_options: tuple[str, ...] = (), vz_test_runner: tuple[Path, int] | None = None,
                 run_id: str | None = None) -> int:
    """Prepare once; continue after a failed assertion only after owned cleanup."""
    if __package__:
        from .installed_host_smoke import SmokeError, _sha256
    else:
        from installed_host_smoke import SmokeError, _sha256

    if run_id is not None and re.fullmatch(r"[0-9a-f]{32}", run_id) is None:
        raise ValueError("installed run ID must be a 32-character hexadecimal identifier")
    source = directory / "prepared"
    env = os.environ.copy()
    for name in ("SAFEYOLO_RUST_PROXY", "SAFEYOLO_PYTHON_SOURCE", "SAFEYOLO_PDP_DIR", "SAFEYOLO_VM_HELPER", "PYTHONPATH", "PYTHONHOME",
                 "SAFEYOLO_TEST_CERT_DIR", "SAFEYOLO_TEST_KEY_DIR", "SAFEYOLO_BLACKBOX_OBSERVATIONS_PATH"):
        env.pop(name, None)
    for name in ("SAFEYOLO_VZ_TEST_RUNNER", "SAFEYOLO_VZ_TEST_TIMEOUT_SECONDS"):
        env.pop(name, None)
    if vz_test_runner is not None:
        env.update(SAFEYOLO_VZ_TEST_RUNNER=str(vz_test_runner[0]),
                   SAFEYOLO_VZ_TEST_TIMEOUT_SECONDS=str(vz_test_runner[1]))
    env.update(UV_TOOL_DIR=str(directory / "uv-tools"),
               UV_TOOL_BIN_DIR=str(directory / "bin"),
               SAFEYOLO_CONFIG_DIR=str(source), SAFEYOLO_LOGS_DIR=str(source / "logs"),
               SAFEYOLO_COORD_DATA_DIR=str(source / "data/coord"),
               SAFEYOLO_NATS_TEST_INSTANCE=uuid.uuid4().hex, CARGO_BUILD_JOBS="1")
    run_id = run_id or uuid.uuid4().hex
    report = {"source_revision": revision, "lane": lane, "run_id": run_id,
              "started_at": datetime.now(UTC).isoformat(), "finished_at": None, "exit": None,
              "requested_sections": list(sections),
              "unexecuted_sections": list(sections), "preparation": {}, "sections": []}
    report_path = artifacts / "installed-sections.json"
    summary_path = artifacts / "installed-summary.json"

    def save(exit_code=None):
        if exit_code is not None:
            report.update(exit=exit_code, finished_at=datetime.now(UTC).isoformat())
        try:
            report_path.write_text(json.dumps(report, indent=2) + "\n")
            temporary = summary_path.with_suffix(".json.tmp")
            temporary.write_text(json.dumps(publication_summary(report), indent=2) + "\n")
            temporary.replace(summary_path)
        except OSError as exc:
            # A missing/unfinished summary must never become a successful run.
            # Keep exception messages and private paths out of publishable data.
            print(f"Installed report writing failed ({type(exc).__name__})", file=sys.stderr)
            return False
        return True

    try:
        # Preserve earlier attempts, including failures, when a caller retries.
        artifacts.mkdir(parents=True, exist_ok=True)
        for path in (report_path, summary_path):
            path.touch(exist_ok=False)
    except OSError as exc:
        print(f"Installed report needs a new writable attempt directory ({type(exc).__name__})", file=sys.stderr)
        return 2
    if not save():
        return 2
    preparation_identity = {}
    try:
        if staged_inputs is not None:
            # Keep ordinary clean-host bootstrap independent of this optional
            # offline path and its wheel/signing validation.
            if __package__:
                from .installed_staging import prepare_inputs
            else:
                from installed_staging import prepare_inputs
            preparation_identity = prepare_inputs(staged_inputs, staged_sha256 or "", checkout, revision,
                                                  directory, python or Path(sys.executable), env)
            preparation_exit = 0
        else:
            prepared = subprocess.run(
                [str(REPOSITORY / "tests/blackbox/run-lane.sh"), lane,
                 "--install-checkout", str(checkout), "--prepare-only"],
                cwd=REPOSITORY, env=env, check=False,
            )
            preparation_exit = prepared.returncode
        if not preparation_exit:
            preparation_identity["native_sha256"] = _sha256(checkout / "proxy/target/release/safeyolo-proxy")
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, subprocess.SubprocessError, SmokeError) as exc:
        report["preparation"] = {"exit": 2, "error": str(exc), "config_dir": str(source)}
        save(2)
        return 2
    report["preparation"] = {"exit": preparation_exit, "config_dir": str(source), **preparation_identity}
    saved = save(2 if preparation_exit else None)
    if preparation_exit:
        print(f"Product preparation failed (exit {preparation_exit}); no sections ran")
    if preparation_exit or not saved:
        return 2
    cli = directory / "bin/safeyolo"
    test_bin = directory / "tests/bin" if staged_inputs is not None else REPOSITORY / ".venv/bin"
    env["PATH"] = os.pathsep.join((str(directory / "bin"), str(test_bin), env["PATH"]))
    env["SAFEYOLO_BLACKBOX_INSTALL_CHECKOUT"] = str(checkout)
    env["SAFEYOLO_BLACKBOX_PREPARED_CONFIG_DIR"] = str(source)
    env["SAFEYOLO_BLACKBOX_INSTALL_REVISION"] = revision
    env["SAFEYOLO_BLACKBOX_RUN_ID"] = run_id
    if lane == "vz":
        env["SAFEYOLO_NATS_TEST_PORTS"] = "46370,46372"
        continuity_options = tuple(item for name, value in VZ_CONTINUITY_DEFAULTS.items()
                                   for item in (f"--{name}", str(value))) + continuity_options
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
                           SAFEYOLO_BLACKBOX_OBSERVATIONS_DIR=str(section_artifacts),
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
            args = [str(test_bin / "python"),
                    str(REPOSITORY / "tests/blackbox/installed_state_transition.py"),
                    "--native", "--cli", str(cli), "--install-commit", revision,
                    "--state-parent", str(directory), "--config-dir", str(instance),
                    "--prepared-config", str(source),
                    "--output", str(section_artifacts / "installed-continuity.json"), *continuity_options]
        print(f"=== Installed {section}: {instance} ===", flush=True)
        error = None
        executed = False
        started_at = datetime.now(UTC).isoformat()
        port_failures = check_vz_ports() if lane == "vz" else []
        try:
            if port_failures:
                error = "; ".join(port_failures)
                section_exit = 2
            else:
                result = subprocess.run(args, cwd=REPOSITORY, env=section_env, check=False)
                executed = True
                section_exit = result.returncode
        except (OSError, subprocess.SubprocessError) as exc:
            error = str(exc)
            section_exit = 2
        finally:
            failures = cleanup_instance(cli, instance)
            if section == "lifecycle":
                failures += cleanup_instance(cli, directory / "lifecycle-owner", owner=True)
            if lane == "vz" and not port_failures:
                failures += check_vz_ports()
        if section != "continuity" and section_exit == INNER_CLEANUP_FAILURE_EXIT:
            # An inner stop can remove its markers while leaving a process
            # live. A later empty inspection cannot clear that known failure.
            failures.insert(0, "section runner reported an owned cleanup failure")
            section_exit = 2
        observations, evidence_failures = (pytest_observations(section_artifacts, run_id, revision)
                                           if section == "isolation" else ([], []))
        if section_exit == 0:
            # A successful command cannot clear a failure in its retained
            # outcomes. The existing runner still owns exit classification.
            evidence_failures.extend(f"{data['suite']}: pytest observations contradict successful section exit"
                                     for data in observations if data["exit"] or data["counts"].get("failed"))
        finished_at = datetime.now(UTC).isoformat()
        installed_runtime = None
        if section != "continuity" and executed:
            installed_runtime, runtime_failures = installed_runtime_observation(section_artifacts, report, started_at, finished_at)
            evidence_failures += runtime_failures
        row = {"section": section, "config_dir": str(instance), "prepared_config_dir": str(source),
               "executed": executed,
               "started_at": started_at, "finished_at": finished_at,
               "exit": section_exit, "result": "cleanup_failure" if failures else
               "passed" if section_exit == 0 else
               "assertion_failure" if section_exit == 1 else "preparation_failure",
               "cleanup": "stopped" if not failures else "failed", "cleanup_failures": failures,
               "installed_runtime": installed_runtime, "evidence_failures": evidence_failures}
        if section == "isolation":
            row["pytest"] = observations
        if evidence_failures and section_exit == 0 and not failures:
            row.update(exit=2, result="evidence_failure")
            section_exit = 2
        if error is not None:
            row["error"] = error
        report["sections"].append(row)
        if executed:
            report["unexecuted_sections"].remove(section)
        saved = save(2 if failures else None)
        if failures:
            print(f"Owned cleanup failed for {section}: {failures}; remaining sections did not run")
        if failures or not saved:
            return 2
        if section_exit:
            overall = max(overall, 1 if section_exit == 1 else 2)
    return overall if save(overall) else 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lane", choices=SECTIONS)
    parser.add_argument("--section", action="append", choices=sorted({s for v in SECTIONS.values() for s in v}))
    parser.add_argument("--install-commit", help="exact commit; defaults to this checkout's HEAD")
    parser.add_argument("--run-id", help="Invocation identifier supplied by the trusted paired caller")
    parser.add_argument("--install-checkout", type=Path, default=REPOSITORY)
    parser.add_argument("--staged-inputs", type=Path, help="Verified Tart-built offline VZ inputs")
    parser.add_argument("--staged-sha256", help="Input index SHA-256 supplied by the trusted caller")
    parser.add_argument("--python", type=Path, help="Existing Python 3.12/3.13 for offline wheel installation")
    parser.add_argument("--vz-test-runner", type=Path, help="Absolute host runner for direct VZ helper deadline supervision")
    parser.add_argument("--vz-test-timeout-seconds", type=int, help="Positive deadline for each supervised VZ helper")
    parser.add_argument("--state-parent", type=Path, default=Path.home(), help="Disk-backed parent for new private section state")
    parser.add_argument("--origin-host", help="Continuity fixture authority (VZ default: 127.0.0.2)")
    parser.add_argument("--origin-bind", help="Continuity fixture bind/owned parent (VZ default: 127.0.0.1)")
    for name in ("http-port", "https-port", "oauth-port", "admin-port"):
        parser.add_argument(f"--{name}", type=int, help="Continuity fixture port; VZ uses its allocated fixed port")
    parser.add_argument("--artifacts", type=Path, default=Path(os.environ.get(
        "SAFEYOLO_BLACKBOX_ARTIFACTS_DIR", REPOSITORY / "tests/blackbox/artifacts")))
    args = parser.parse_args()
    if args.run_id is not None and re.fullmatch(r"[0-9a-f]{32}", args.run_id) is None:
        parser.error("--run-id must be a 32-character hexadecimal identifier")
    if bool(args.staged_inputs) != bool(args.staged_sha256):
        parser.error("--staged-inputs and --staged-sha256 must be supplied together")
    if args.staged_inputs is not None and args.lane != "vz":
        parser.error("staged preparation currently supports the VZ lane")
    if (args.vz_test_runner is None) != (args.vz_test_timeout_seconds is None):
        parser.error("--vz-test-runner and --vz-test-timeout-seconds must be supplied together")
    if args.vz_test_runner is not None and (args.lane != "vz" or args.vz_test_timeout_seconds < 1
            or not args.vz_test_runner.is_absolute() or not args.vz_test_runner.is_file()
            or not os.access(args.vz_test_runner, os.X_OK)):
        parser.error("VZ supervision needs an absolute executable runner and positive deadline on the VZ lane")
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
    directory = Path(tempfile.mkdtemp(prefix=f"sy-{args.lane}-", dir=args.state_parent.resolve()))
    print(f"Prepared product and section state: {directory}", flush=True)
    continuity_options = []
    for name in ("origin-host", "origin-bind", "http-port", "https-port", "oauth-port", "admin-port"):
        value = getattr(args, name.replace("-", "_"))
        if value is not None:
            continuity_options.extend((f"--{name}", str(value)))
    return run_sections(args.lane, sections, checkout, revision, directory, args.artifacts.resolve(),
                        staged_inputs=args.staged_inputs.resolve() if args.staged_inputs else None,
                        staged_sha256=args.staged_sha256, python=args.python,
                        continuity_options=tuple(continuity_options),
                        run_id=args.run_id,
                        vz_test_runner=(args.vz_test_runner, args.vz_test_timeout_seconds)
                        if args.vz_test_runner is not None else None)


if __name__ == "__main__":
    # This bootstrap starts before run-lane.sh creates the test environment.
    # Reuse the checkout's stdlib process-identity helper in this parent only;
    # installed CLI subprocesses retain their isolated package imports.
    sys.path.insert(0, str(REPOSITORY / "cli/src"))
    raise SystemExit(main())
