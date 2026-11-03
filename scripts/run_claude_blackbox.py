#!/usr/bin/env python3
"""Run the trusted installed Claude check on an operator-owned Ubuntu host.

Invoke through the existing Rundeck run/script and ssh_exec.sh boundary. The
operator supplies a provisioning executable; no provider secret is an argument
or a report field. This entry does not install a schedule or approve requests.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import tomllib
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
    from tests.blackbox.claude_smoke import SmokeFailure, require_dedicated_instance
    from tests.blackbox.installed_sections import SECTIONS, copy_prepared_nats, prepare_native_instance
    from tests.blackbox.retained_inputs import controller_identity, selected, verify_installed
else:
    from tests.blackbox.claude_smoke import SmokeFailure, require_dedicated_instance
    from tests.blackbox.installed_sections import SECTIONS, copy_prepared_nats, prepare_native_instance
    from tests.blackbox.retained_inputs import controller_identity, selected, verify_installed


def read_json(path: Path) -> dict:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("report must contain a JSON mapping")
    return value


def select_inputs(args: argparse.Namespace, attempt: Path, log) -> Path:
    inputs = attempt / "inputs"
    if args.selection is not None:
        inputs.mkdir(mode=0o700)
        frozen = inputs / "selection.json"
        frozen.write_bytes(args.selection.read_bytes())
    else:
        download_inputs(args, inputs, log)
    selection = selected(inputs / "selection.json")
    if args.ref != "refs/heads/" + selection["default_branch"]:
        raise ValueError("invocation must use the repository default branch")
    if args.source_revision and selection["host"]["source_revision"] != args.source_revision:
        raise ValueError("selected production package does not match the requested source revision")
    return inputs / "selection.json"


def download_inputs(args: argparse.Namespace, inputs: Path, log) -> None:
    selection_command = [ROOT / ".venv/bin/python", ROOT / "scripts/select_blackbox_artifacts.py",
                         "--platform", "linux-amd64", "--output", inputs]
    if args.host_run is not None:
        selection_command += ["--host-run", str(args.host_run)]
    if args.guest_index is not None:
        selection_command += ["--guest-index", args.guest_index]
    subprocess.run([str(value) for value in selection_command], cwd=ROOT, stdout=log,
                   stderr=subprocess.STDOUT, check=True)


def fresh_readiness(selection: Path, readiness: Path, log) -> Path:
    # Package fixtures in this credential-free child need normal build permissions.
    subprocess.run([str(ROOT / ".venv/bin/python"), str(ROOT / "tests/blackbox/retained_inputs.py"), "run",
                    "--lane", "systrap", "--yes", "--selection", str(selection),
                    "--artifacts", str(readiness)], cwd=ROOT, stdout=log,
                   stderr=subprocess.STDOUT, check=True, umask=0o022)
    if read_json(readiness / "retained-run.json")["exit"] != 0:
        raise ValueError("credential-free installed readiness did not pass")
    return Path(read_json(readiness / "guest/installed-sections.json")["preparation"]["config_dir"])


def reuse_readiness(args: argparse.Namespace, selection: Path, attempt: Path, log) -> Path:
    """Carry original maintained proof forward, then create separate writable state."""
    source = args.prepared_config.resolve()
    installed = verify_installed(selection, source, attempt)
    proof = args.readiness.resolve()
    prior = read_json(proof / "retained-run.json")
    sections = read_json(proof / "guest/installed-sections.json")
    if (prior.get("exit") != 0 or prior.get("lane") != "systrap"
            or prior.get("host_id") != platform.node()
            or prior.get("host_system") != platform.system()
            or prior.get("host_architecture") != platform.machine()
            or prior.get("controller_dirty") is not False
            or not re.fullmatch(r"[0-9a-f]{40}", prior.get("controller_revision") or "")
            or not prior.get("finished_at")):
        raise ValueError("retained credential-free readiness is failed, incomplete or from another host")
    if installed != read_json(proof / "installed-inputs.json"):
        raise ValueError("retained readiness installed inputs differ from the verified installation")
    original_selection = selected(proof / "selection.json")
    current_selection = selected(selection)
    if (original_selection["host"]["archive"] != current_selection["host"]["archive"]
            or any(original_selection["guest"][key] != current_selection["guest"][key]
                   for key in ("version", "compatibility", "index", "child", "archive"))):
        raise ValueError("retained readiness selection differs from the selected artifacts")
    preparation = sections["preparation"]
    rows = sections["sections"]
    if (sections.get("source_revision") != installed["host_source_revision"]
            or sections.get("lane") != "systrap" or preparation["exit"] != 0
            or Path(preparation["config_dir"]).resolve() != source
            or {row["section"] for row in rows} != set(SECTIONS["systrap"])
            or any(row["exit"] != 0 or row["result"] != "passed"
                   or row["cleanup"] != "stopped" or row["cleanup_failures"] for row in rows)):
        raise ValueError("retained credential-free sections do not prove readiness for this installation")
    # Doctor checks the current runtime payload, mapping and host prerequisites.
    # Never copy unchecked Linux settings from a cached config.toml.
    diagnosis = subprocess.run([str(source / "bin/safeyolo"), "--root", str(source), "doctor"],
                               cwd=ROOT, stdout=subprocess.PIPE, stderr=log, check=True, timeout=15)
    diagnosis_json = json.loads(diagnosis.stdout)
    linux = diagnosis_json.get("linux") if isinstance(diagnosis_json, dict) else None
    if not isinstance(linux, dict) or linux.get("state") != "ready":
        raise ValueError("retained Linux runtime is not ready")
    runtime = read_json(proof / "guest/isolation/installed-rust-runtime.json")
    isolation = next(row for row in rows if row["section"] == "isolation")
    prior_config = Path(isolation["config_dir"]) / "config.toml"
    if (runtime.get("status") != "attached_ready"
            or runtime["cli"]["source_revision"] != installed["host_source_revision"]
            or any(runtime["substrate"][key] != linux[key] for key in ("path", "version", "origin"))
            or tomllib.loads(prior_config.read_text()).get("linux") !=
               tomllib.loads((source / "config.toml").read_text()).get("linux")):
        raise ValueError("retained readiness configuration or runtime differs from this installation")
    readiness = attempt / "readiness"
    (readiness / "guest/isolation").mkdir(parents=True)
    for name in ("retained-run.json", "installed-inputs.json", "selection.json", "guest/installed-sections.json",
                 "guest/isolation/installed-rust-runtime.json"):
        (readiness / name).write_bytes((proof / name).read_bytes())
    prepared = attempt / "prepared"
    prepare_native_instance(source, prepared, log=log)
    copy_prepared_nats(source, prepared)
    verify_installed(selection, prepared, attempt)
    return prepared


def collect_reports(report: dict, attempt: Path) -> None:
    """Return maintained nonsecret reports, keeping raw diagnostics private."""
    for name, path in (("selection", "inputs/selection.json"),
                       ("readiness", "readiness/retained-run.json"),
                       ("readiness_sections", "readiness/guest/installed-sections.json"),
                       ("readiness_selection", "readiness/selection.json"),
                       ("installed", "readiness/installed-inputs.json"),
                       ("installed", "installed-inputs.json"),
                       ("smoke", "smoke/guest/claude/claude-smoke.json"),
                       ("cleanup", "smoke/guest/installed-sections.json")):
        if (attempt / path).is_file():
            try:
                report[name] = read_json(attempt / path)
            except (OSError, ValueError) as exc:
                report.setdefault("report_failures", {})[name] = type(exc).__name__
    if report["exit"] == 0 and (any(name not in report for name in ("selection", "readiness", "installed", "smoke", "cleanup"))
                               or report["smoke"].get("status") != "passed"
                               or report["smoke"].get("exit") != 0
                               or report["smoke"].get("cleanup") != "stopped"):
        report.update(exit=2, stage="report-return", failure="maintained success and cleanup reports are unavailable")


def run(args: argparse.Namespace) -> dict:
    """Select, check without credentials, provision, then admit one smoke."""
    attempt = args.output.resolve()
    attempt.mkdir(parents=True, exist_ok=False, mode=0o700)
    report = {"trigger": args.trigger, "ref": args.ref, "requested_revision": args.source_revision,
              "started_at": datetime.now(UTC).isoformat(), "stage": "admission", "exit": 2,
              "selection_mode": "retained-manual" if args.selection else
                                "exact" if args.host_run is not None or args.guest_index is not None else "newest-completed",
              "readiness_reused": False,
              "readiness_origin": str(args.readiness.resolve()) if args.readiness else None,
              "installation_origin": str(args.prepared_config.resolve()) if args.prepared_config else None,
              **controller_identity()}
    python = ROOT / ".venv/bin/python"
    readiness = attempt / "readiness"
    smoke = attempt / "smoke"

    try:
        if args.trigger not in {"nightly", "manual", "merge"}:
            raise ValueError("only trusted nightly, manual and default-branch merge invocations are supported")
        if args.trigger == "merge" and not re.fullmatch(r"[0-9a-f]{40}", args.source_revision or ""):
            raise ValueError("merge requires the full merged source revision")
        if not args.credential:
            raise ValueError("host credential name is required")
        if report["controller_dirty"] or not report["controller_revision"]:
            raise ValueError("requires a clean pinned trusted controller")
        retained = (args.selection, args.prepared_config, args.readiness)
        if any(retained) and (not all(retained) or args.trigger != "manual"
                              or args.host_run is not None or args.guest_index is not None):
            raise ValueError("retained reuse requires manual --selection --prepared-config --readiness without selector options")
        with (attempt / "private.log").open("xb") as log:
            report["stage"] = "selection"
            selection = select_inputs(args, attempt, log)
            report["stage"] = "credential-free-installed"
            if args.readiness:
                prepared = reuse_readiness(args, selection, attempt, log)
                report["readiness_reused"] = True
            else:
                prepared = fresh_readiness(selection, readiness, log)
            require_dedicated_instance(prepared)
            report["stage"] = "host-service-binding"
            # The trusted operator helper consumes its existing sealed access-only
            # provisioning route. Renewal ownership stays in the host vault.
            # Provisioner output can contain authentication material. Retain
            # only its exit, never its stdout/stderr, even in the private log.
            subprocess.run([str(args.provision), str(prepared), args.credential], cwd=ROOT,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            report["stage"] = "claude"
            environment = dict(os.environ, SAFEYOLO_CLAUDE_SMOKE_CREDENTIAL=args.credential)
            subprocess.run([str(python), str(ROOT / "tests/blackbox/retained_inputs.py"), "run",
                            "--lane", "systrap", "--selection", str(selection),
                            "--prepared-config", str(prepared), "--section", "claude",
                            "--artifacts", str(smoke)], cwd=ROOT, env=environment, stdout=log,
                           stderr=subprocess.STDOUT, check=True)
            report["stage"] = "complete"
            report["exit"] = 0
    except subprocess.TimeoutExpired:
        report["failure"] = "command timed out"
    except subprocess.CalledProcessError as exc:
        report["exit"] = exc.returncode if exc.returncode >= 0 else 128 - exc.returncode
        report["failure"] = "command failed"
    except (OSError, ValueError, KeyError, TypeError, SmokeFailure) as exc:
        report["failure"] = str(exc) if isinstance(exc, (ValueError, SmokeFailure)) else type(exc).__name__
    finally:
        collect_reports(report, attempt)
        report["finished_at"] = datetime.now(UTC).isoformat()
        (attempt / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trigger", choices=("nightly", "manual", "merge"))
    parser.add_argument("--ref", required=True, help="Trusted trigger ref; must be the repository default branch")
    parser.add_argument("--source-revision", help="Full source SHA; required for a merge invocation")
    parser.add_argument("--host-run", type=int, help="Exact default-branch production run")
    parser.add_argument("--guest-index", help="Exact completed staged index, sha256:DIGEST")
    parser.add_argument("--selection", type=Path, help="Manual reuse: frozen selected production inputs; no discovery/download")
    parser.add_argument("--prepared-config", type=Path, help="Manual reuse: verified installed root; original writable state is preserved")
    parser.add_argument("--readiness", type=Path, help="Manual reuse: original successful credential-free retained report directory on this host")
    parser.add_argument("--provision", type=Path, required=True,
                        help="Trusted executable: PROGRAM INSTALLED_ROOT CREDENTIAL_NAME; host secrets stay private")
    parser.add_argument("--credential", required=True, help="Host credential name created by the provisioner")
    parser.add_argument("--output", type=Path, required=True, help="New private attempt directory on disk")
    args = parser.parse_args()
    args.provision = args.provision.resolve()
    os.umask(0o077)
    try:
        report = run(args)
    except OSError as exc:
        parser.exit(2, f"Trusted Claude invocation failed: {type(exc).__name__}\n")
    print(json.dumps(report))
    return report["exit"]


if __name__ == "__main__":
    raise SystemExit(main())
