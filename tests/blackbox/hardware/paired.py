"""Trusted overnight and operator on-demand paired KVM/physical-VZ execution.

Run this pinned installation with its private deployment configuration. It
admits one source commit before candidate code reaches either hardware lane.
Rundeck, Tart, SSH and GitHub principals remain in the control process.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import json
import shlex
import signal
import subprocess
import sys
import uuid
from pathlib import Path

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "cli/src"))
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    from tests.blackbox.hardware import attempt_results, kvm_host, publish_results, service_calls
else:
    from . import attempt_results, kvm_host, publish_results, service_calls

ROOT = Path(__file__).resolve().parents[3]
CHUNK_BYTES = 1024 * 1024
MAX_TRANSFER_BYTES = 32 * 1024**3
ERRORS = (OSError, ValueError, KeyError, TypeError, RuntimeError, RecursionError, subprocess.SubprocessError)


def shell(arguments) -> str:
    return shlex.join(str(item) for item in arguments)


def checked_controller(checkout: Path, revision: str) -> None:
    attempt_results.hexadecimal(revision, 40)
    observed = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
    changes = subprocess.check_output(["git", "-C", str(checkout), "status", "--porcelain"], text=True).strip()
    if observed != revision or changes:
        raise ValueError("trusted installation is dirty or differs from its pinned controller revision")


def hardware_result(output: str) -> dict:
    rows = [json.loads(line[len("HARDWARE_RESULT="):]) for line in output.splitlines()
            if line.startswith("HARDWARE_RESULT=")]
    if len(rows) != 1 or not isinstance(rows[0], dict):
        raise ValueError("missing or ambiguous trusted host response")
    return rows[0]


class PairedHardware:
    """Concrete adapters for the three existing operator transport bindings."""

    def __init__(self, configuration: dict, attempt: attempt_results.HardwareAttempt):
        self.config = configuration
        self.attempt = attempt
        self.rundeck = service_calls.Rundeck(configuration["rundeck_url"],
                                            Path(configuration["rundeck_token_file"]) if configuration.get("rundeck_token_file") else None)
        self.timeout = attempt_results.integer(configuration.get("lane_timeout_seconds", 7200), minimum=1)

    def rundeck_call(self, action: str, extra: tuple[str, ...] = ()) -> dict:
        checkout = self.config["rundeck_controller"]
        command = ["python3", str(Path(checkout) / "tests/blackbox/hardware/kvm_host.py"), action,
                   "--owner", self.attempt.data["owner"], *extra]
        revision = self.attempt.data["controller_revision"]
        script = ("set -euo pipefail\n"
                  f"test \"$(git -C {shlex.quote(checkout)} rev-parse HEAD)\" = {revision}\n"
                  f"test -z \"$(git -C {shlex.quote(checkout)} status --porcelain)\"\n" + shell(command) + "\n")
        invocation = self.rundeck.submit(script)
        self.attempt.data.setdefault("rundeck_executions", []).append(invocation)
        self.attempt.save()
        try:
            status = self.rundeck.wait(invocation, self.timeout + 1200 if action == "run" else 240)
        finally:
            # A cancelled/failed wait still needs independent host cleanup.
            # Abort is request-state only; its success never marks teardown.
            if sys.exception() is not None:
                try:
                    self.rundeck.abort(invocation)
                except ERRORS:
                    # Retain the original cancellation/deadline. Failed abort
                    # leaves independent owned cleanup explicitly outstanding.
                    self.attempt.fail("cleanup", lane="kvm")
        log = self.attempt.directory / f"rundeck-{invocation}-{uuid.uuid4().hex}.log"
        self.rundeck.output(invocation, log)
        if status["executionState"] != "SUCCEEDED":
            raise ValueError("Rundeck host command did not complete successfully")
        return hardware_result(log.read_text())

    def run_kvm(self, receipt: dict) -> None:
        owner, revision = self.attempt.data["owner"], self.attempt.data["source_revision"]
        result = None
        try:
            with self.attempt.phase("execution", lane="kvm"):
                result = self.rundeck_call("run", ("--install-commit", revision, "--run-id", receipt["run_id"],
                                                   "--timeout-seconds", str(self.timeout)))
                if any(result[name] != value for name, value in (("owner", owner), ("source_revision", revision), ("run_id", receipt["run_id"]))):
                    raise ValueError("KVM response differs from the admitted attempt")
                receipt["allocation"] = {"guest_name": result["guest_name"]}
                receipt["trusted_host"] = result.get("platform")
                receipt["command_exit"] = result["exit"]
                self.attempt.save()
                if result["stage"] is not None:
                    self.attempt.fail(result["stage"], lane="kvm")
                if type(result["exit"]) is not int or result["exit"] != 0:
                    self.attempt.fail("execution", lane="kvm")
                path = self.attempt.directory / "kvm-summary.json"
                path.write_text(json.dumps(result["summary"]))
                self.attempt.retain_lane("kvm", path)
        finally:
            try:
                if result is not None and result.get("guest_name"):
                    # A second host process inspects exact domain/disk/seed/lease.
                    check = self.rundeck_call("verify", ("--guest-name", result["guest_name"]))
                else:
                    check = self.rundeck_call("cleanup")
                stopped = check["owner"] == owner and check["removed"] is True
                if result is not None:
                    stopped = stopped and result["cleanup"] == "verified"
            except ERRORS:
                stopped = False
            receipt["cleanup"] = "verified" if stopped else "failed"
            if not stopped:
                self.attempt.fail("cleanup", lane="kvm")
            self.attempt.save()

    def tart(self, script: str, timeout: int = 60, *, retain_output: bool = True) -> dict:
        path = self.attempt.directory / f"tart-{uuid.uuid4().hex}.sh"
        path.write_text(script)
        result = service_calls.tart_command(Path(self.config["tart_client"]), Path(self.config["tart_mailbox"]), path, timeout)
        self.attempt.data.setdefault("tart_executions", []).append(result["job_id"])
        self.attempt.save()
        # Build logs stay private; only canonical fields decide transport outcome.
        if retain_output:
            (path.with_suffix(".log")).write_text(result["stdout"] + result["stderr"])
        if result["timed_out"] or result["exit_code"] != 0:
            raise ValueError("Tart invocation failed or exceeded its deadline")
        return hardware_result(result["stdout"])

    def build_vz(self) -> tuple[Path, dict]:
        config = self.config
        revision = self.attempt.data["source_revision"]
        build_root = Path(config["tart_runs"]) / self.attempt.data["run_id"]
        self.attempt.data["tart_build"] = {"root": str(build_root), "complete": False, "removed": False}
        self.attempt.save()
        controller = Path(config["tart_controller"])
        commands = ["set -euo pipefail",
                    f"test \"$(git -C {shlex.quote(str(controller))} rev-parse HEAD)\" = {self.attempt.data['controller_revision']}",
                    f"test -z \"$(git -C {shlex.quote(str(controller))} status --porcelain)\"",
                    shell(["mkdir", "-m", "700", build_root]),
                    shell(["git", "init", build_root / "source"]),
                    shell(["git", "-C", build_root / "source", "remote", "add", "origin", "https://github.com/craigbalding/safeyolo.git"]),
                    shell(["git", "-C", build_root / "source", "fetch", "--depth=1", "origin", revision]),
                    shell(["git", "-C", build_root / "source", "checkout", "--detach", "FETCH_HEAD"]),
                    shell([str(config["tart_python"]), str(controller / "tests/blackbox/hardware/build_inputs.py"),
                           "--checkout", build_root / "source", "--install-commit", revision,
                           "--boot-inputs", config["tart_boot_inputs"], "--boot-provenance", config["tart_boot_provenance"],
                           "--output", build_root / "build", "--python", config["tart_python"], "--timeout-seconds", "3600"])
                    + " >" + shlex.quote(str(build_root / "build-receipt.json")),
                    shell([str(config["tart_python"]), "-", str(build_root), revision]) + " <<'PY'",
                    "import hashlib,json,subprocess,sys,tarfile\nfrom pathlib import Path\n"
                    "root=Path(sys.argv[1]); source=root/'source'; payload=root/'build/payload'\n"
                    "archive=root/'inputs.tar'\n"
                    "with tarfile.open(archive,'w') as out:\n"
                    "    out.add(payload,arcname='payload')\n"
                    "    out.add(source/'.git',arcname='source/.git')\n"
                    "    for name in subprocess.check_output(['git','-C',str(source),'ls-files','-z']).decode().split('\\0'):\n"
                    "        if name: out.add(source/name,arcname='source/'+name,recursive=False)\n"
                    "digest=hashlib.file_digest(archive.open('rb'),'sha256').hexdigest()\n"
                    "index=hashlib.file_digest((payload/'staged-inputs.json').open('rb'),'sha256').hexdigest()\n"
                    "print('HARDWARE_RESULT='+json.dumps({'source_revision':sys.argv[2], 'size':archive.stat().st_size, 'sha256':digest, 'input_index_sha256':index}))",
                    "PY"]
        metadata = self.tart("\n".join(commands) + "\n", 3660)
        self.attempt.data["tart_build"]["complete"] = True
        self.attempt.save()
        if metadata["source_revision"] != revision:
            raise ValueError("Tart returned a different source")
        size = attempt_results.integer(metadata["size"], minimum=1)
        digest = attempt_results.hexadecimal(metadata["sha256"], 64)
        attempt_results.hexadecimal(metadata["input_index_sha256"], 64)
        if size > MAX_TRANSFER_BYTES:
            raise ValueError("Tart transfer exceeds the configured disk-backed bound")
        target = self.attempt.directory / "inputs.tar"
        with target.open("xb") as stream:
            for offset in range(0, size, CHUNK_BYTES):
                script = (shell([str(config["tart_python"]), "-", build_root / "inputs.tar", str(offset), str(CHUNK_BYTES)])
                          + " <<'PY'\nimport base64,json,sys\n"
                          "with open(sys.argv[1],'rb') as f:\n"
                          "    f.seek(int(sys.argv[2])); chunk=f.read(int(sys.argv[3]))\n"
                          "print('HARDWARE_RESULT='+json.dumps({'offset':int(sys.argv[2]),'content_b64':base64.b64encode(chunk).decode()}))\nPY\n")
                chunk = self.tart(script, retain_output=False)
                content = base64.b64decode(chunk["content_b64"], validate=True)
                if chunk["offset"] != offset or len(content) != min(CHUNK_BYTES, size - offset):
                    raise ValueError("Tart artifact transfer is partial or out of order")
                stream.write(content)
        with target.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                raise ValueError("Tart artifact differs from its trusted build digest")
        return target, metadata

    def release_build(self) -> bool:
        """An unfinished or unknown builder is never removed or reported clean."""
        build = self.attempt.data.get("tart_build")
        if build is None or build["removed"]:
            return True
        if not build["complete"]:
            return False
        code = ("import json,shutil,sys\nfrom pathlib import Path\np=Path(sys.argv[1])\n"
                "if p.name!=sys.argv[2] or p.is_symlink(): raise ValueError('build ownership differs')\n"
                "if p.exists(): shutil.rmtree(p)\n"
                "print('HARDWARE_RESULT='+json.dumps({'removed':not p.exists()}))")
        released = self.tart(shell([self.config["tart_python"], "-c", code, build["root"], self.attempt.data["run_id"]]), 180)
        build["removed"] = released["removed"] is True
        self.attempt.save()
        return build["removed"]

    def bristol(self, arguments: list[str], *, stdin=None, timeout: int = 60) -> dict:
        private = self.attempt.directory / f"bristol-{uuid.uuid4().hex}.log"
        checkout = shlex.quote(self.config["bristol_controller"])
        remote = ("set -eu\n"
                  f"test \"$(git -C {checkout} rev-parse HEAD)\" = {self.attempt.data['controller_revision']}\n"
                  f"test -z \"$(git -C {checkout} status --porcelain)\"\nexec " + shell(arguments))
        with private.open("xb") as output:
            status = service_calls.bristol_command(Path(self.config["bristol_ssh_config"]), remote, stdin, output, timeout)
        if status:
            raise ValueError("Bristol SSH command failed; independent cleanup is still required")
        return hardware_result(private.read_text())

    def mac_arguments(self, action: str, root: Path, state: Path) -> list[str]:
        config = self.config
        return [config["bristol_python"], str(Path(config["bristol_controller"]) / "tests/blackbox/hardware/mac_host.py"),
                action, "--journal", config["bristol_journal"], "--owner", self.attempt.data["owner"],
                "--run-root", str(root), "--state-parent", str(state)]

    def run_vz(self, receipt: dict) -> None:
        config = self.config
        root = Path(config["bristol_runs"]) / self.attempt.data["run_id"][:8]
        state = Path(config["bristol_states"]) / self.attempt.data["run_id"][:8]
        self.attempt.data["lanes"]["vz"]["allocation"] = {"run_root": str(root), "state_parent": str(state)}
        self.attempt.save()
        receipt["execution_started"] = False
        result = None
        archive = None
        try:
            with self.attempt.phase("preflight", lane="vz"):
                self.bristol(self.mac_arguments("preflight", Path(config["bristol_runs"]), state))
            with self.attempt.phase("build", lane="vz"):
                archive, metadata = self.build_vz()
                receipt["input_index_sha256"] = metadata["input_index_sha256"]
                self.attempt.save()
            with self.attempt.phase("execution", lane="vz"):
                arguments = self.mac_arguments("run", root, state) + [
                    "--python", config["bristol_python"], "--install-commit", self.attempt.data["source_revision"],
                    "--run-id", receipt["run_id"], "--staged-sha256", metadata["input_index_sha256"],
                    "--archive-sha256", metadata["sha256"],
                    "--timeout-seconds", str(self.timeout), "--helper-timeout-seconds", str(config.get("vz_helper_timeout_seconds", 120)),
                ]
                receipt["execution_started"] = True
                self.attempt.save()
                with archive.open("rb") as source:
                    result = self.bristol(arguments, stdin=source, timeout=self.timeout + 900)
                if any(result[name] != value for name, value in (("owner", self.attempt.data["owner"]),
                       ("source_revision", self.attempt.data["source_revision"]), ("run_id", receipt["run_id"]))):
                    raise ValueError("VZ response differs from the admitted attempt")
                receipt["trusted_host"] = result.get("platform")
                receipt["command_exit"] = result["exit"]
                if result["stage"] is not None:
                    self.attempt.fail(result["stage"], lane="vz")
                if type(result["exit"]) is not int or result["exit"] != 0:
                    self.attempt.fail("execution", lane="vz")
            self.retain_vz_reports(root)
        finally:
            self.teardown_vz(receipt, result, archive)

    def retain_vz_reports(self, root: Path) -> None:
        config = self.config
        with self.attempt.phase("report", lane="vz"):
            code = ("import base64,hashlib,json,sys\nfrom pathlib import Path\n"
                    "import os,stat\np=Path(sys.argv[1]); fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)\n"
                    "with os.fdopen(fd,'rb') as f:\n"
                    "    if not stat.S_ISREG(os.fstat(f.fileno()).st_mode): raise ValueError('report is not regular')\n"
                    "    data=f.read(8388609)\n"
                    "if len(data)>8388608: raise ValueError('report exceeds bounded transfer')\n"
                    "print('HARDWARE_RESULT='+json.dumps({'path':str(p),'size':len(data),'sha256':hashlib.sha256(data).hexdigest(),"
                    "'content_b64':base64.b64encode(data).decode(),'truncated':False}))")
            for name in kvm_host.report_names("vz"):
                remote = str(root / "results" / name)
                try:
                    fetched = self.bristol([config["bristol_python"], "-c", code, remote])
                    data = kvm_host.fetched_report(fetched, remote)
                except ERRORS:
                    self.attempt.fail("report", lane="vz")
                    continue  # Retain other named reports before independent owned teardown.
                path = self.attempt.directory / "vz-private" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(data))
                if name == "installed-summary.json":
                    self.attempt.retain_lane("vz", path)

    def teardown_vz(self, receipt: dict, result: dict | None, archive: Path | None) -> None:
        config = self.config
        allocation = receipt["allocation"]
        root, state = Path(allocation["run_root"]), Path(allocation["state_parent"])
        try:
            if receipt["execution_started"]:
                # Lost SSH needs the separate, owner-bound cleanup operation.
                check = self.bristol(self.mac_arguments("verify" if result is not None else "cleanup", root, state), timeout=180)
                stopped = check["owner"] == self.attempt.data["owner"] and check["removed"] is True
                if result is not None:
                    stopped = stopped and result["cleanup"] == "verified"
                    if stopped:
                        released = self.bristol(self.mac_arguments("release", root, state), timeout=180)
                        stopped = released["owner"] == self.attempt.data["owner"] and released["removed"] is True
            else:
                # No candidate was launched. Recheck ports independently.
                self.bristol(self.mac_arguments("preflight", Path(config["bristol_runs"]), state))
                stopped = True
        except ERRORS:
            stopped = False
        try:
            build_removed = self.release_build()
            stopped = stopped and build_removed
            if archive is not None and result is not None and result.get("stage") != "transfer":
                archive.unlink()  # The verified host copy and retained input hashes replace redundant bytes.
        except ERRORS:
            stopped = False
        receipt["cleanup"] = "verified" if stopped else "failed"
        if not stopped:
            self.attempt.fail("cleanup", lane="vz")
        self.attempt.save()


def execute(config: dict, trigger: str, authorized_commit: str | None = None,
            *, github=None, hardware_type=PairedHardware) -> attempt_results.HardwareAttempt:
    """Announce before admission; serialize attempts without suppressing failures."""
    github = github or publish_results.GitHubResults()
    root = Path(config["attempts"])
    with publish_results.managed_attempt(root, config["controller_revision"], trigger, github) as attempt:
        with attempt.phase("selection"):
            service_calls.select_source(attempt, github, authorized_commit)
        with attempt.phase("preflight"):
            checked_controller(ROOT, config["controller_revision"])
            lock = (root / ".paired.lock").open("a")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                lock.close()
                raise
        try:
            hardware = hardware_type(config, attempt)
            for lane in ("kvm", "vz"):
                receipt = attempt.start_lane(lane)
                try:
                    with attempt.phase("execution", lane=lane):
                        getattr(hardware, f"run_{lane}")(receipt)
                except ERRORS:
                    # An independently cleaned failed lane does not erase its
                    # failure or prevent the other hardware result being retained.
                    pass  # The phase retained failure; cleanup is checked below before another lane.
                if receipt["cleanup"] != "verified":
                    break  # Do not overlap more resource use with failed teardown.
        finally:
            lock.close()
    return attempt


def recover_attempt(config: dict, directory: Path, *, github=None, hardware_type=PairedHardware):
    """Repair this failed attempt's owned teardown/outbox; never rerun tests."""
    checked_controller(ROOT, config["controller_revision"])
    attempt = attempt_results.HardwareAttempt.restore(directory)
    if attempt.data["controller_revision"] != config["controller_revision"]:
        raise ValueError("recovery must use the attempt's original trusted installation")
    github = github or publish_results.GitHubResults()
    with (Path(config["attempts"]) / ".paired.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        hardware = hardware_type(config, attempt)
        for lane, receipt in attempt.data["lanes"].items():
            if receipt["cleanup"] == "verified":
                continue
            try:
                if lane == "kvm":
                    for invocation in list(attempt.data.get("rundeck_executions", [])):
                        if not hardware.rundeck.state(invocation)["completed"]:
                            hardware.rundeck.abort(invocation)
                            hardware.rundeck.wait(invocation, 180)
                    check = hardware.rundeck_call("cleanup")
                else:
                    allocation = receipt["allocation"]
                    if receipt.get("execution_started") is False:
                        hardware.bristol(hardware.mac_arguments("preflight", Path(config["bristol_runs"]),
                                                               Path(allocation["state_parent"])))
                        check = {"owner": attempt.data["owner"], "removed": True}
                    else:
                        check = hardware.bristol(hardware.mac_arguments("cleanup", Path(allocation["run_root"]),
                                                                       Path(allocation["state_parent"])), timeout=180)
                stopped = check["owner"] == attempt.data["owner"] and check["removed"] is True
                if lane == "vz":
                    stopped = hardware.release_build() and stopped
            except ERRORS:
                stopped = False
            receipt["cleanup"] = "verified" if stopped else "failed"
            if not stopped:
                attempt.fail("cleanup", lane=lane)
        if not attempt.data["failures"]:
            attempt.fail("execution")  # An interrupted attempt cannot become a later pass.
        attempt.finish()
        publish_results.publish_attempt(attempt, github)
    return attempt


def interrupted(_signal, _frame):
    raise KeyboardInterrupt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trigger", choices=("overnight", "on-demand", "recover"))
    parser.add_argument("--config", type=Path, required=True, help="private operator deployment bindings")
    parser.add_argument("--authorized-commit", help="full commit explicitly selected by the trusted operator")
    parser.add_argument("--attempt", type=Path, help="original private attempt directory for owned cleanup/publication recovery")
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, interrupted)
    try:
        configuration = attempt_results.read_json(args.config)
        if args.trigger == "recover":
            if args.attempt is None or args.authorized_commit is not None:
                parser.error("recover needs the original --attempt and does not select source")
            attempt = recover_attempt(configuration, args.attempt.resolve())
        else:
            if args.attempt is not None:
                parser.error("new execution does not accept an earlier --attempt")
            attempt = execute(configuration, args.trigger, args.authorized_commit)
    except KeyboardInterrupt:
        print("Hardware attempt cancelled; inspect its published index and owned cleanup", file=sys.stderr)
        return 130
    except ERRORS as exc:
        print(f"Hardware attempt failed ({type(exc).__name__}); retained publication needs inspection", file=sys.stderr)
        return 2
    print(json.dumps({"run_id": attempt.data["run_id"], "source_revision": attempt.data["source_revision"],
                      "index": attempt.data["publication"]["index"]["url"], "passed": attempt.passed()}))
    return 0 if attempt.passed() else 2


if __name__ == "__main__":
    raise SystemExit(main())
