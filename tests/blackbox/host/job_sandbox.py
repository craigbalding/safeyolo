"""Exercise disposable jobs on a prepared Linux or physical macOS instance.

On the selected host, supply the candidate CLI and a disposable installed root:
python3 tests/blackbox/host/job_sandbox.py --cli /path/to/safeyolo --root /path/to/instance --scratch /disk/backed/directory
The root must already select the shared Trixie guest and native launcher.
For macOS, also supply --observer-probe /path/to/arm64-linux-static-probe.
Build that small test executable on Linux as documented in tests/fixtures/job-observer-probe.c.
This runs fixed local checks without starting a coding agent or contacting services.
Successful output names each observed boundary. Failure retains the scratch path.
"""

import argparse
import base64
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def job_directories(root: Path):
    """Select this instance's transient roots, including macOS short UDS paths."""
    parent = Path(os.environ.get("TMPDIR", "/tmp")) if sys.platform == "darwin" else root / "data"
    config = (root / "config.toml").resolve(strict=True)
    result = set()
    for directory in parent.glob("job-*"):
        try:
            if directory.stat().st_uid != os.geteuid():
                continue
            link = directory / "config.toml"
            if link.is_symlink() and link.resolve(strict=True) == config:
                result.add(directory)
        except (FileNotFoundError, NotADirectoryError):
            # A concurrent job can finish between enumeration and symlink lookup.
            continue
    return result


def interrupt_request(command, root: Path, signal_number: int):
    """Signal the owned caller after its host runtime record is published."""
    before = job_directories(root)
    records = []
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
        deadline = time.monotonic() + 180
        try:
            while child.poll() is None:
                records = [
                    path
                    for directory in job_directories(root) - before
                    for path in directory.glob("agents/job-*/runtime.json")
                    if path.is_file()
                ]
                if records:
                    child.send_signal(signal_number)
                    break
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(command, 180)
                time.sleep(0.05)
            stdout, stderr = child.communicate(timeout=max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as error:
            child.terminate()
            try:
                stdout, stderr = child.communicate(timeout=180)
            except subprocess.TimeoutExpired:
                child.kill()
                stdout, stderr = child.communicate()
            raise subprocess.TimeoutExpired(command, error.timeout, output=stdout, stderr=stderr) from error
        finally:
            # Reap the owned caller if the fixture's filesystem observer fails.
            # Give native teardown its normal bound before the last-resort kill.
            if child.poll() is None:
                child.terminate()
                try:
                    child.communicate(timeout=180)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.communicate()
        return subprocess.CompletedProcess(command, child.returncode, stdout, stderr), records


def run(cli: Path, root: Path, scratch: Path, signals_only: bool = False, observer_probe: Path | None = None) -> None:
    """Keep normal installed state unchanged while exercising real job runs."""
    protected = [root / "config.toml", root / "policy.toml"]
    original = {path: path.read_bytes() for path in protected if path.is_file()}
    jobs_before = job_directories(root)
    input_dir = scratch / "input"
    input_dir.mkdir()
    (input_dir / "candidate").write_text("read-only candidate\n")
    if observer_probe is not None:
        shutil.copyfile(observer_probe, input_dir / "observer-probe")
        (input_dir / "observer-probe").chmod(0o755)
    input_bytes = sum(path.stat().st_size for path in input_dir.iterdir())
    job_number = 0

    def job(program: str, *, privilege: str = "unprivileged", timeout: int = 30, interrupt_signal=None):
        nonlocal job_number
        job_number += 1
        prefix = scratch / f"job-{job_number:02d}"
        spec_path = prefix.with_suffix(".spec.json")
        spec_path.write_text(
            json.dumps(
                {
                    "gate_id": "job-boundary-probe",
                    "argv": ["/bin/bash", "-euo", "pipefail", "-c", program],
                    "timeout_seconds": timeout,
                    "max_input_bytes": input_bytes,
                    "max_input_entries": 32,
                    "retain_bytes": 8192,
                    "memory_mb": 512,
                    "privilege": privilege,
                    "network": False,
                }
            )
        )
        command = [str(cli), "--root", str(root), "job", "run", str(spec_path), "--input", str(input_dir)]
        records = []
        try:
            if interrupt_signal is None:
                completed = subprocess.run(command, capture_output=True, timeout=180, check=False)
            else:
                completed, records = interrupt_request(command, root, interrupt_signal)
        except subprocess.TimeoutExpired as error:
            prefix.with_suffix(".stdout").write_bytes(error.stdout or b"")
            prefix.with_suffix(".stderr").write_bytes(error.stderr or b"")
            prefix.with_suffix(".cli-result.json").write_text(json.dumps({"timeout": True}))
            raise
        prefix.with_suffix(".stdout").write_bytes(completed.stdout)
        prefix.with_suffix(".stderr").write_bytes(completed.stderr)
        prefix.with_suffix(".cli-result.json").write_text(json.dumps({
            "returncode": completed.returncode,
            "interrupt_signal": interrupt_signal,
            "observed_runtime_records": [str(path) for path in records],
        }))
        result = json.loads(completed.stdout)
        if interrupt_signal is not None:
            assert len(records) == 1, records
            assert result["run_id"] == records[0].parent.name, result
        assert result["gate_principal"] == "gate:job-boundary-probe", result
        assert result["authorization_principal"] is None, result
        assert result["observation_error"] is None, result
        assert len(result["rootfs"]["sha256"]) == 64, result
        assert len(result["input_sha256"]) == 64, result
        assert len(result["gate_definition_sha256"]) == 64, result
        assert job_directories(root) == jobs_before
        for path, content in original.items():
            assert path.read_bytes() == content, path
        assert (input_dir / "candidate").read_text() == "read-only candidate\n"
        return completed.returncode, result

    def caller_signals():
        for number, privilege in ((signal.SIGINT, "unprivileged"), (signal.SIGTERM, "guest-root")):
            code, interrupted = job("exec sleep 300", privilege=privilege, interrupt_signal=number)
            assert code == 1 and interrupted["outcome"] == {"kind": "interrupted", "signal": number}, interrupted
        print("PASS caller SIGINT/SIGTERM after runtime publication and owned teardown")

    if signals_only:
        caller_signals()
        return

    _, default = job(r"""
test "$(id -u):$(id -g)" = 1000:1000
declare -A status
while read -r field value rest; do
    status[$field]=$value
done < /proc/self/status
test "${status[NoNewPrivs:]}" = 1
for field in CapInh: CapPrm: CapEff: CapBnd: CapAmb:; do
    test "${status[$field]}" = 0000000000000000
done
if sudo -n id -u; then exit 1; fi
if /usr/bin/sudo -n id -u; then exit 1; fi
if setpriv --reuid=0 --regid=0 --clear-groups id -u; then exit 1; fi
if (printf mutated > /input/candidate); then exit 1; fi
for path in /app/agent_token /safeyolo/agent_token /safeyolo/skills /home/agent/.safeyolo-command; do
    test ! -e "$path"
done
while IFS= read -r variable; do
    case "$variable" in *PROXY|SAFEYOLO_*) exit 1 ;; esac
done < <(compgen -e)
test "$(cat /input/candidate)" = 'read-only candidate'
printf transient > /home/agent/job-marker
printf transient > /work/job-marker
printf 'uid=1000 gid=1000 NoNewPrivs=1\n'
""")
    assert default["outcome"] == {"kind": "exit", "code": 0}, default
    print("PASS default identity, capability clearing, sudo/setuid refusal, read-only inputs, no agent authority")

    root_program = """
test "$(id -u)" = 0
test ! -e /home/agent/job-marker
test ! -e /work/job-marker
printf transient > /etc/job-root-marker
"""
    if sys.platform == "darwin":
        if observer_probe is None:
            raise ValueError("macOS proof needs --observer-probe built for the Linux guest architecture")
        root_program += """
read -r inside outside count < /proc/self/uid_map
test "$inside:$outside:$count" = 0:65536:65536
chown 1234:1234 /etc/job-root-marker
test "$(stat -c '%u:%g' /etc/job-root-marker)" = 1234:1234
mkdir /work/root-mount
mount -t tmpfs tmpfs /work/root-mount
printf 'root mount works' > /work/root-mount/file
umount /work/root-mount
test ! -e /.observer-root
exec /input/observer-probe
"""
    _, root_result = job(root_program, privilege="guest-root")
    assert root_result["outcome"] == {"kind": "exit", "code": 0}, root_result
    _, fresh = job("test ! -e /etc/job-root-marker")
    assert fresh["outcome"] == {"kind": "exit", "code": 0}, fresh
    print("PASS explicit guest root and discarded root/home/work state")

    _, high_exit = job("exit 139")
    _, signalled = job("kill -s SEGV $$")
    assert high_exit["outcome"] == {"kind": "exit", "code": 139}, high_exit
    assert signalled["outcome"] == {"kind": "signal", "number": 11}, signalled
    code, printed = job("printf 'PASS\\n'; exit 17")
    assert code != 0 and printed["outcome"] == {"kind": "exit", "code": 17}, printed
    if sys.platform == "darwin":
        for signal_number in (7, 64):
            _, generic = job(f"kill -s {signal_number} $$")
            assert generic["outcome"] == {"kind": "signal", "number": signal_number}, generic
    print("PASS real exit139 versus SIGSEGV and printed PASS has no acceptance authority")

    code, timed_out = job(
        "head -c 100000 /dev/zero | tr '\\0' A; head -c 100000 /dev/zero | tr '\\0' B >&2; exec sleep 300", timeout=2
    )
    assert code == 124 and timed_out["outcome"] == {"kind": "timeout"}, timed_out
    for stream, byte in (("stdout", b"A"), ("stderr", b"B")):
        output = timed_out[stream]
        assert output["bytes"] == 100000, output
        assert output["sha256"] == hashlib.sha256(byte * 100000).hexdigest(), output
        assert base64.b64decode(output["retained_base64"]) == byte * 8192, output
    print("PASS timeout, bounded retained output, complete stream hashes and owned teardown")

    caller_signals()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--signals-only", action="store_true", help="Run caller SIGINT/SIGTERM checks without repeating other rows.")
    parser.add_argument("--observer-probe", type=Path, help="Static Linux probe for the macOS guest, built from tests/fixtures/job-observer-probe.c.")
    args = parser.parse_args()
    scratch = Path(tempfile.mkdtemp(prefix="job-probe-", dir=args.scratch))
    print(f"scratch={scratch}", flush=True)
    if sys.platform == "darwin" and not args.signals_only and args.observer_probe is None:
        parser.error("macOS proof requires --observer-probe")
    observer_probe = args.observer_probe.resolve(strict=True) if args.observer_probe else None
    run(args.cli.resolve(strict=True), args.root.resolve(strict=True), scratch, args.signals_only, observer_probe)


if __name__ == "__main__":
    main()
