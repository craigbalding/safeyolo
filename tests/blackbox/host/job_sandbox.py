"""Exercise disposable jobs on a prepared Linux or physical macOS instance.

On the selected host, supply the candidate CLI and a disposable installed root:
python3 tests/blackbox/host/job_sandbox.py --cli /path/to/safeyolo --instance-dir /path/to/instance --scratch /disk/backed/directory
The root must already select the shared Trixie guest and native launcher.
For macOS, also supply --observer-probe /path/to/arm64-linux-static-probe.
Build that small test executable on Linux as documented in tests/fixtures/job-observer-probe.c.
This runs fixed local checks without starting a coding agent or contacting services.
Successful output names each observed boundary. Failure retains the scratch path.
"""

import argparse
import base64
import hashlib
import http.client
import json
import os
import runpy
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from execution_receipt import ProcedureReceipt


def network_off(job, receipt, port=0):
    """Pair direct guest TCP attempts with an independently functioning sink."""
    hits = []

    class Receiver(BaseHTTPRequestHandler):
        timeout = 3
        def do_GET(self):
            hits.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *unused):
            pass  # The sanitized path inventory replaces request logging.

    class ReceiverServer(HTTPServer):
        accepts = 0

        def get_request(self):
            connection, address = super().get_request()
            self.accepts += 1
            connection.settimeout(3)
            return connection, address

    with ReceiverServer(("127.0.0.1", port), Receiver) as sink:
        thread = threading.Thread(target=sink.serve_forever)
        thread.start()
        try:
            connection = http.client.HTTPConnection(*sink.server_address, timeout=3)
            try:
                connection.request("GET", "/host-positive")
                response = connection.getresponse()
                assert response.status == 200 and response.read() == b"ok"
            finally:
                connection.close()
            for privilege in ("unprivileged", "guest-root"):
                program = f'''if exec 3<>/dev/tcp/127.0.0.1/{sink.server_port}; then
                    printf 'GET /job-{privilege} HTTP/1.0\\r\\n\\r\\n' >&3 || true
                    exit 1
                fi'''
                _, result = job(program, privilege=privilege)
                assert result["outcome"] == {"kind": "exit", "code": 0}, result
            connection = http.client.HTTPConnection(*sink.server_address, timeout=3)
            try:
                connection.request("GET", "/host-positive-after")
                response = connection.getresponse()
                assert response.status == 200 and response.read() == b"ok"
            finally:
                connection.close()
            assert hits == ["/host-positive", "/host-positive-after"] and sink.accepts == 2, (hits, sink.accepts)
            receipt.checkpoint("network-off", receiver_hits=hits, accepts=sink.accepts, privileges=["unprivileged", "guest-root"])
        finally:
            sink.shutdown()
            thread.join(timeout=5)
            assert not thread.is_alive(), "network-off receiver did not stop"


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


def observe_backend(record):
    """Reuse the installed runner's live backend and process-birth checks."""
    probe = runpy.run_path(str(Path(__file__).resolve().parents[1] / "assert-platform.py"))
    observed = probe["running_platform"](record.parents[2], record.parent.name)
    expected = os.environ.get("SAFEYOLO_BLACKBOX_LANE")
    if expected is not None and observed["platform"] != expected:
        raise ValueError("job used another backend")
    return observed


def interrupt_request(command, root: Path, signal_number: int | None, *, umask=-1):
    """Signal the owned caller after its live backend identity is verified."""
    before = job_directories(root)
    records = []
    observed = []
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, umask=umask,
                          env=dict(os.environ, SAFEYOLO_DANGEROUSLY_ALLOW_ROOT="1")) as child:
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
                    try:
                        pending = False
                        observed = []
                        for record in records:
                            run = json.loads(record.read_text())
                            # jobs.rs publishes this owned starting record
                            # before start_job_sandbox supplies the backend.
                            if (run.get("state") == "starting"
                                    and run.get("name") == run.get("agent_id") == record.parent.name
                                    and run.get("backend_pid") is None and run.get("backend_token") is None):
                                pending = True
                            else:
                                observed.append(observe_backend(record))
                    except (OSError, ValueError, KeyError) as error:
                        # Keep the native result and streams before the caller
                        # rejects this missing observer evidence.
                        observed = [{"error": str(error)}]
                        child.terminate()
                        break
                    else:
                        if not pending:
                            if signal_number is not None:
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
        return subprocess.CompletedProcess(command, child.returncode, stdout, stderr), records, observed


def run(cli: Path, root: Path, scratch: Path, signals_only: bool = False, observer_probe: Path | None = None,
        receipt=None, receiver_port=0) -> None:
    """Keep normal installed state unchanged while exercising real job runs."""
    protected = [root / "config.toml", root / "policy.toml"]
    original = {path: path.read_bytes() for path in protected if path.is_file()}
    jobs_before = job_directories(root)
    receipt = receipt or ProcedureReceipt("job-sandbox", scratch / "result.json")
    receipt.checkpoint("identity", cli=subprocess.check_output([str(cli), "--version"], text=True).strip())
    input_dir = scratch / "input"
    input_dir.mkdir()
    (input_dir / "candidate").write_text("read-only candidate\n")
    if observer_probe is not None:
        shutil.copyfile(observer_probe, input_dir / "observer-probe")
        (input_dir / "observer-probe").chmod(0o755)
    input_bytes = sum(path.stat().st_size for path in input_dir.iterdir())
    job_number = 0
    runtimes = []

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
        command = [str(cli), "--instance-dir", str(root), "--json", "job", "run", str(spec_path), "--input", str(input_dir)]
        records = []
        try:
            completed, records, observed = interrupt_request(command, root, interrupt_signal)
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
            "observed_backends": observed,
        }))
        assert observed and all("error" not in item for item in observed), "job did not retain a verified live backend"
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
        runtimes.append({**{key: result[key] for key in ("run_id", "engine", "rootfs", "input_sha256")}, "backends": observed})
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
    receipt.checkpoint("inputs", job=runtimes[-1])

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
    receipt.checkpoint("privilege-state", jobs=runtimes[-2:])

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
    receipt.checkpoint("exit-signal")

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
    receipt.checkpoint("timeout")

    caller_signals()
    receipt.checkpoint("caller-signals")
    network_off(job, receipt, receiver_port)
    assert job_directories(root) == jobs_before
    receipt.checkpoint("cleanup", jobs=runtimes)
    receipt.checkpoint("finished")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--instance-dir", dest="root", type=Path, required=True)
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
