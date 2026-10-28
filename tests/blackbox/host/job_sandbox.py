"""Exercise disposable jobs on a prepared Linux or physical macOS instance.

On the selected host, supply the candidate CLI and a disposable installed root:
python3 tests/blackbox/host/job_sandbox.py --cli /path/to/safeyolo --root /path/to/instance --scratch /disk/backed/directory
The root must already select the shared Trixie guest and native launcher.
This runs fixed local checks without starting a coding agent or contacting services.
Successful output names each observed boundary. Failure retains the scratch path.
"""

import argparse
import base64
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path


def run(cli: Path, root: Path, scratch: Path) -> None:
    """Keep normal installed state unchanged while exercising real job runs."""
    protected = [root / "config.toml", root / "policy.toml"]
    original = {path: path.read_bytes() for path in protected if path.is_file()}
    jobs_before = set((root / "data").glob("job-*"))
    input_dir = scratch / "input"
    input_dir.mkdir()
    (input_dir / "candidate").write_text("read-only candidate\n")
    job_number = 0

    def job(program: str, *, privilege: str = "unprivileged", timeout: int = 30):
        nonlocal job_number
        job_number += 1
        prefix = scratch / f"job-{job_number:02d}"
        spec_path = prefix.with_suffix(".spec.json")
        spec_path.write_text(
            json.dumps(
                {
                    "gate_id": "job-boundary-probe",
                    "argv": ["/usr/bin/python3", "-c", program],
                    "timeout_seconds": timeout,
                    "max_input_bytes": 1024,
                    "max_input_entries": 32,
                    "retain_bytes": 8192,
                    "memory_mb": 512,
                    "privilege": privilege,
                }
            )
        )
        try:
            completed = subprocess.run(
                [str(cli), "--root", str(root), "job", "run", str(spec_path), "--input", str(input_dir)],
                capture_output=True,
                timeout=180,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            prefix.with_suffix(".stdout").write_bytes(error.stdout or b"")
            prefix.with_suffix(".stderr").write_bytes(error.stderr or b"")
            prefix.with_suffix(".cli-result.json").write_text(json.dumps({"timeout": True}))
            raise
        prefix.with_suffix(".stdout").write_bytes(completed.stdout)
        prefix.with_suffix(".stderr").write_bytes(completed.stderr)
        prefix.with_suffix(".cli-result.json").write_text(json.dumps({"returncode": completed.returncode}))
        result = json.loads(completed.stdout)
        assert result["gate_principal"] == "gate:job-boundary-probe", result
        assert result["authorization_principal"] is None, result
        assert len(result["rootfs"]["sha256"]) == 64, result
        assert len(result["input_sha256"]) == 64, result
        assert len(result["gate_definition_sha256"]) == 64, result
        assert set((root / "data").glob("job-*")) == jobs_before
        for path, content in original.items():
            assert path.read_bytes() == content, path
        assert (input_dir / "candidate").read_text() == "read-only candidate\n"
        return completed.returncode, result

    _, default = job("""
import json, os, pathlib, subprocess
status = dict(line.split(':', 1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
assert os.getuid() == os.getgid() == 1000
assert status['NoNewPrivs'].strip() == '1'
for field in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'):
    assert int(status[field], 16) == 0, (field, status[field])
for argv in (['sudo', '-n', 'id', '-u'], ['/usr/bin/sudo', '-n', 'id', '-u'], ['setpriv', '--reuid=0', '--regid=0', '--clear-groups', 'id', '-u']):
    result = subprocess.run(argv, capture_output=True, check=False)
    assert result.returncode != 0, (argv, result.stdout)
try:
    pathlib.Path('/input/candidate').write_text('mutated')
except OSError:
    pass
else:
    raise AssertionError('input was writable')
for path in ('/app/agent_token', '/safeyolo/agent_token', '/safeyolo/skills', '/home/agent/.safeyolo-command'):
    assert not pathlib.Path(path).exists(), path
assert not any(key.endswith('PROXY') or key.startswith('SAFEYOLO_') for key in os.environ)
assert pathlib.Path('/input/candidate').read_text() == 'read-only candidate\\n'
pathlib.Path('/home/agent/job-marker').write_text('transient')
pathlib.Path('/work/job-marker').write_text('transient')
print(json.dumps({'uid': os.getuid(), 'gid': os.getgid(), 'NoNewPrivs': status['NoNewPrivs'].strip()}))
""")
    assert default["outcome"] == {"kind": "exit", "code": 0}, default
    print("PASS default identity, capability clearing, sudo/setuid refusal, read-only inputs, no agent authority")

    _, root_result = job(
        """
import os, pathlib
assert os.getuid() == 0
assert not pathlib.Path('/home/agent/job-marker').exists()
assert not pathlib.Path('/work/job-marker').exists()
pathlib.Path('/etc/job-root-marker').write_text('transient')
""",
        privilege="guest-root",
    )
    assert root_result["outcome"] == {"kind": "exit", "code": 0}, root_result
    _, fresh = job("import pathlib; assert not pathlib.Path('/etc/job-root-marker').exists()")
    assert fresh["outcome"] == {"kind": "exit", "code": 0}, fresh
    print("PASS explicit guest root and discarded root/home/work state")

    _, high_exit = job("raise SystemExit(139)")
    _, signalled = job("import os, signal; os.kill(os.getpid(), signal.SIGSEGV)")
    assert high_exit["outcome"] == {"kind": "exit", "code": 139}, high_exit
    assert signalled["outcome"] == {"kind": "signal", "number": 11}, signalled
    code, printed = job("print('PASS'); raise SystemExit(17)")
    assert code != 0 and printed["outcome"] == {"kind": "exit", "code": 17}, printed
    print("PASS real exit139 versus SIGSEGV and printed PASS has no acceptance authority")

    code, timed_out = job(
        "import os,time; os.write(1,b'A'*100000); os.write(2,b'B'*100000); time.sleep(300)", timeout=2
    )
    assert code == 124 and timed_out["outcome"] == {"kind": "timeout"}, timed_out
    for stream, byte in (("stdout", b"A"), ("stderr", b"B")):
        output = timed_out[stream]
        assert output["bytes"] == 100000, output
        assert output["sha256"] == hashlib.sha256(byte * 100000).hexdigest(), output
        assert base64.b64decode(output["retained_base64"]) == byte * 8192, output
    print("PASS timeout, bounded retained output, complete stream hashes and owned teardown")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    args = parser.parse_args()
    scratch = Path(tempfile.mkdtemp(prefix="job-probe-", dir=args.scratch))
    print(f"scratch={scratch}", flush=True)
    run(args.cli.resolve(strict=True), args.root.resolve(strict=True), scratch)


if __name__ == "__main__":
    main()
