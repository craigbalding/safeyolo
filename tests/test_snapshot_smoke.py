"""Shell orchestration controls; fake helper results are not VZ acceptance."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "vm/test/snapshot-smoke.sh"


@pytest.fixture
def probe(tmp_path):
    guest = tmp_path / "guest"
    assets = tmp_path / "assets"
    binaries = tmp_path / "bin"
    for path in (guest, assets, binaries):
        path.mkdir()
    for name in ("Image", "initramfs.cpio.gz", "rootfs-base.ext4"):
        (guest / name).write_text(name)
    for name in ("guest-init", "guest-init-static", "guest-init-per-run", "safeyolo-guest"):
        (assets / name).write_text("#!/bin/bash\nexit 0\n")
    helper = binaries / "safeyolo-vm"
    helper.write_text(f"#!{sys.executable}\n" + r'''
import json, os, pathlib, signal, sys, time
if sys.argv[1:] == ['version']:
    print('fake helper for shell controls')
    sys.exit(0)
args = sys.argv[1:]
with open(os.environ['FAKE_ARGV'], 'a') as log:
    log.write(json.dumps(args) + '\n')
def value(flag):
    return args[args.index(flag) + 1]
run = pathlib.Path(value('--overlay')).parent
status = run / 'status'
if value('--memory') == '2048':
    print('snapshot/host hardware fingerprint mismatch (memoryMB=1024!=2048)', flush=True)
    sys.exit(75)
scenario = os.environ.get('FAKE_SCENARIO', 'complete')
if scenario == 'boot-exit':
    sys.exit(23)
save_requested = False
def request_save(*_):
    global save_requested
    save_requested = True
signal.signal(signal.SIGUSR1, request_save)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
(status / 'queued.txt').write_text('@reboot canary\njob 1 pending\n')
tick = int((status / 'quiet-ticks').read_text()) if (status / 'quiet-ticks').exists() else 0
(status / 'static-init-done').write_text('ready\n')
(status / 'probe.ready').write_text('ready\n')
while True:
    if save_requested:
        snap = pathlib.Path(value('--snapshot-on-signal'))
        snap.write_text('fake memory')
        pathlib.Path(str(snap) + '.meta.json').write_text('{"memoryMB":1024}')
        if scenario != 'missing-overlay':
            pathlib.Path(str(snap) + '.overlay').write_text('pristine paired overlay')
        if scenario == 'complete':
            print(f'Snapshot written to {snap} (overlay cloned to {snap}.overlay)', flush=True)
        if scenario == 'save-failed':
            print('Snapshot failed: injected save failure', flush=True)
        save_requested = False
    tick += 1
    temporary = status / 'quiet-ticks.tmp'
    temporary.write_text(str(tick) + '\n')
    temporary.replace(status / 'quiet-ticks')
    if (run / 'config/per-run-go').exists():
        if not pathlib.Path(value('--snapshot-on-signal') + '.overlay').exists():
            raise RuntimeError('gate opened without paired overlay')
        (status / 'per-run-started').write_text('ready\n')
        (status / 'jobs').write_text('cron uid=1000\nat uid=1000\n')
        (status / 'daemons').write_text('cron=100 atd=101\n')
        (status / 'probe.done').write_text('passed\n')
    time.sleep(0.05)
''')
    helper.chmod(0o755)
    # Avoid creating large overlay fixtures in shell-control tests.
    dd = binaries / "dd"
    dd.write_text('#!/bin/bash\nfor arg; do case "$arg" in of=*) printf seed > "${arg#of=}";; esac; done\n')
    dd.chmod(0o755)
    runner = binaries / "run-vz-test"
    runner.write_text(f"#!{sys.executable}\n" + '''
import signal, subprocess, sys
child = subprocess.Popen(sys.argv[4:])
def stop(*_):
    raise SystemExit(143)
signal.signal(signal.SIGTERM, stop)
try:
    sys.exit(child.wait(timeout=int(sys.argv[2])))
finally:
    if child.poll() is None:
        child.terminate()
        child.wait(timeout=2)
''')
    runner.chmod(0o755)
    argv_log = tmp_path / "argv.jsonl"
    env = {
        **os.environ,
        "PATH": f"{binaries}:{os.environ['PATH']}",
        "FAKE_ARGV": str(argv_log),
        "SAFEYOLO_SNAPSHOT_TIMEOUT_SECONDS": "2",
    }
    env.pop("SAFEYOLO_VZ_TEST_RUNNER", None)

    def run(mode="capture-only", scenario="complete", wrapped=False):
        output = tmp_path / "run"
        run_env = {**env, "FAKE_SCENARIO": scenario}
        if wrapped:
            run_env["SAFEYOLO_VZ_TEST_RUNNER"] = str(runner)
        result = subprocess.run(
            ["bash", str(SCRIPT), mode, str(helper), str(guest), str(assets), str(output)],
            env=run_env, capture_output=True, text=True, timeout=15,
        )
        calls = [json.loads(line) for line in argv_log.read_text().splitlines()] if argv_log.exists() else []
        return result, output, calls

    return run, guest, assets


def test_capture_waits_for_paired_completion_and_preserves_inputs(probe):
    run, guest, assets = probe
    result, output, calls = run()
    assert result.returncode == 0, result.stdout + result.stderr
    assert len(calls) == 1
    args = calls[0]
    assert "--restore-from" not in args
    assert "--no-terminal" not in args  # Keep the helper's supported signal mode.
    assert args[args.index("--rootfs") + 1] == str(guest / "rootfs-base.ext4")
    assert args[args.index("--overlay") + 1] == str(output / "overlay.ext4")
    shares = [args[i + 1] for i, flag in enumerate(args) if flag == "--share"]
    assert shares == [str(output / name) + f":{name}:{'ro' if name == 'config' else 'rw'}"
                      for name in ("config", "status", "home", "workspace")]
    assert (output / "capture.snap.overlay").read_text() == "pristine paired overlay"
    assert (output / "capture-jobs.txt").read_text().splitlines() == ["cron uid=1000", "at uid=1000"]
    assert "reaped=yes" in (output / "cleanup.log").read_text()
    assert (guest / "rootfs-base.ext4").read_text() == "rootfs-base.ext4"
    assert sorted(p.name for p in assets.iterdir()) == ["guest-init", "guest-init-per-run", "guest-init-static", "safeyolo-guest"]


@pytest.mark.parametrize("scenario", ["missing-overlay", "save-failed", "boot-exit"])
def test_failed_capture_keeps_diagnostics_and_gate_closed(probe, scenario):
    run, _, _ = probe
    result, output, calls = run(scenario=scenario)
    assert result.returncode == 1, result.stdout + result.stderr
    assert len(calls) == 1
    assert not (output / "config/per-run-go").exists()
    assert (output / "capture-helper.log").exists()
    assert (output / "inputs.sha256").exists()
    assert "reaped=yes" in (output / "cleanup.log").read_text()
    assert (output / "exit").read_text() == "exit=1\n"


def test_full_uses_fresh_overlay_copies_and_meaningful_fingerprint_refusal(probe):
    run, guest, _ = probe
    result, output, calls = run(mode="full")
    assert result.returncode == 0, result.stdout + result.stderr
    assert len(calls) == 3
    for args, overlay, memory in zip(calls, ("overlay.ext4", "restore.overlay.ext4", "boundary.overlay.ext4"), ("1024", "1024", "2048"), strict=True):
        assert args[args.index("--rootfs") + 1] == str(guest / "rootfs-base.ext4")
        assert args[args.index("--overlay") + 1] == str(output / overlay)
        assert args[args.index("--memory") + 1] == memory
        assert args.count("--memory") == 1
    for args in calls[1:]:
        assert args[args.index("--restore-from") + 1] == str(output / "capture.snap")
    assert (output / "capture.snap.overlay").read_text() == "pristine paired overlay"
    assert "OK" in (output / "paired-overlay-check.txt").read_text()
    assert (output / "liveness.snap.meta.json").is_file()


def test_existing_attempt_is_not_overwritten(probe):
    run, _, _ = probe
    first, output, _ = run()
    assert first.returncode == 0
    original = (output / "capture-helper.log").read_bytes()
    second, _, calls = run()
    assert second.returncode != 0
    assert len(calls) == 1
    assert (output / "capture-helper.log").read_bytes() == original


def test_runner_owns_helper_but_only_helper_receives_snapshot_signal(probe):
    run, _, _ = probe
    result, output, calls = run(wrapped=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert len(calls) == 1
    ids = dict(field.split("=") for field in (output / "pids.txt").read_text().split())
    assert ids["runner"] != ids["helper"]
    assert "exit=143 reaped=yes" in (output / "cleanup.log").read_text()


@pytest.mark.parametrize("scheduler,status", [("cron", 0), ("atd", 0), ("cron", 2)])
def test_guest_observer_refuses_daemons_and_failed_process_reads(tmp_path, scheduler, status):
    """Exercise the guest shell's refusal before release, with owned fake tools."""
    root = tmp_path / "guest"
    for name in ("status", "config", "run", "bin", "spool"):
        (root / name).mkdir(parents=True, exist_ok=True)
    commands = {
        "su": '#!/bin/bash\nexec /bin/bash -c "${@: -1}"\n',
        "crontab": '''#!/bin/bash
case "$1" in
-l) if [[ -f "$FAKE_SPOOL/crontab" ]]; then cat "$FAKE_SPOOL/crontab"; else echo 'no crontab for agent' >&2; exit 1; fi;;
-r) rm "$FAKE_SPOOL/crontab";;
*) cp "$1" "$FAKE_SPOOL/crontab";;
esac
''',
        "at": '#!/bin/bash\ncat >/dev/null\ntouch "$FAKE_SPOOL/pending"\necho "job 1 at now" >&2\n',
        "atq": '#!/bin/bash\nif [[ -f "$FAKE_SPOOL/pending" ]]; then echo "1 pending"; fi\n',
        "atrm": '#!/bin/bash\nrm "$FAKE_SPOOL/pending"\n',
        "pgrep": f'#!/bin/bash\nif [[ "$2" = {scheduler} ]]; then echo 123; exit {status}; fi\nexit 1\n',
    }
    for name, source in commands.items():
        tool = root / "bin" / name
        tool.write_text(source)
        tool.chmod(0o755)
    source = (ROOT / "vm/test/snapshot-scheduling.sh").read_text()
    # The probe's real guest paths are replaced only in this unit fixture.
    source = source.replace("/safeyolo-status", str(root / "status"))
    source = source.replace("/run/safeyolo", str(root / "run"))
    source = source.replace("/safeyolo/", str(root / "config") + "/")
    source = source.replace("/var/log/safeyolo-scheduling.log", str(root / "scheduling.log"))
    script = root / "probe.sh"
    script.write_text(source)
    result = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, timeout=5,
        env={**os.environ, "PATH": f"{root / 'bin'}:{os.environ['PATH']}", "FAKE_SPOOL": str(root / "spool")},
    )
    assert result.returncode != 0
    assert (root / "status/probe.failed").is_file()
    assert not (root / "status/probe.ready").exists()
    assert not (root / "status/probe.done").exists()
    assert not list((root / "spool").iterdir())
