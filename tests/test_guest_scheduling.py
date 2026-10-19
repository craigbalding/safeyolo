"""Real tmux examples and opt-in cron/at image probes.

The daemon probe needs a standard rootfs built by guest/build-rootfs.sh and
guest-local root. It runs in owned chroots within the Linux test sandbox.
It does not claim an installed runsc/VZ restart or snapshot result.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
EXAMPLES = REPO / "cli/src/safeyolo/agent_context/skills/safeyolo/scripts"
ROOTFS = os.environ.get("SAFEYOLO_SCHEDULING_ROOTFS")


def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=15, **kwargs)


def eventually(check, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if result := check():
            return result
        time.sleep(0.1)
    raise AssertionError("expected scheduler result did not arrive")


def test_tmux_example_checks_exact_pane_and_sends_literal_text(tmp_path):
    """A missing window must fail even when tmux display falls back to active."""
    if not shutil.which("tmux"):
        pytest.skip("tmux is needed for the real pane probe")
    server = tmp_path / "tmux.sock"
    other_server = tmp_path / "other.sock"

    def tmux(*args):
        return run("tmux", "-S", str(server), *args).stdout

    script = tmp_path / "send.sh"
    script.write_text((EXAMPLES / "scheduled-tmux.sh").read_text().replace(
        "/home/agent/.local/state/tmux/scheduled.sock", str(server)))
    tmux("new-session", "-d", "-s", "scheduled", "-n", "input", "cat")
    run("tmux", "-S", str(other_server), "new-session", "-d", "-s", "scheduled", "-n", "input", "cat")
    try:
        tmux("new-window", "-t", "scheduled:1", "-n", "input-other", "cat")
        tmux("select-window", "-t", "scheduled:input-other")
        other_pid = run("tmux", "-S", str(other_server), "display-message", "-p", "#{pid}").stdout.strip()
        run("sh", str(script), env={**os.environ, "TMUX": f"{other_server},{other_pid},0"})
        literal = "Please inspect $HOME; [literal text]."
        eventually(lambda: literal in tmux("capture-pane", "-p", "-t", "scheduled:input.0"))
        assert literal not in tmux("capture-pane", "-p", "-t", "scheduled:input-other.0")
        assert literal not in run("tmux", "-S", str(other_server), "capture-pane", "-p",
                                  "-t", "scheduled:input.0").stdout
        tmux("kill-window", "-t", "scheduled:input")
        absent = subprocess.run(["sh", str(script)], capture_output=True, text=True, timeout=5)
        assert absent.returncode != 0
        assert "tmux target" in absent.stderr
        assert literal not in tmux("capture-pane", "-p", "-t", "scheduled:input-other.0")
    finally:
        tmux("kill-server")
        run("tmux", "-S", str(other_server), "kill-server")


@pytest.fixture
def image(tmp_path):
    if not ROOTFS or os.geteuid() != 0:
        pytest.skip("set SAFEYOLO_SCHEDULING_ROOTFS to a built tree and run with guest sudo")
    root = tmp_path / "guest"
    shutil.copytree(ROOTFS, root, symlinks=True)
    # Emulate the Linux tree's uid mapping back to guest-root, without changing
    # package metadata in the original build outputs.
    run("chown", "-R", "0:0", str(root))
    for path in ("run/safeyolo", "safeyolo", "home/agent/jobs", "workspace", "app"):
        (root / path).mkdir(parents=True, exist_ok=True)
    run("chown", "-R", "1000:1000", str(root / "home/agent"), str(root / "workspace"))
    # chroot has no devtmpfs. This finite sink supplies the /dev/null interface
    # used by the command probes; native guest startup supplies the real device.
    (root / "dev/null").touch()
    (root / "dev/null").chmod(0o666)
    for name in ("safeyolo-job", "safeyolo-schedule-command", "safeyolo-scheduling.sh"):
        built = root / ({"safeyolo-job": "usr/local/bin/safeyolo-job",
                         "safeyolo-schedule-command": "usr/local/bin/at",
                         "safeyolo-scheduling.sh": "usr/local/lib/safeyolo/scheduling.sh"}[name])
        assert built.read_bytes() == (REPO / "guest/rootfs" / name).read_bytes(), name
    return root


def agent(root, command, **kwargs):
    return run("chroot", str(root), "/usr/bin/setpriv", "--reuid=1000", "--regid=1000",
               "--clear-groups", "--inh-caps=+setuid,+setgid", "--ambient-caps=+setuid,+setgid",
               "/bin/sh", "-c", "cd /home/agent; " + command, **kwargs)


@contextmanager
def daemons(root):
    ready = root / "run/safeyolo/probe-ready"
    ready.unlink(missing_ok=True)
    # /dev is fresh on each real sandbox boot. Remove the previous owned
    # fixture syslog socket after its daemon has stopped.
    (root / "dev/log").unlink(missing_ok=True)
    process = subprocess.Popen(["chroot", str(root), "/bin/bash", "-c", '''
set -e
. /usr/local/lib/safeyolo/scheduling.sh
trap 'stop_guest_schedulers; exit' TERM INT
start_guest_schedulers
printf '%s\n' "$CRON_PID" "$ATD_PID" "$SCHEDULER_SYSLOG_PID" > /run/safeyolo/probe-pids
touch /run/safeyolo/probe-ready
while :; do check_guest_schedulers; sleep 0.25 & wait $! || true; done
'''], start_new_session=True)
    try:
        eventually(lambda: ready.exists() or process.poll() is not None)
        assert process.poll() is None
        yield [int(pid) for pid in (root / "run/safeyolo/probe-pids").read_text().split()]
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
            raise AssertionError("fixture scheduler owner did not stop") from None


def test_gate_stays_quiet_and_built_image_has_no_jobs(image):
    """A closed capture gate must leave both real daemons unstarted."""
    assert not list((image / "var/spool/cron/crontabs").iterdir())
    assert not [line for line in (image / "etc/crontab").read_text().splitlines()
                if line.strip() and not line.startswith("#")]
    with daemons(image) as pids:
        assert pids == []
        assert "per-run gate is closed" in (image / "var/log/safeyolo-scheduling.log").read_text()


def test_real_cron_at_restart_environment_coord_and_failures(image, tmp_path):
    """Run real daemons and native Coord in owned state, with no model calls."""
    from tests.proxy_contracts.test_native_coord_operator import POLICY, cli, history
    from tests.proxy_contracts.test_native_policy_cli import AGENT_TOKEN, native_instance

    (image / "safeyolo/per-run-go").touch()
    with daemons(image):
        pass  # Establish the package spool permissions before submission.
    job = image / "home/agent/jobs/report.sh"
    job.write_text('''#!/bin/sh
set -eu
/bin/sh /home/agent/jobs/post-coord.sh
printf '%s uid=%s cwd=%s home=%s env=%s\n' "$1" "$(id -u)" "$PWD" "$HOME" "$SCHEDULING_FIXTURE" >> /home/agent/jobs/observed
''')
    shutil.copyfile(EXAMPLES / "scheduled-coord.sh", image / "home/agent/jobs/post-coord.sh")
    (image / "home/agent/jobs/coord-message.json").write_text(json.dumps({
        "body": "owned-scheduling-probe", "declared_content_type": "text/plain", "notify": "none"}))
    (image / "app/agent_token").write_text("obsolete-fixture-token")
    agent(image, "printf '%s\\n' 'MAILTO=\"\"' '@reboot /usr/bin/touch /home/agent/jobs/reboot' '* * * * * /usr/local/bin/safeyolo-job /bin/sh /home/agent/jobs/report.sh cron >>/home/agent/jobs/cron.log 2>&1' | crontab -")
    agent(image, "HTTP_PROXY=http://127.0.0.1:1 SCHEDULING_FIXTURE=old at -M now <<'JOB'\n/usr/local/bin/safeyolo-job /bin/sh /home/agent/jobs/report.sh at >>/home/agent/jobs/at.log 2>&1\nJOB")
    cancellation = agent(image, "printf '%s\\n' 'touch /home/agent/jobs/should-not-run' | at -M now")
    cancel_id = cancellation.stderr.split("job ")[1].split()[0]
    agent(image, f"atrm {cancel_id}")
    assert cancel_id not in {line.split()[0] for line in agent(image, "atq").stdout.splitlines()}
    assert "report.sh" in agent(image, "crontab -l").stdout

    # Reuse the maintained native fixture. This is a private NATS store and
    # two trusted per-agent listeners, never the Factory's Coord endpoint.
    with native_instance(tmp_path / "coord", source=POLICY, agent_api=True) as instance:
        instance.environment["SAFEYOLO_NATS_TEST_INSTANCE"] = "scheduling-owned-probe"
        args = ["start"]
        if binary := os.environ.get("SAFEYOLO_COORD_NATS_BINARY"):
            args += ["--binary", binary]
        assert cli(instance, *args).returncode == 0
        try:
            for args in (("room", "create", "scheduled-work"), ("grant", "scheduled-work", "alice")):
                result = cli(instance, *args)
                assert result.returncode == 0, result.stderr
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            bridge = subprocess.Popen(["socat", f"TCP-LISTEN:{port},bind=127.0.0.1,reuseaddr,fork",
                                       f"UNIX-CONNECT:{instance.paths['alice']}"])
            try:
                def bridge_ready():
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            return True
                    except ConnectionRefusedError:
                        return False

                eventually(bridge_ready)
                (image / "etc/environment").write_text(
                    f"export HTTP_PROXY=http://127.0.0.1:{port}\nexport HTTPS_PROXY=$HTTP_PROXY\n"
                    "export http_proxy=$HTTP_PROXY\nexport https_proxy=$HTTP_PROXY\n"
                    "export HOME=/home/agent\nexport SCHEDULING_FIXTURE=current\n"
                    "export PATH=/usr/local/bin:/usr/bin:/bin\n"
                    "export SSL_CERT_FILE=/usr/local/share/ca-certificates/safeyolo.crt\n"
                    "export REQUESTS_CA_BUNDLE=$SSL_CERT_FILE\nexport NODE_EXTRA_CA_CERTS=$SSL_CERT_FILE\n")
                (image / "app/agent_token").write_text(AGENT_TOKEN)
                observed = image / "home/agent/jobs/observed"
                with daemons(image) as pids:
                    eventually(lambda: observed.exists() and "cron uid=1000" in observed.read_text()
                               and "at uid=1000" in observed.read_text(), seconds=80)
                    assert "cwd=/workspace home=/home/agent env=current" in observed.read_text()
                    assert (image / "home/agent/jobs/reboot").exists()
                    def published():
                        messages = history(instance, "scheduled-work")
                        return messages if len(messages) >= 2 else None

                    messages = eventually(published)
                    assert all(message["sender_kind"] == "agent" and message["sender_agent_name"] == "alice"
                               for message in messages)
                    assert not (image / "home/agent/jobs/should-not-run").exists()
                    agent(image, "crontab -r")
                    agent(image, "printf '%s\\n' '/usr/local/bin/safeyolo-job /bin/false >>/home/agent/jobs/failure.log 2>&1' | at -M now")
                    failure = image / "home/agent/jobs/failure.log"
                    eventually(lambda: failure.exists() and "command failed (exit=1)" in failure.read_text())
                    denied_room = cli(instance, "room", "create", "denied-work")
                    assert denied_room.returncode == 0, denied_room.stderr
                    denied = image / "home/agent/jobs/post-denied.sh"
                    denied.write_text((EXAMPLES / "scheduled-coord.sh").read_text().replace(
                        "/rooms/scheduled-work/send", "/rooms/denied-work/send"))
                    agent(image, "printf '%s\\n' '/usr/local/bin/safeyolo-job /bin/sh /home/agent/jobs/post-denied.sh >>/home/agent/jobs/denied.log 2>&1' | at -M now")
                    refusal = image / "home/agent/jobs/denied.log"
                    eventually(lambda: refusal.exists() and "room not found or not accessible" in refusal.read_text()
                               and "command failed (exit=22)" in refusal.read_text())
                    assert history(instance, "denied-work") == []
                    eventually(lambda: not agent(image, "atq").stdout)
                    os.kill(pids[0], signal.SIGTERM)
                    log = image / "var/log/safeyolo-scheduling.log"
                    eventually(lambda: "cron exited (status=" in log.read_text())
                assert agent(image, "atq").stdout == ""
                message_file = tmp_path / "host-message.txt"
                message_file.write_text("owned operator scheduler recipe\n")
                result = cli(instance, "send", "scheduled-work", "--file", str(message_file),
                             "--to", "alice", "--content-type", "text/plain")
                assert result.returncode == 0, result.stderr
                operator = history(instance, "scheduled-work")[-1]
                assert operator["sender_kind"] == "operator"
                assert operator.get("sender_agent_name") is None
            finally:
                bridge.terminate()
                bridge.wait(timeout=5)
        finally:
            result = cli(instance, "stop")
            assert result.returncode == 0, result.stderr
