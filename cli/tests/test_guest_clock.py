"""Run the per-run clock, scheduler and hook ordering in an isolated tree.

The helper and scheduler here record calls. Real RTC/TLS results are separate
platform evidence; these tests cover current shell integration and cleanup.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "src/safeyolo/guest-init-per-run.sh"


@pytest.mark.parametrize("staged", [True, False])
@pytest.mark.parametrize("initial_failure", [False, True])
@pytest.mark.parametrize("shutdown", ["signal", "command_exit"])
def test_vz_clock_precedes_schedulers_and_hooks_and_stops(
    tmp_path, staged, initial_failure, shutdown
):
    _run_per_run(tmp_path, "vz-test", staged, initial_failure, shutdown)


def test_gvisor_starts_no_clock_child(tmp_path):
    _run_per_run(tmp_path, "4.4.0-gvisor", True, False, "signal")


def _run_per_run(tmp_path, release, staged, initial_failure, shutdown):
    source = SOURCE.read_text()
    paths = {
        "/usr/local/lib/safeyolo/scheduling.sh": tmp_path / "scheduling.sh",
        "/run/safeyolo": tmp_path / "staged",
        "/safeyolo": tmp_path / "share",
        "/home/agent": tmp_path / "agent",
        "/etc": tmp_path / "etc",
        "/app": tmp_path / "app",
        "/dev/console": tmp_path / "console",
    }
    # Redirect only guest paths. Commands still use the real Bash and setsid.
    path_pattern = r"(?<![A-Za-z0-9_/])(?:" + "|".join(re.escape(path) for path in paths) + r")(?=/|[\s\"';]|$)"
    source = re.sub(
        path_pattern,
        lambda match: str(paths[match[0]]),
        source,
    )
    # A console device does not truncate earlier output when it is reopened.
    source = re.sub(r"> ?" + re.escape(str(tmp_path / "console")),
                    ">>" + str(tmp_path / "console"), source)
    for path in paths.values():
        if path.suffix != ".sh" and path.name != "console":
            path.mkdir(parents=True)
    (tmp_path / "etc/profile.d").mkdir()
    hooks = tmp_path / "agent/.safeyolo-hooks"
    hooks.mkdir()
    (hooks / "agent-init.sh").write_text('printf "hook\\n" >> "$TRACE"\n')
    (tmp_path / "scheduling.sh").write_text(
        'start_guest_schedulers() { printf "schedulers\\n" >> "$TRACE"; }\n'
        'stop_guest_schedulers() { printf "schedulers-stopped\\n" >> "$TRACE"; }\n'
    )
    helper = (
        '#!/bin/bash\n'
        'if [ "${2:-}" = watch ]; then exec sleep 60; fi\n'
        'printf "%s\\n" "$0" >> "$TRACE"\n'
        'if [ "$INITIAL_FAILURE" = 1 ]; then\n'
        '  echo "[guest-clock] controlled unavailable RTC" >&2\n'
        '  exit 1\n'
        'fi\n'
    )
    path = tmp_path / "share/safeyolo-guest"
    path.write_text(helper)
    path.chmod(0o755)
    if staged:
        # Use static init's real install operation to prepare the tmpfs copy.
        per_run = tmp_path / "share/guest-init-per-run"
        per_run.write_bytes(SOURCE.read_bytes())
        static = SOURCE.with_name("guest-init-static.sh").read_text()
        stage = static[static.index("[ -d /run/safeyolo ]") : static.index("# 6. Seed")]
        stage = re.sub(path_pattern, lambda match: str(paths[match[0]]), stage)
        subprocess.run(["bash", "-ec", stage], check=True, timeout=5)
        for name in ["safeyolo-guest", "guest-init-per-run"]:
            copy = tmp_path / "staged" / name
            assert copy.read_bytes() == (tmp_path / "share" / name).read_bytes()
            assert copy.stat().st_mode & 0o777 == 0o755
    # Execute the actual setup through scheduler startup and the agent hook.
    setup = source[source.index("GUEST_HELPER=") : source.index("# 4. Run the host")]
    if shutdown == "signal":
        cleanup = source[
            source.index("graceful_shutdown()") : source.index("COMMAND_SUPERVISOR_PID=")
        ]
        cleanup += 'kill -TERM "$$"\n'
    else:
        cleanup = source[source.rindex("stop_guest_schedulers\n") : source.rindex("sync\n")]
    result = subprocess.run(
        ["bash", "-ec", (
            'uname() { printf "%s\\n" "$RELEASE"; }\n'
            # Simulate the hook's user transition without needing guest root.
            'su() { test "$1" = agent; test "$2" = -c; bash -c "$3"; }\n'
            # An omitted cleanup must fail while still retiring the test child.
            + "trap 'if [ -n \"${CLOCK_SYNC_PID:-}\" ]; then stop_guest_clock; exit 91; fi' EXIT\n"
            + setup
            + ("test -n \"$CLOCK_SYNC_PID\"; kill -0 \"$CLOCK_SYNC_PID\"\n"
               if release == "vz-test" else 'test -z "$CLOCK_SYNC_PID"\n')
            + cleanup
        )],
        env={**os.environ, "TRACE": str(tmp_path / "trace"), "RELEASE": release,
             "INITIAL_FAILURE": str(int(initial_failure))},
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr
    expected = []
    if release == "vz-test":
        expected.append(str(tmp_path / ("staged" if staged else "share") / "safeyolo-guest"))
        assert ("controlled unavailable RTC" in (tmp_path / "console").read_text()) == initial_failure
    assert (tmp_path / "trace").read_text().splitlines() == [
        *expected, "schedulers", "hook", "schedulers-stopped"
    ]
