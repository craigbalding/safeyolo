"""Runtime capability parity probes run inside the real sandbox."""

import resource
import subprocess
import sys

NOFILE_LIMIT = 65536


class TestOpenFileLimit:
    """Every supported sandbox exposes the same open-file headroom.

    Why: A lower hard limit on the VZ normal-session path makes agent
    workloads depend on the operator's host platform. The session must repair
    that limit before it runs the requested workload.
    """

    def test_pid1_shell_and_child_inherit_nofile_limit(self):
        """PID 1 and all later descendants have a 65536 soft/hard limit.

        What: Read PID 1's proc limit, inspect the running test process that
        was launched through the normal agent-shell path, and spawn one more
        child.
        Why: Checking only the final agent process can hide a child-only
        workaround. The normal SSH entry path must establish the session and
        its visible PID 1 limit before it launches the requested workload.
        """
        with open("/proc/1/limits") as limits_file:
            pid1_line = next(
                line for line in limits_file if line.startswith("Max open files")
            )
        pid1_fields = pid1_line.split()
        pid1_limits = tuple(int(value) for value in pid1_fields[3:5])
        assert pid1_limits == (NOFILE_LIMIT, NOFILE_LIMIT)

        assert resource.getrlimit(resource.RLIMIT_NOFILE) == (
            NOFILE_LIMIT,
            NOFILE_LIMIT,
        )

        child = subprocess.run(
            [
                sys.executable,
                "-c",
                ("import resource; print(*resource.getrlimit(resource.RLIMIT_NOFILE))"),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        assert child.stdout.strip() == f"{NOFILE_LIMIT} {NOFILE_LIMIT}"
