"""Correlate each guest refusal with a host listener live in the same run."""

import json
import os
import shlex
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from guest_exec import guest_command_args
from harness.host_listener import listener_endpoint
from installed_lifecycle import running_guest


class TestLiveHostListener:
    """A contemporaneously live host listener remains isolated from guests.

    Why: A guest refusal without host liveness can pass when no service exists.
    """

    @pytest.mark.parametrize("user,guest_root,nodes", [
        ("ordinary", False, (
            "test_vm_isolation.py::TestHostAdjacentReachability::test_host_listener_unreachable",
            "test_vm_isolation.py::TestNetworkEscape::test_proxy_reachable",
        )),
        ("guest-root", True, (
            "test_root_containment.py::TestGuestRootContainment::test_root_cannot_reach_live_host_listener",
            "test_root_containment.py::TestGuestRootContainment::test_root_proxy_path_works",
        )),
        pytest.param("sandbox-root", False, (
            "test_vm_isolation.py::TestSandboxRootContainment::test_host_listener_stays_unreachable_as_sandbox_root",
            "test_vm_isolation.py::TestNetworkEscape::test_proxy_reachable",
        ), marks=pytest.mark.skipif(sys.platform == "darwin", reason="namespace-root control applies to gVisor")),
    ])
    def test_live_host_listener_refused(self, user, guest_root, nodes):
        """A live host listener stays unreachable to ordinary and root guests.

        What: Connect from the host before and after the maintained guest refusal
        and proxy positive controls. Record the actual endpoint and guest identity.
        Why: A stale port or an absent listener cannot establish host isolation.
        """
        root = Path(os.environ["SAFEYOLO_CONFIG_DIR"])
        agent = os.environ.get("SAFEYOLO_TEST_AGENT", "bbtest")
        cli = os.environ.get("SAFEYOLO_NATIVE_CLI", "safeyolo")
        share = root / "agents" / agent / "config-share"
        artifacts = Path(os.environ.get("SAFEYOLO_BLACKBOX_ARTIFACTS_DIR", str(root / "logs")))
        artifacts.mkdir(parents=True, exist_ok=True)
        output = artifacts / f"host-listener-{user}.json"
        report = {"user": user, "config_dir": str(root), "agent": agent,
                  "markers": [str(share / name) for name in ("host-listener-address", "host-listener-port")],
                  "host_liveness": []}

        def save():
            output.write_text(json.dumps(report, indent=2) + "\n")

        def guest():
            status = subprocess.run([cli, "--root", str(root), "agent", "status", agent],
                                    capture_output=True, text=True, timeout=15, check=True)
            return running_guest(root, agent, json.loads(status.stdout))

        def host_live():
            with socket.create_connection((host, port), timeout=3) as connection:
                return {"time_ns": time.time_ns(), "peer": list(connection.getpeername()), "connected": True}

        save()  # Retain the actual inputs even when a prerequisite fails.
        try:
            host, port = listener_endpoint(share)
            report["endpoint"] = {"host": host, "port": port}
            save()
            report["guest_before"] = guest()
            report["host_liveness"].append(host_live())
            save()
            command = ("cd /workspace/tests/blackbox/isolation && "
                       "SAFEYOLO_BLACKBOX_ISOLATION=1 /usr/bin/python3 -m pytest -q -s -rs --tb=short --timeout=30 " + shlex.join(nodes))
            report["command"] = guest_command_args(cli, agent, command, guest_root=guest_root)
            save()
            result = subprocess.run(report["command"], capture_output=True, text=True, timeout=75)
            report["guest_tests"] = {"exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
            report["host_liveness"].append(host_live())
            report["guest_after"] = guest()
            save()
            assert result.returncode == 0 and "2 passed" in result.stdout and "skipped" not in result.stdout, (
                f"guest listener/proxy controls did not pass: {result.stdout} {result.stderr}"
            )
            observations = [line.partition("HOST_LISTENER_REFUSAL=")[2] for line in result.stdout.splitlines()
                            if "HOST_LISTENER_REFUSAL=" in line]
            assert len(observations) == 1, "guest returned no single listener refusal"
            refusal = json.loads(observations[0])
            report["refusal"] = refusal
            assert (refusal["host"], refusal["port"]) == (host, port), "guest probed another listener endpoint"
            assert refusal["connected"] is False and refusal["uid"] == (1000 if user == "ordinary" else 0)
            assert report["guest_after"] == report["guest_before"], "listener control changed the running guest"
            report["passed"] = True
        finally:
            save()
