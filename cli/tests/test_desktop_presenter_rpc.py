"""Protocol tests for the native desktop presenter owner."""

from __future__ import annotations

import io
import json
import os
import select
import subprocess
import sys
import textwrap
import time
import types
from types import SimpleNamespace

import pytest

from safeyolo import desktop_presenter_rpc


def test_daemon_keeps_one_presenter_owner_until_shutdown(monkeypatch):
    class PresentationError(RuntimeError):
        pass

    class Presenter:
        instances = []

        def __init__(self):
            self.calls = []
            self.closed = False
            self.instances.append(self)

        def present(self, agent_id):
            self.calls.append(agent_id)
            return SimpleNamespace(
                to_dict=lambda: {
                    "agent_id": agent_id,
                    "agent": "alice",
                    "url": "http://127.0.0.1:12345/vnc.html",
                    "unlock_code": "1234-5678",
                    "reused": bool(len(self.calls) > 1),
                }
            )

        def close_all(self):
            self.closed = True

    presenter_module = types.ModuleType("safeyolo.desktop_presenter")
    presenter_module.DesktopPresentationError = PresentationError
    presenter_module.DesktopPresenter = Presenter
    agents_module = types.ModuleType("safeyolo.agents_store")
    agents_module.get_or_mint_agent_id = lambda agent_id: agent_id
    monkeypatch.setitem(sys.modules, "safeyolo.desktop_presenter", presenter_module)
    monkeypatch.setitem(sys.modules, "safeyolo.agents_store", agents_module)

    output = io.StringIO()
    assert (
        desktop_presenter_rpc.daemon_main(
            io.StringIO('{"agent_id":"alice"}\n{"agent_id":"alice"}\n{"shutdown":true}\n'),
            output,
        )
        == 0
    )

    responses = [json.loads(line) for line in output.getvalue().splitlines()]
    assert [response["reused"] for response in responses[:2]] == [False, True]
    assert responses[2] == {"status": "stopped"}
    assert len(Presenter.instances) == 1
    assert Presenter.instances[0].calls == ["alice", "alice"]
    assert Presenter.instances[0].closed


def test_daemon_keeps_inherited_guest_output_off_protocol_stdout():
    # Use a separate interpreter because guest commands inherit fd 1 rather
    # than Python's sys.stdout object. A string-stream unit test misses the
    # actual Rust-facing corruption boundary.
    fixture = textwrap.dedent(
        """
        import subprocess
        import sys
        from types import SimpleNamespace
        from safeyolo import desktop_presenter_rpc as rpc

        class PresentationError(RuntimeError):
            pass

        class Presenter:
            def present(self, agent_id):
                subprocess.run(
                    [sys.executable, "-c", "print('desktop already ready')"],
                    check=True,
                )
                if agent_id == "failed":
                    raise ValueError("preview unavailable")
                if agent_id == "missing":
                    raise PresentationError("Agent not found")
                return SimpleNamespace(to_dict=lambda: {
                    "agent_id": "ag-alice",
                    "agent": agent_id,
                    "url": "http://127.0.0.1:12345/vnc.html",
                    "unlock_code": "1234-5678",
                    "reused": False,
                })

            def close_all(self):
                pass

        rpc._load_dependencies = lambda: (PresentationError, Presenter, lambda value: value, None)
        raise SystemExit(rpc.main())
        """
    )
    completed = subprocess.run(
        [sys.executable, "-c", fixture, "--daemon"],
        input=('{"agent_id":"alice"}\n{"agent_id":"failed"}\n{"agent_id":"missing"}\n{"shutdown":true}\n'),
        capture_output=True,
        text=True,
        check=True,
    )

    responses = [json.loads(line) for line in completed.stdout.splitlines()]
    assert len(responses) == 4
    assert responses[0]["agent"] == "alice"
    assert responses[1] == {"error": "ValueError", "kind": "failed"}
    assert responses[2] == {"error": "Agent not found", "kind": "not_found"}
    assert responses[3] == {"status": "stopped"}
    assert completed.stderr.count("desktop already ready") == 4


@pytest.mark.skipif(sys.platform != "linux", reason="Linux runsc stdin inheritance")
def test_daemon_keeps_protocol_stdin_after_noninteractive_guest_command(tmp_path):
    # A guest command that makes inherited fd 0 nonblocking also changes the
    # presenter's read end of the same pipe. With no second request yet, Python
    # then treats the nonblocking read as EOF and closes the preview owner.
    runsc = tmp_path / "runsc-stub"
    runsc.write_text(
        f"#!{sys.executable}\n"
        "import os\n"
        "import sys\n"
        "os.set_blocking(0, False)\n"
        "if 'state' in sys.argv:\n"
        "    print('{\"status\":\"running\"}')\n"
    )
    runsc.chmod(0o755)
    fixture = textwrap.dedent(
        """
        import os
        from types import SimpleNamespace
        from safeyolo import desktop_presenter_rpc as rpc
        from safeyolo.platform import linux

        linux._find_runsc = lambda: os.environ["SAFEYOLO_TEST_RUNSC"]
        linux._runsc_root = lambda: "/tmp"
        linux._get_userns_pid = lambda _name: None

        class PresentationError(RuntimeError):
            pass

        class Presenter:
            def __init__(self):
                self.calls = 0

            def present(self, agent_id):
                self.calls += 1
                platform = linux.LinuxPlatform()
                assert platform.is_sandbox_running(agent_id)
                assert platform.exec_in_sandbox(
                    agent_id, "true", interactive=False
                ) == 0
                return SimpleNamespace(to_dict=lambda: {
                    "agent_id": agent_id,
                    "agent": agent_id,
                    "url": "http://127.0.0.1:12345/vnc.html",
                    "unlock_code": "fixture",
                    "reused": self.calls > 1,
                })

            def close_all(self):
                pass

        rpc._load_dependencies = lambda: (PresentationError, Presenter, lambda value: value, None)
        raise SystemExit(rpc.main())
        """
    )
    env = os.environ.copy()
    env["SAFEYOLO_TEST_RUNSC"] = str(runsc)
    process = subprocess.Popen(
        [sys.executable, "-c", fixture, "--daemon"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    try:
        assert process.stdin is not None
        assert process.stdout is not None
        process.stdin.write('{"agent_id":"alice"}\n')
        process.stdin.flush()
        ready, _, _ = select.select([process.stdout], [], [], 5)
        assert ready, "first presenter response did not arrive"
        first = json.loads(process.stdout.readline())
        assert first["reused"] is False
        time.sleep(0.1)
        assert process.poll() is None, "presenter exited while the proxy pipe remained open"

        process.stdin.write('{"agent_id":"alice"}\n{"shutdown":true}\n')
        process.stdin.flush()
        remaining, stderr = process.communicate(timeout=5)
        assert process.returncode == 0, stderr
        assert [json.loads(line) for line in remaining.splitlines()] == [
            {**first, "reused": True},
            {"status": "stopped"},
        ]
    finally:
        if process.poll() is None:
            process.kill()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()
        process.wait(timeout=5)


def test_daemon_closes_preview_owner_on_input_end_or_broken_response_pipe(monkeypatch):
    class PresentationError(RuntimeError):
        pass

    class Presenter:
        instance = None

        def __init__(self):
            self.closed = False
            Presenter.instance = self

        def present(self, agent_id):
            return SimpleNamespace(to_dict=lambda: {
                "agent_id": agent_id,
                "agent": agent_id,
                "url": "http://127.0.0.1:12345/vnc.html",
                "unlock_code": "fixture",
                "reused": False,
            })

        def close_all(self):
            self.closed = True

    monkeypatch.setattr(
        desktop_presenter_rpc,
        "_load_dependencies",
        lambda: (PresentationError, Presenter, lambda value: value, None),
    )
    output = io.StringIO()
    assert desktop_presenter_rpc.daemon_main(io.StringIO('{"agent_id":"alice"}\n'), output) == 0
    assert json.loads(output.getvalue())["agent"] == "alice"
    assert Presenter.instance.closed

    class BrokenOutput:
        def write(self, _text):
            raise BrokenPipeError("proxy output closed")

    with pytest.raises(BrokenPipeError, match="proxy output closed"):
        desktop_presenter_rpc.daemon_main(io.StringIO('{"agent_id":"alice"}\n'), BrokenOutput())
    assert Presenter.instance.closed
