"""PTY acceptance tests for the operator chat prompt.

The terminal line discipline and live prompt redraw both require a real tty.
Each test therefore drives the production loop under a pseudo-terminal.

The loop and its helpers are extracted from the module by AST rather than
imported, so these run without the full CLI dependency tree.
"""

from __future__ import annotations

import ast
import os
import pty
import re
import select
import shutil
import sys
import textwrap
import time
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "cli/src/safeyolo/commands/coord.py"
if not SRC.exists():  # running from a different layout
    SRC = Path(__file__).resolve().parents[1] / "src/safeyolo/commands/coord.py"

WANTED = {
    "_visible_controls",
    "_render_body",
    "_render_message",
    "_fmt_ts",
    "_read_clipboard",
    "_read_editor",
    "_prompt_line",
    "_confirm_send",
    "_receive_messages",
    "_interactive_session",
    "_interactive_loop",
}


def _extracted_source() -> str:
    """The real functions under test, lifted verbatim from the module."""
    tree = ast.parse(SRC.read_text())
    keep = [
        n
        for n in tree.body
        if (isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in WANTED)
        or (isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "").endswith(("_CMDS", "_CONTROLS")))
    ]
    return ast.unparse(ast.Module(body=keep, type_ignores=[]))


HARNESS = """
from __future__ import annotations
import sys, types, datetime, asyncio, os, shlex, shutil, subprocess, tempfile
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from rich.console import Console
from rich.markup import escape
from rich.text import Text
console = Console(force_terminal=True, width=100, color_system="standard")
UTC = datetime.UTC
datetime = datetime.datetime
sent = []
incoming = os.environ.get("FAKE_INCOMING") == "1"
class GrantError(Exception): pass
class NatsUnavailable(Exception): pass
class CoordDataError(Exception): pass
class NatsPublishOutcomeUnknown(Exception): pass
# The extracted functions retain their production relative imports. Recreate
# the module package context so this harness exercises the same import form.
# Inject only the exception classes needed by the chat helpers; the harness
# deliberately avoids importing the production NATS client.
__package__ = "safeyolo.commands"
_nats_client = types.ModuleType("safeyolo.coord.nats_client")
_nats_client.CoordDataError = CoordDataError
_nats_client.NatsPublishOutcomeUnknown = NatsPublishOutcomeUnknown
_nats_client.NatsUnavailable = NatsUnavailable
sys.modules[_nats_client.__name__] = _nats_client
async def _send(room, kind, aid, body, **kwargs):
    sent.append(body); print("SENT<<" + repr(body) + ">>", flush=True)
    print("NOTIFY<<" + repr(kwargs.get("notify")) + ">>", flush=True)
    return {"attention_status": "ready", "attention_intent": {"mode": "room"}}
async def _read(*a, **k):
    since = k.get("since_sequence", 0)
    if incoming and since < 1:
        return {"messages": [{"sender_kind": "agent", "sender_agent_name": "relay",
                 "sender_agent_id": "ag-relay", "sent_at": 0, "sequence": 1,
                 "body": "incoming while typing", "attention_intent": {"mode": "targeted"}}],
                "next_cursor": 1, "has_more": False}
    return {"messages": [], "next_cursor": 0, "has_more": False}
async def _wait(*a, **k):
    if incoming and k.get("since_sequence", 0) < 1:
        await asyncio.sleep(0.2)
        return {"messages": [{}]}
    await asyncio.sleep(3600)
api = types.SimpleNamespace(MAX_BODY_BYTES=256*1024, GrantError=GrantError,
                            READ_PAGE_MAX=200, send=_send, read_room=_read,
                            wait_for_message=_wait)
_OBSERVE_WAIT_SECONDS = 30.0
class _ChatRuntime: pass
class RT:
    def __init__(self): self.loop = asyncio.new_event_loop()
    def run(self, coro): return self.loop.run_until_complete(coro)
__EXTRACTED__
_interactive_loop(RT(), "huddle", 0)
print("LOOP-EXITED", flush=True)
"""


def _run_under_pty(
    script: str,
    keystrokes: bytes | list[tuple[float, bytes]],
    env: dict,
) -> str:
    """Feed `keystrokes` to `script` running on a real pty; return its output."""
    pid, fd = pty.fork()
    if pid == 0:  # child
        os.execve(sys.executable, [sys.executable, "-c", script], env)
    if isinstance(keystrokes, bytes):
        os.write(fd, keystrokes)
    else:
        for delay, data in keystrokes:
            time.sleep(delay)
            os.write(fd, data)
    out = b""
    while True:
        r, _, _ = select.select([fd], [], [], 5.0)
        if not r:
            break
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
        if b"LOOP-EXITED" in out:
            break
    os.close(fd)
    os.waitpid(pid, 0)
    return out.decode("utf-8", errors="replace")


def _script() -> str:
    return textwrap.dedent(HARNESS).replace("__EXTRACTED__", _extracted_source())


def _sent(output: str) -> list[str]:
    return [eval(m) for m in re.findall(r"SENT<<(.*?)>>", output, re.S)]  # noqa: S307


@pytest.fixture
def env(tmp_path):
    e = dict(os.environ)
    e["PYTHONUNBUFFERED"] = "1"
    return e


pytestmark = pytest.mark.skipif(shutil.which("printf") is None, reason="needs a shell for the fake clipboard")


def test_typed_ctrl_r_is_mangled_by_the_tty(env):
    """Baseline: this is the bug. Typing ^R does not survive the prompt.

    Kept as a regression witness -- it documents *why* :paste exists. If this
    ever starts passing the text through intact, the tty assumption changed.
    """
    out = _run_under_pty(_script(), b"before\x12after\n:q\n", env)
    sent = _sent(out)
    assert sent, "nothing was sent"
    assert "\x12" not in sent[0], "raw ^R reached the message body"


def test_paste_delivers_control_bytes_verbatim(tmp_path, env):
    """:paste bypasses the line discipline, so the bytes survive."""
    fake = tmp_path / "pbpaste"
    fake.write_text('#!/bin/sh\nprintf "one \\003 two\\n\\033[31mred\\033[0m\\n"\n')
    fake.chmod(0o755)
    env = {**env, "PATH": f"{tmp_path}:{env['PATH']}"}
    out = _run_under_pty(_script(), b":paste\ny\n:q\n", env)
    sent = _sent(out)
    assert sent, f"nothing sent; output was {out!r}"
    assert "\x03" in sent[0] and "\x1b[31m" in sent[0]
    assert sent[0].count("\n") == 1, "multi-line paste did not arrive as one message"


def test_paste_alias_p_works(tmp_path, env):
    fake = tmp_path / "pbpaste"
    fake.write_text('#!/bin/sh\nprintf "via the short alias\\n"\n')
    fake.chmod(0o755)
    env = {**env, "PATH": f"{tmp_path}:{env['PATH']}"}
    out = _run_under_pty(_script(), b":p\ny\n:q\n", env)
    assert _sent(out) == ["via the short alias"]


def test_confirm_send_survives_markup_in_pasted_text(tmp_path, env):
    """A paste whose first line contains rich markup must not kill the loop.

    Regression for the MarkupError introduced alongside :paste -- unbalanced
    markup in clipboard content crashed the whole chat session.
    """
    fake = tmp_path / "pbpaste"
    fake.write_text('#!/bin/sh\nprintf "normal[/] [bold yellow]operator[/]\\nsecond\\n"\n')
    fake.chmod(0o755)
    env = {**env, "PATH": f"{tmp_path}:{env['PATH']}"}
    out = _run_under_pty(_script(), b":paste\ny\n:q\n", env)
    assert "MarkupError" not in out and "Traceback" not in out
    assert "LOOP-EXITED" in out, "loop died instead of exiting cleanly"
    assert _sent(out), "nothing sent"


def test_editor_path_round_trips(tmp_path, env):
    ed = tmp_path / "fakeed"
    ed.write_text('#!/bin/sh\nprintf "from editor \\033[1mbold\\033[0m\\n" > "$1"\n')
    ed.chmod(0o755)
    env = {**env, "PATH": f"{tmp_path}:{env['PATH']}", "EDITOR": "fakeed", "VISUAL": ""}
    out = _run_under_pty(_script(), b":e\ny\n:q\n", env)
    sent = _sent(out)
    assert sent and "\x1b[1m" in sent[0]


def test_cancelling_a_paste_sends_nothing(tmp_path, env):
    fake = tmp_path / "pbpaste"
    fake.write_text('#!/bin/sh\nprintf "should not be sent\\n"\n')
    fake.chmod(0o755)
    env = {**env, "PATH": f"{tmp_path}:{env['PATH']}"}
    out = _run_under_pty(_script(), b":paste\nn\n:q\n", env)
    assert _sent(out) == []


def test_typed_line_still_sends(env):
    out = _run_under_pty(_script(), b"an ordinary line\n:q\n", env)
    assert _sent(out) == ["an ordinary line"]
    assert "NOTIFY<<'room'>>" in out
    plain = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", out)
    assert "attention=room" in plain


def test_incoming_message_preserves_draft_and_send(env):
    """One process receives while the operator continues editing a draft."""
    env = {**env, "FAKE_INCOMING": "1"}
    out = _run_under_pty(
        _script(),
        [(0.1, b"draft "), (0.4, b"continues\n"), (0.1, b":q\n")],
        env,
    )
    assert "Traceback" not in out
    assert "incoming while typing" in out
    assert _sent(out) == ["draft continues"]


def test_ctrl_c_detaches_without_a_traceback(env):
    out = _run_under_pty(_script(), [(1.0, b"\x03")], env)
    assert "Traceback" not in out
    assert "detached" in out
    assert "LOOP-EXITED" in out


def test_every_physical_line_is_guttered():
    """Wrapped continuation lines must keep the gutter.

    Console wrapping puts continuations at column 0, so a body containing one
    long line had part of itself render as top-level text -- defeating the
    gutter. Found by live test, not by the in-process suite.
    """
    import io

    from rich.console import Console
    from rich.text import Text

    ns: dict = {"Text": Text, "console": None}
    exec(compile(_extracted_source(), "x", "exec"), ns)  # noqa: S102
    body = "short\n" + ("word " * 40).strip() + "\n" + "A" * 150 + "\n\ntail"
    for width in (40, 60, 100):
        buf = io.StringIO()
        ns["console"] = Console(file=buf, force_terminal=False, width=width)
        ns["_render_body"](body)
        lines = [ln for ln in buf.getvalue().split("\n") if ln != ""]
        assert lines, "nothing rendered"
        ungutttered = [ln for ln in lines if not ln.startswith("│")]
        assert not ungutttered, f"width={width}: unguttered lines {ungutttered!r}"
