"""PTY acceptance tests for the operator chat prompt.

The bug these guard against was caused by the terminal line discipline, so
in-process tests cannot see it: `input()` only misbehaves when it is attached
to a real tty. Each test drives the loop under an actual pseudo-terminal.

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
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "cli/src/safeyolo/commands/coord.py"
if not SRC.exists():  # running from a different layout
    SRC = Path(__file__).resolve().parents[1] / "src/safeyolo/commands/coord.py"

WANTED = {
    "_visible_controls", "_render_body", "_render_message", "_fmt_ts",
    "_read_clipboard", "_read_editor", "_confirm_send", "_interactive_loop",
}


def _extracted_source() -> str:
    """The real functions under test, lifted verbatim from the module."""
    tree = ast.parse(SRC.read_text())
    keep = [
        n for n in tree.body
        if (isinstance(n, ast.FunctionDef) and n.name in WANTED)
        or (isinstance(n, ast.Assign)
            and getattr(n.targets[0], "id", "").endswith(("_CMDS", "_CONTROLS")))
    ]
    return ast.unparse(ast.Module(body=keep, type_ignores=[]))


HARNESS = '''
import sys, types, datetime, asyncio, os, shlex, shutil, subprocess, tempfile
from rich.console import Console
from rich.markup import escape
from rich.text import Text
console = Console(force_terminal=True, width=100, color_system="standard")
UTC = datetime.UTC
datetime = datetime.datetime
sent = []
class GrantError(Exception): pass
async def _send(room, kind, aid, body):
    sent.append(body); print("SENT<<" + repr(body) + ">>", flush=True); return {}
async def _read(*a, **k):
    return {"messages": [], "next_cursor": 0, "has_more": False}
api = types.SimpleNamespace(MAX_BODY_BYTES=256*1024, GrantError=GrantError,
                            READ_PAGE_MAX=200, send=_send, read_room=_read)
class _ChatRuntime: pass
class RT:
    def run(self, coro): return asyncio.new_event_loop().run_until_complete(coro)
__EXTRACTED__
_interactive_loop(RT(), "huddle", 0)
print("LOOP-EXITED", flush=True)
'''


def _run_under_pty(script: str, keystrokes: bytes, env: dict) -> str:
    """Feed `keystrokes` to `script` running on a real pty; return its output."""
    pid, fd = pty.fork()
    if pid == 0:  # child
        os.execve(sys.executable, [sys.executable, "-c", script], env)
    os.write(fd, keystrokes)
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


pytestmark = pytest.mark.skipif(
    shutil.which("printf") is None, reason="needs a shell for the fake clipboard"
)


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
