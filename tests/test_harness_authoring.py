"""Exercise shipped harness qualification with a constrained unfamiliar target.

This target runs real file effects and retains a session, but supplies no model,
network policy or Coord implementation. Its evidence must stay fixture evidence.
"""

from __future__ import annotations

import json
import os
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "cli/src/safeyolo/agent_context/skills/harness-authoring/scripts/qualify.py"
HELPER = runpy.run_path(str(SCRIPT))


@pytest.fixture
def target(tmp_path):
    """The target implements Codex-shaped turns but no external attention."""
    path = tmp_path / "ember"
    path.write_text(f'''#!{sys.executable}
import json,re,sys
from pathlib import Path
if '--version' in sys.argv:
    print('ember 1.2.3');sys.exit(0)
prompt=sys.stdin.read()
history=Path('session.json')
if 'resume' in sys.argv:
    saved=json.loads(history.read_text())
    assert sys.argv[sys.argv.index('resume')+3] == saved['id']
    with Path('result.txt').open('a') as result: result.write(saved['nonce']+'\\n')
else:
    saved={{'id':'ember-session','nonce':re.search("write exactly '([a-f0-9]+)'",prompt)[1]}}
    history.write_text(json.dumps(saved))
    Path('result.txt').write_text(saved['nonce']+'\\n')
for event in [{{'type':'thread.started','thread_id':saved['id']}},
              {{'type':'turn.started'}},
              {{'type':'item.completed','item':{{'type':'command_execution','status':'completed','exit_code':0}}}},
              {{'type':'turn.completed'}}]:
    print(json.dumps(event))
''')
    path.chmod(0o700)
    return path


def invoke(*args):
    result = subprocess.run([sys.executable, str(SCRIPT), *map(str, args)],
                            capture_output=True, text=True, timeout=15)
    return result.returncode, json.loads(result.stdout)


def test_unfamiliar_target_remains_fixture_evidence_across_real_file_and_resume(target, tmp_path):
    code, unsupported = invoke("probe", "--harness", "ember", "--binary", target)
    assert code == 2 and unsupported["state"] == "unsupported"
    code, probe = invoke("probe", "--harness", "ember", "--protocol", "codex", "--binary", target)
    assert code == 0 and probe["state"] == "not_tested" and probe["version"] == "1.2.3"
    output = tmp_path / "proof"
    code, proof = invoke("fixture", "--harness", "ember", "--protocol", "codex", "--binary", target, "--output", output)
    assert code == 0, proof
    assert proof["state"] == "fixture_passing"
    assert proof["provenance"] == "deliberately constrained fixture"
    assert proof["observations"]["first"]["session_id"] == proof["observations"]["resumed"]["session_id"]
    lines = (output / "workspace/result.txt").read_text().splitlines()
    assert len(lines) == 2 and lines[0] == lines[1]
    assert json.loads((output / "report.json").read_text()) == proof
    original = (output / "report.json").read_bytes()
    code, repeated = invoke("fixture", "--harness", "ember", "--protocol", "codex", "--binary", target, "--output", output)
    assert code == 1 and repeated["state"] == "failed"
    assert (output / "report.json").read_bytes() == original


def trace(tmp_path, values, harness="codex"):
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(json.dumps(event) for event in values) + "\n")
    return invoke("trace", "--harness", harness, "--events", path)


CODEX = [{"type": "thread.started", "thread_id": "retained"}, {"type": "turn.started"},
         {"type": "item.completed", "item": {"type": "command_execution", "status": "completed", "exit_code": 0}},
         {"type": "turn.completed"}]
PI = [{"type": "session", "id": "retained"}, {"type": "agent_start"},
      {"type": "tool_execution_start", "toolCallId": "one", "toolName": "bash", "args": {}},
      {"type": "tool_execution_end", "toolCallId": "one", "toolName": "bash", "isError": False},
      {"type": "agent_end", "willRetry": False}]


@pytest.mark.parametrize("harness,values", [("codex", CODEX), ("pi", PI)])
def test_native_captures_do_not_become_installed_proof(tmp_path, harness, values):
    code, report = trace(tmp_path, values, harness)
    assert code == 0 and report["state"] == "fixture_passing"
    assert report["boundary"] == "ordinary.structured_turn"


@pytest.mark.parametrize("values,reason", [
    (CODEX[:-1], "terminal"),
    ([CODEX[0], CODEX[1], CODEX[-1]], "tool event"),
    (CODEX + [{"type": "turn.failed"}], "turn failed"),
    (CODEX + [{"type": "thread.started", "thread_id": "different"}], "identity changed"),
    ([CODEX[-1], *CODEX[:-1]], "preceded turn start"),
    ([{"type": "thread.started", "thread_id": ""}, *CODEX[1:]], "identity is missing"),
    (["DONE"], "not an object"),
])
def test_false_or_incomplete_success_has_one_actionable_reason(tmp_path, values, reason):
    code, report = trace(tmp_path, values)
    assert code == 1 and report["state"] == "failed"
    assert reason in report["reason"]


@pytest.mark.parametrize("suffix,reason", [
    ({"type": "agent_end", "willRetry": True}, "terminal"),
    ({"type": "message_end", "message": {"role": "assistant", "stopReason": "error"}}, "turn failed"),
])
def test_pi_retry_and_error_are_not_success(tmp_path, suffix, reason):
    code, report = trace(tmp_path, [*PI[:-1], suffix], "pi")
    assert code == 1 and reason in report["reason"]


def test_malformed_json_is_failure(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text('{"type":\n')
    code, report = invoke("trace", "--harness", "codex", "--events", path)
    assert code == 1 and "Malformed JSON at line 1" in report["reason"]


@pytest.mark.parametrize("source,reason", [
    ("print('unknown')", "version is unavailable"),
    ("raise SystemExit(7)", "version is unavailable"),
    ("import time;time.sleep(60)", "deadline expired"),
])
def test_missing_version_crash_and_stall_are_bounded(tmp_path, source, reason):
    binary = tmp_path / "broken"
    binary.write_text(f"#!{sys.executable}\n" + source + "\n")
    binary.chmod(0o700)
    code, report = invoke("probe", "--harness", "codex", "--binary", binary, "--timeout", "0.2")
    assert code == 1 and reason in report["reason"]


@pytest.mark.parametrize("replacement,reason", [
    ("raise SystemExit(7)", "exited unsuccessfully"),
    ("import time;time.sleep(60)", "deadline expired"),
    ("print('not JSON');sys.exit(0)", "Malformed JSON"),
])
def test_native_turn_failure_retains_output_instead_of_qualifying(target, tmp_path, replacement, reason):
    target.write_text(target.read_text().replace("prompt=sys.stdin.read()", replacement))
    output = tmp_path / "failed-trial"
    code, report = invoke("fixture", "--harness", "ember", "--protocol", "codex", "--binary", target,
                          "--output", output, "--timeout", "0.5")
    assert code == 1 and report["state"] == "failed" and reason in report["reason"]
    assert (output / "first.jsonl").is_file()
    assert json.loads((output / "report.json").read_text()) == report


@pytest.mark.skipif(sys.platform != "linux", reason="process state observer uses procfs")
def test_deadline_cleans_owned_child_and_preserves_unrelated_process(tmp_path):
    output = tmp_path / "output"
    pid_file = tmp_path / "child.pid"
    source = ("import subprocess,sys,time\n"
              "from pathlib import Path\n"
              "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])\n"
              f"Path({str(pid_file)!r}).write_text(str(child.pid))\n"
              "time.sleep(60)\n")
    with subprocess.Popen([sys.executable, "-c", "import time;time.sleep(60)"]) as unrelated:
        try:
            with pytest.raises(HELPER["QualificationError"], match="deadline expired"):
                HELPER["execute"]([sys.executable, "-c", source], tmp_path, output, 1)
            child = int(pid_file.read_text())
            stat = Path(f"/proc/{child}/stat")
            assert not stat.exists() or stat.read_text().rsplit(")", 1)[1].split()[0] == "Z"
            assert unrelated.poll() is None
        finally:
            unrelated.terminate()
            unrelated.wait()


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf"])
def test_nonfinite_and_nonpositive_deadlines_are_rejected(value):
    result = subprocess.run([sys.executable, str(SCRIPT), "probe", "--harness", "pi", "--timeout", value],
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 2 and "positive and finite" in result.stderr


@pytest.mark.skipif(not os.environ.get("SAFEYOLO_HARNESS_AUTHORING_CODEX"), reason="select an authorized installed Codex explicitly")
def test_installed_codex_task_and_session_recovery(tmp_path):
    """Opt-in real model/tool proof; the ordinary CI lane makes no model request."""
    output = tmp_path / "installed"
    command = [sys.executable, str(SCRIPT), "installed", "--harness", "codex", "--binary",
               os.environ["SAFEYOLO_HARNESS_AUTHORING_CODEX"], "--output", str(output)]
    if os.environ.get("SAFEYOLO_HARNESS_AUTHORING_COORD"):
        command += ["--coord", os.environ["SAFEYOLO_HARNESS_AUTHORING_COORD"]]
    result = subprocess.run(command, capture_output=True, text=True, timeout=260)
    report = json.loads(result.stdout)
    assert result.returncode == 0, report
    assert report["state"] == "installed_qualified"
    assert report["boundary"] == "ordinary.task_and_resume"
    assert len(report["evidence"]) == 2
