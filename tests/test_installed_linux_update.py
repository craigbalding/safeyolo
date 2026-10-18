"""Check the installed update observer's identities and bounded hosted caller."""

import copy
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
import yaml

from tests.blackbox import installed_linux_update as update

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.safe_load((ROOT / ".github/workflows/installed-arm64.yml").read_text())
JOB = WORKFLOW["jobs"]["installed-update"]


@pytest.mark.parametrize("expected", [0, 1])
@pytest.mark.parametrize("damage", [None, "index", "manifest", "archive", "platform", "compatibility"])
def test_update_observer_requires_each_published_selection_identity(tmp_path, expected, damage):
    manifest, archive, size = update.CHAINS["arm64"][expected]
    selection = {"index": {"digest": (update.G1, update.G2)[expected]},
                 "manifest": {"digest": "sha256:" + manifest},
                 "archive": {"digest": "sha256:" + archive, "size": size},
                 "platform": "linux/arm64", "compatibility": "v1"}
    if damage in {"index", "manifest", "archive"}:
        selection[damage]["digest"] = "sha256:" + "0" * 64
    elif damage:
        selection[damage] = "wrong"
    (tmp_path / "share").mkdir()
    (tmp_path / "share/guest-selection.json").write_text(json.dumps(selection))
    if damage:
        with pytest.raises(AssertionError):
            update.check_selection(tmp_path, "arm64", expected)
    else:
        assert update.check_selection(tmp_path, "arm64", expected) == selection


def test_reuse_observation_accepts_alias_move_and_detects_replaced_base():
    before = {name: {"path": "/old/" + name, "device": 1, "inode": index, "mtime_ns": 1}
              for index, name in enumerate(("rootfs-tree", "cache-paths.txt"))}
    after = copy.deepcopy(before)
    after["rootfs-tree"].update(path="/new/rootfs-tree", mtime_ns=2)
    assert update.same_guest_base(before, after)
    after["rootfs-tree"]["inode"] += 1
    assert not update.same_guest_base(before, after)


def test_configuration_comparison_excludes_only_native_derived_fields(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text('reload_id = "first"\nlisteners = []\n[linux]\nuid_base = 100000\n')
    before = update.operator_settings(path)
    path.write_text('reload_id = "second"\nlisteners = [{agent_id="bbtest"}]\n[linux]\nuid_base = 100000\n')
    assert update.operator_settings(path) == before
    path.write_text('[linux]\nuid_base = 165536\n')
    assert update.operator_settings(path) != before


def test_report_redacts_installation_tokens_in_normal_and_timeout_output(tmp_path):
    (tmp_path / "data").mkdir()
    for name in ("admin_token", "agent_token"):
        (tmp_path / "data" / name).write_text(name + "-secret\n")
    for text in ("admin_token-secret agent_token-secret ordinary", b"admin_token-secret agent_token-secret ordinary"):
        assert update.redact(text, tmp_path) == "[redacted] [redacted] ordinary"


@pytest.mark.parametrize("damage", [None, "checksum", "size", "interrupted"])
def test_host_acquisition_verifies_both_archives_before_observer(tmp_path, damage):
    source = tmp_path / "package-info"
    source.write_text("public fixture\n")
    archive = tmp_path / "fixture.tar.gz"
    with tarfile.open(archive, "w:gz") as stream:
        stream.add(source, arcname="safeyolo-linux-arm64-production/package-info")
    checksum = update.sha(archive)
    sums = tmp_path / "sums"
    sums.write_text(f"{checksum}  safeyolo-linux-arm64-production.tar.gz\n")
    tools = tmp_path / "tools"
    tools.mkdir()
    curl = tools / "curl"
    curl.write_text(f"#!{sys.executable}\n" + '''import os,shutil,sys
from pathlib import Path
args = sys.argv[1:]
url = next(arg for arg in args if arg.startswith('https://'))
assert url.startswith('https://github.com/craigbalding/safeyolo/releases/download/host-')
assert not any('Authorization' in arg for arg in args)
output = Path(args[args.index('--output') + 1])
source = Path(os.environ['SUMS'] if url.endswith('SHA256SUMS') else os.environ['ARCHIVE'])
shutil.copyfile(source, output)
if os.environ['DAMAGE'] == 'interrupted' and not url.endswith('SHA256SUMS'):
    output.write_bytes(output.read_bytes()[:20])
    sys.exit(18)
''')
    curl.chmod(0o755)
    selected = next(step for step in JOB["steps"] if step.get("name") == "Acquire the two published ARM64 host archives")
    script = selected["run"]
    for digest, size in ((WORKFLOW["env"]["HOST_SHA256"], "176869006"),
                         ("dd51dc5a74effde88c4160a91fffb406f938a438c4594b6a008a8019d1a257ea", "176883685")):
        script = script.replace(digest, "0" * 64 if damage == "checksum" else checksum)
        script = script.replace(size, str(archive.stat().st_size + (1 if damage == "size" else 0)))
    result = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
                            env={**os.environ, "PATH": f"{tools}:{os.environ['PATH']}", "RUNNER_TEMP": str(tmp_path),
                                 "GITHUB_ENV": str(tmp_path / "env"), "SUMS": str(sums), "ARCHIVE": str(archive),
                                 "DAMAGE": damage or ""},
                            capture_output=True, text=True, timeout=10)
    assert (result.returncode == 0) == (damage is None), result.stdout + result.stderr
    extracted = list((tmp_path / "installed-update").glob("*/safeyolo-linux-arm64-production/package-info"))
    assert len(extracted) == (2 if damage is None else 0)


@pytest.mark.parametrize("failure", [0, 7, 124])
def test_workflow_propagates_observer_failure_and_uses_published_bundles(tmp_path, failure):
    tools = tmp_path / "tools"
    tools.mkdir()
    capture = tmp_path / "call.json"
    python = tools / "python3"
    python.write_text(f"#!{sys.executable}\n" +
                      "import json,os,sys; from pathlib import Path; " +
                      "Path(os.environ['CAPTURE']).write_text(json.dumps(sys.argv[1:])); " +
                      "sys.exit(int(os.environ['EXIT']))\n")
    python.chmod(0o755)
    selected = next(step for step in JOB["steps"] if step.get("name") == "Observe the connected installed update journey")
    result = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", selected["run"]],
                            env={**os.environ, "PATH": f"{tools}:{os.environ['PATH']}", "CAPTURE": str(capture),
                                 "EXIT": str(failure), "INSTALLED_UPDATE_WORK": str(tmp_path)},
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == failure, result.stdout + result.stderr
    args = json.loads(capture.read_text())
    assert args[:2] == ["-B", "tests/blackbox/installed_linux_update.py"]
    assert args[args.index("--initial") + 1] == str(tmp_path / update.INITIAL / "safeyolo-linux-arm64-production")
    assert args[args.index("--target") + 1] == str(tmp_path / update.TARGET / "safeyolo-linux-arm64-production")
    assert JOB["runs-on"] == "ubuntu-24.04-arm" and JOB["permissions"] == {"contents": "read"}
    upload = JOB["steps"][-1]
    assert upload["if"] == "always()"
    assert upload["with"]["path"] == "${{ env.INSTALLED_UPDATE_WORK }}/journey/observed.json"
