"""Exercise offline wheel preparation and transferred-input rejection."""

import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests.blackbox import installed_lifecycle, installed_sections
from tests.blackbox import installed_staging as staging

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def staged_payload(tmp_path, monkeypatch):
    checkout = tmp_path / "source"
    checkout.mkdir()
    for name in ("uv.lock", "pyproject.toml"):
        (checkout / name).write_text("fixture selected inputs\n")
    observer = tmp_path / "input-invocations.jsonl"
    observe = f"""
import json, os
from pathlib import Path
with Path({str(observer)!r}).open('a') as output:
    output.write(json.dumps({{'command': __file__, 'has_principal': 'GH_TOKEN' in os.environ,
                             'proxy': os.environ.get('HTTPS_PROXY'), 'ca': os.environ.get('SSL_CERT_FILE')}}) + '\\n')
"""
    vm = checkout / "vm"
    vm.mkdir()
    (vm / "build-info.py").write_text(observe + "import sys\nassert sys.argv[1:4] == ['verify', '--profile', 'production']\n")
    (checkout / ".gitignore").write_text("proxy/target/\n")
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    subprocess.run(["git", "-C", str(checkout), "add", "."], check=True)
    subprocess.run(["git", "-C", str(checkout), "-c", "user.name=Fixture",
                    "-c", "user.email=fixture@example.test", "-c", "core.hooksPath=/dev/null",
                    "commit", "-qm", "Selected source"], check=True)
    revision = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
    nats_bytes = b"#!/bin/sh\nprintf 'fixture-nats\\n'\n"
    nats_hash = hashlib.sha256(nats_bytes).hexdigest()
    wheel = tmp_path / "safeyolo-0.1.0-py3-none-any.whl"
    contents = {
        "safeyolo/__init__.py": observe,
        "safeyolo/traffic_session.py": (ROOT / "cli/src/safeyolo/traffic_session.py").read_text(),
        "safeyolo/runtime_identity.py": (ROOT / "cli/src/safeyolo/runtime_identity.py").read_text(),
        "safeyolo/config.py": """
import os
from pathlib import Path
def get_config_dir(): return Path(os.environ['SAFEYOLO_CONFIG_DIR'])
def get_data_dir(): return get_config_dir() / 'data'
""",
        "safeyolo/_build_identity.json": json.dumps({"state": "known", "source_revision": revision}),
        "safeyolo/cli.py": observe + """
import os, sys
from pathlib import Path
def main():
    if '--version' in sys.argv:
        print('safeyolo 0.1.0')
    else:
        assert sys.argv[1:] == ['init', '--no-interactive']
        root = Path(os.environ['SAFEYOLO_CONFIG_DIR'])
        for name in ('bin', 'share', 'data'):
            (root / name).mkdir(parents=True)
""",
        "safeyolo/bin/safeyolo-proxy": f"#!{sys.executable}\n" + observe + "print('safeyolo-proxy 0.1.0 (fixture)')\n",
        "safeyolo/coord/__init__.py": "",
        "safeyolo/coord/nats_runtime.py": f"""
import hashlib, os
from pathlib import Path
NATS_VERSION = 'fixture-version'
def _sha256_of(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def _expected_binary_sha256(): return {nats_hash!r}
def nats_binary_path(): return Path(os.environ['SAFEYOLO_COORD_DATA_DIR']) / 'nats/bin/fixture-version/nats-server'
def ensure_binary():
    target = nats_binary_path()
    assert _sha256_of(target) == _expected_binary_sha256()
    return target
""",
        "safeyolo-0.1.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: safeyolo\nVersion: 0.1.0\n",
        "safeyolo-0.1.0.dist-info/WHEEL": "Wheel-Version: 1.0\nGenerator: fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        "safeyolo-0.1.0.dist-info/entry_points.txt": "[console_scripts]\nsafeyolo = safeyolo.cli:main\n",
        "safeyolo-0.1.0.dist-info/RECORD": "",
    }
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, value in contents.items():
            info = zipfile.ZipInfo(name)
            info.external_attr = (0o100755 if name.endswith("safeyolo-proxy") else 0o100644) << 16
            archive.writestr(info, value)
    native = checkout / "proxy/target/release/safeyolo-proxy"
    native.parent.mkdir(parents=True)
    native.write_text(contents["safeyolo/bin/safeyolo-proxy"])
    native.chmod(0o755)
    prepared = tmp_path / "prepared-build"
    for name in ("bin/safeyolo-vm", "bin/vsock-term", *(f"share/{name}" for name in staging.BOOT_FILES)):
        path = prepared / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"fixture input " + name.encode())
    nats = prepared / "data/coord/nats/bin/fixture-version/nats-server"
    nats.parent.mkdir(parents=True)
    nats.write_bytes(nats_bytes)
    nats.chmod(0o755)
    tmux = prepared / "bin/safeyolo-tmux"
    tmux.write_text(f"#!{sys.executable}\n" + observe + "print('tmux 3.7c')\n")
    tmux.chmod(0o755)
    for name in staging.TMUX_LICENSES:
        path = prepared / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture license")
    (prepared / "data/admin_token").write_text("private-build-secret")
    (prepared / "vault.json").write_text("private-build-secret")
    provenance = tmp_path / "boot-provenance.json"
    provenance.write_text(json.dumps({name: {"source_revision": digit * 40,
                                          "sha256": staging._sha256(prepared / "share" / name)}
                                     for name, digit in zip(staging.BOOT_FILES, "bcd")}))
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    # No dependencies are needed by this tiny installed fixture. The payload
    # still exercises the directory's closed set of hashed wheel inputs.
    (wheelhouse / "unused-1.0-py3-none-any.whl").write_bytes(b"unused hashed fixture")
    helper = {"git_sha": revision, "git_dirty": False, "architecture": "arm64", "build_profile": "production"}
    executable = prepared / "bin/safeyolo-vm"
    executable.write_text(f"#!{sys.executable}\n" + observe + f"print({json.dumps(helper)!r})\n")
    executable.chmod(0o755)
    commands = tmp_path / "staging-commands"
    commands.mkdir()
    uv = shutil.which("uv")
    assert uv
    for name, code in {
        "codesign": "",
        "otool": "import sys\nprint(sys.argv[-1]+':\\n\\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)')\n",
        "uv": f"import sys\nif sys.argv[1] != 'export': os.execv({uv!r}, [{uv!r}, *sys.argv[1:]])\n",
    }.items():
        command = commands / name
        command.write_text(f"#!{sys.executable}\n" + observe + code)
        command.chmod(0o755)
    monkeypatch.setenv("PATH", f"{commands}:{os.environ['PATH']}")
    monkeypatch.setattr(staging.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(staging.platform, "machine", lambda: "arm64")
    payload = tmp_path / "payload"
    index = staging.package_inputs(checkout, revision, wheel, wheelhouse, prepared, provenance, payload)
    return payload, staging._sha256(index), checkout, revision


def test_packaging_and_offline_identity_calls_keep_principals_out(tmp_path, staged_payload, monkeypatch):
    payload, _, checkout, revision = staged_payload
    monkeypatch.setenv("GH_TOKEN", "fake-publication-principal")
    monkeypatch.setenv("HTTPS_PROXY", "http://fixture-mediated-proxy")
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "fixture-ca"))
    observer = tmp_path / "input-invocations.jsonl"
    observer.unlink()
    index = staging.package_inputs(checkout, revision, next((payload / "wheel").glob("*.whl")),
                                   payload / "wheelhouse", tmp_path / "prepared-build",
                                   tmp_path / "boot-provenance.json", tmp_path / "repackaged",
                                   env=staging.staging_environment())
    directory = tmp_path / "execution"
    directory.mkdir()
    env = staging.staging_environment()
    env.update(SAFEYOLO_CONFIG_DIR=str(directory / "prepared"),
               SAFEYOLO_COORD_DATA_DIR=str(directory / "prepared/data/coord"))
    report = staging.prepare_inputs(index.parent, staging._sha256(index), checkout, revision,
                                    directory, Path(sys.executable), env)
    assert report["source_revision"] == revision and report["tmux_version"] == "tmux 3.7c"
    observations = [json.loads(line) for line in observer.read_text().splitlines()]
    commands = {Path(row["command"]).name for row in observations}
    assert {"safeyolo-vm", "build-info.py", "safeyolo-tmux", "cli.py", "safeyolo-proxy", "__init__.py", "uv"} <= commands
    assert all(not row["has_principal"] and row["proxy"] == env["HTTPS_PROXY"]
               and row["ca"] == env["SSL_CERT_FILE"] for row in observations)


def test_offline_preparation_installs_once_and_preserves_boot_provenance(tmp_path, staged_payload, monkeypatch):
    payload, digest, checkout, revision = staged_payload
    (checkout / "proxy/target/release/safeyolo-proxy").unlink()
    # An unindexed transfer residue must not become a runtime input merely
    # because it shares a directory with verified boot files or helpers.
    (payload / "share/cache-paths.txt").write_text("/unapproved-host-path\n")
    (payload / "bin/unapproved-helper").write_text("unapproved helper")
    directory = tmp_path / "execution"
    directory.mkdir()
    source = directory / "prepared"
    env = {**os.environ, "SAFEYOLO_CONFIG_DIR": str(source),
           "SAFEYOLO_COORD_DATA_DIR": str(source / "data/coord"),
           "UV_CACHE_DIR": str(tmp_path / "empty-cache")}
    report = staging.prepare_inputs(payload, digest, checkout, revision, directory, Path(sys.executable), env)
    assert report["source_revision"] == revision
    assert report["nats_version"] == "fixture-version"
    assert report["tmux_version"] == "tmux 3.7c"
    assert report["tmux_sha256"] == staging._sha256(payload / "bin/safeyolo-tmux")
    assert [item["source_revision"] for item in report["boot_inputs"].values()] == [digit * 40 for digit in "bcd"]
    for name in staging.BOOT_FILES:
        assert (source / "share" / name).resolve() == payload / "share" / name
    assert (source / "bin/safeyolo-vm").resolve() == payload / "bin/safeyolo-vm"
    assert (source / "bin/safeyolo-tmux").resolve() == payload / "bin/safeyolo-tmux"
    assert not (source / "share/cache-paths.txt").exists()
    assert not (source / "bin/unapproved-helper").exists()
    assert (source / "data/coord/nats/bin/fixture-version/nats-server").read_bytes() == (payload / "nats/nats-server").read_bytes()
    assert not (source / "data/admin_token").exists()
    assert not any(b"private-build-secret" in path.read_bytes() for path in payload.rglob("*") if path.is_file())
    for name in ("cli", "tests"):
        installed = directory / name / "bin/python"
        subprocess.run([str(installed), "-I", "-c",
                        f"import safeyolo, pathlib, json; p=pathlib.Path(safeyolo.__file__); assert 'site-packages' in str(p); assert json.loads((p.parent/'_build_identity.json').read_text())['source_revision']=={revision!r}"],
                       check=True)
    assert not (checkout / ".venv").exists(), "offline preparation must not invoke uv sync"
    assert (checkout / "proxy/target/release/safeyolo-proxy").read_bytes() == (payload / "native/safeyolo-proxy").read_bytes()

    owner = directory / "lifecycle-owner"
    primary_env = dict(env, SAFEYOLO_NATS_TEST_INSTANCE="primary-instance", SAFEYOLO_NATS_TEST_PORTS="46370,46372",
                       SAFEYOLO_LIFECYCLE_OWNER_NATS_TEST_INSTANCE="owner-instance",
                       SAFEYOLO_LIFECYCLE_OWNER_NATS_TEST_PORTS="46377,46378")
    owner_env = installed_sections.lifecycle_owner_environment(owner, env=primary_env)

    def failed_prepare(command, *, env, **_kwargs):
        # The installed consumer must find the pinned runtime before even a
        # failed first CLI call. No package index or source import is available.
        subprocess.run([str(directory / "cli/bin/python"), "-I", "-c",
                        "from safeyolo.coord.nats_runtime import ensure_binary; ensure_binary()"],
                       env=env, check=True)
        assert env["SAFEYOLO_NATS_TEST_INSTANCE"] == "owner-instance"
        assert env["SAFEYOLO_NATS_TEST_PORTS"] == "46377,46378"
        assert env["SAFEYOLO_COORD_DATA_DIR"] == str(owner / "data/coord")
        assert command[1:] == ["init", "--no-interactive"]
        raise OSError("injected owner preparation failure")

    monkeypatch.setattr(installed_lifecycle, "checked", failed_prepare)
    with pytest.raises(OSError, match="injected owner preparation failure"):
        installed_lifecycle.prepare_owner(str(directory / "bin/safeyolo"), owner, source, {}, "unused",
                                          tmp_path / "owner-runtime.json", env=owner_env)
    assert owner_env == installed_sections.lifecycle_owner_environment(owner, env=primary_env)
    assert (owner / "data/coord/nats/bin/fixture-version/nats-server").read_bytes() == (payload / "nats/nats-server").read_bytes()
    assert not (owner / "bin").exists(), "owner preparation reuses its later bootstrapped bin symlink"
    assert primary_env["SAFEYOLO_NATS_TEST_INSTANCE"] == "primary-instance"


def test_boot_provenance_annotations_do_not_reach_transfer_or_preparation_reports(tmp_path, staged_payload, monkeypatch):
    payload, _, checkout, revision = staged_payload
    provenance_path = tmp_path / "boot-provenance.json"
    expected = json.loads(provenance_path.read_text())
    annotated = json.loads(provenance_path.read_text())
    marker = "fixture-provenance-secret"
    for name in staging.BOOT_FILES:
        annotated[name]["operator_private_context"] = {"admin_token": marker, "nested": [{"note": marker}]}
    provenance_path.write_text(json.dumps(annotated))
    index_path = staging.package_inputs(
        checkout, revision, next((payload / "wheel").glob("*.whl")), payload / "wheelhouse",
        tmp_path / "prepared-build", provenance_path, tmp_path / "repackaged",
    )
    packaged = json.loads(index_path.read_text())

    # Also consume a correctly hashed older index carrying annotations: its
    # preparation report must omit private fields even if its producer did not.
    transferred = {**packaged, "boot_inputs": annotated}
    index_path.write_text(json.dumps(transferred))
    # Packaging uses controlled Mac command fixtures. The new offline child
    # observes its actual host rather than inheriting the parent's Python patch.
    transferred["host"] = {"system": "Darwin" if sys.platform == "darwin" else "Linux",
                           "machine": os.uname().machine}
    index_path.write_text(json.dumps(transferred))
    directory = tmp_path / "execution"
    directory.mkdir()
    artifacts = tmp_path / "reports"
    # Exercise real offline preparation and its retained report, without
    # starting a hardware section in this fixture.
    result = installed_sections.run_sections(
        "vz", (), checkout, revision, directory, artifacts,
        staged_inputs=index_path.parent, staged_sha256=staging._sha256(index_path), python=Path(sys.executable),
    )
    report_text = (artifacts / "installed-sections.json").read_text()
    report = json.loads(report_text)
    assert result == 0 and report["preparation"]["exit"] == 0
    assert packaged["boot_inputs"] == expected
    assert marker not in json.dumps(packaged)
    assert report["preparation"]["boot_inputs"] == expected
    assert marker not in report_text
    assert json.loads(provenance_path.read_text()) == annotated, "source annotations remain available on the build host"
    summary_text = (artifacts / "installed-summary.json").read_text()
    summary = json.loads(summary_text)
    assert summary["preparation"]["boot_inputs"] == expected
    assert summary["preparation"]["native_sha256"] == report["preparation"]["native_sha256"]
    assert summary["exit"] == 0 and summary["full_section_selection"] is False
    assert "cli" not in summary["preparation"] and str(tmp_path) not in summary_text
    assert marker not in summary_text


def test_offline_preparation_cancellation_stops_the_real_installer_child(tmp_path, staged_payload):
    """Cancel the maintained offline consumer while its benign uv child is live."""
    from safeyolo.runtime_identity import process_is_alive

    payload, _, checkout, revision = staged_payload
    index = payload / staging.INDEX_NAME
    data = json.loads(index.read_text())
    data["host"] = {"system": "Darwin" if sys.platform == "darwin" else "Linux", "machine": os.uname().machine}
    index.write_text(json.dumps(data))
    heartbeat, identities, reaped = (tmp_path / name for name in ("heartbeat", "children.json", "reaped"))
    uv = tmp_path / "staging-commands/uv"
    uv.write_text(f"#!{sys.executable}\n" + f'''
import json, os, pathlib, signal, subprocess, sys, time
if sys.argv[1] == 'export': raise SystemExit(0)
child = subprocess.Popen([sys.executable, '-I', '-c',
    "import pathlib,time\\np=pathlib.Path({str(heartbeat)!r})\\n"
    "while True: p.write_text(str(time.monotonic())); time.sleep(0.03)"])
pathlib.Path({str(identities)!r}).write_text(json.dumps({{'uv': os.getpid(), 'child': child.pid}}))
def interrupted(_signum, _frame):
    child.wait(timeout=5)
    pathlib.Path({str(reaped)!r}).write_text(str(child.returncode))
    raise SystemExit(0)
signal.signal(signal.SIGTERM, interrupted)
while True: time.sleep(0.05)
''')
    directory, artifacts = tmp_path / "execution", tmp_path / "reports"
    code = f'''
import sys
from pathlib import Path
sys.path[:0] = [{str(ROOT)!r}, {str(ROOT / 'cli/src')!r}]
from tests.blackbox.installed_sections import run_sections
raise SystemExit(run_sections('vz', ('access', 'lifecycle'), Path({str(checkout)!r}), {revision!r},
    Path({str(directory)!r}), Path({str(artifacts)!r}), staged_inputs=Path({str(payload)!r}),
    staged_sha256={staging._sha256(index)!r}, python=Path({sys.executable!r})))
'''
    with (tmp_path / "runner.log").open("w") as output:
        runner = subprocess.Popen([sys.executable, "-I", "-c", code], env=staging.staging_environment(),
                                  stdout=output, stderr=output)
        try:
            deadline = time.monotonic() + 10
            while not heartbeat.exists() and runner.poll() is None and time.monotonic() < deadline:
                time.sleep(0.025)
            assert heartbeat.exists(), (tmp_path / "runner.log").read_text()
            children = json.loads(identities.read_text())
            runner.send_signal(signal.SIGINT)
            time.sleep(0.1)
            runner.send_signal(signal.SIGHUP)  # Cleanup must retain the first reason.
            assert runner.wait(timeout=20) == 130
            assert reaped.exists()
            assert all(not process_is_alive(pid) for pid in children.values())
            summary_text = (artifacts / "installed-summary.json").read_text()
            summary = json.loads(summary_text)
            assert summary["exit"] == 130 and summary["cancellation"] == "SIGINT"
            assert summary["finished_at"] and summary["cleanup"] == "stopped"
            assert summary["preparation"]["exit"] == 130 and summary["preparation"]["cleanup"] == "stopped"
            assert summary["sections"] == [] and summary["unexecuted_sections"] == ["access", "lifecycle"]
            assert str(tmp_path) not in summary_text
        finally:
            if runner.poll() is None:
                runner.terminate()
                runner.wait(timeout=15)
            if identities.exists():
                for pid in json.loads(identities.read_text()).values():
                    if process_is_alive(pid):
                        os.kill(pid, signal.SIGKILL)


@pytest.mark.parametrize("failure", ["wrong-index", "mixed-source", "host", "tampered-wheel", "missing-boot",
                                     "outside", "extra-wheel", "changed-lock", "unfrozen-requirements", "boot-origin",
                                     "missing-tmux", "tampered-tmux", "missing-tmux-index", "invalid-tmux-version"])
def test_transfer_rejects_unverified_inputs_before_executing_payload(tmp_path, staged_payload, failure):
    payload, digest, checkout, revision = staged_payload
    index_path = payload / staging.INDEX_NAME
    index = json.loads(index_path.read_text())
    if failure == "wrong-index":
        digest = "0" * 64
    elif failure == "mixed-source":
        index["source_revision"] = "e" * 40
    elif failure == "host":
        index["host"]["machine"] = "x86_64"
    elif failure == "tampered-wheel":
        (payload / index["wheel"]).write_bytes(b"replaced wheel")
    elif failure == "missing-boot":
        (payload / "share/Image").unlink()
    elif failure == "missing-tmux":
        (payload / "bin/safeyolo-tmux").unlink()
    elif failure == "tampered-tmux":
        (payload / "bin/safeyolo-tmux").write_bytes(b"foreign runtime")
    elif failure == "missing-tmux-index":
        del index["files"]["bin/safeyolo-tmux"]
    elif failure == "invalid-tmux-version":
        index["tmux_version"] = "fixture-private-secret\n"
    elif failure == "outside":
        outside = tmp_path / "outside"
        outside.write_bytes(b"unapproved")
        index["files"]["../outside"] = staging._sha256(outside)
    elif failure == "extra-wheel":
        (payload / "wheelhouse/unverified.whl").write_bytes(b"unverified")
    elif failure == "changed-lock":
        (checkout / "uv.lock").write_text("changed lock")
    elif failure == "unfrozen-requirements":
        (payload / "runtime-requirements.txt").write_text("unapproved==1\n")
        index["files"]["runtime-requirements.txt"] = staging._sha256(payload / "runtime-requirements.txt")
    else:
        index["boot_inputs"]["Image"]["source_revision"] = "unknown"
    index_path.write_text(json.dumps(index))
    if failure != "wrong-index":
        digest = staging._sha256(index_path)
    with pytest.raises((ValueError, OSError)):
        staging.verified_inputs(payload, digest, checkout, revision)


def test_requirements_use_the_real_frozen_project_export():
    # This probes the uv exporter against the maintained lock, independently
    # of the dependency-free fixture used for offline installation above.
    checkout = Path(__file__).resolve().parents[1]
    runtime = staging.requirements(checkout, dev=False)
    tests = staging.requirements(checkout, dev=True)
    assert "--hash=sha256:" in runtime and "pytest==" not in runtime
    assert "pytest==" in tests and "--hash=sha256:" in tests
    assert "-e ." not in runtime + tests


def test_staging_help_runs_before_a_product_environment_exists(tmp_path):
    environment = tmp_path / "python"
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(environment)], check=True)
    env = {key: value for key, value in os.environ.items() if key not in {"PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"}}
    script = Path(__file__).resolve().parent / "blackbox/installed_staging.py"
    result = subprocess.run([str(environment / "bin/python"), str(script), "--help"],
                            env=env, cwd=tmp_path, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "--boot-provenance" in result.stdout


@pytest.mark.parametrize("signature_valid", [False, True])
def test_helper_signature_is_checked_before_transferred_code_runs(tmp_path, monkeypatch, signature_valid):
    commands = tmp_path / "commands"
    commands.mkdir()
    executed = tmp_path / "helper-executed"
    codesign = commands / "codesign"
    codesign.write_text(f"#!/bin/sh\nexit {0 if signature_valid else 7}\n")
    codesign.chmod(0o755)
    helper = tmp_path / "safeyolo-vm"
    identity = {"git_sha": "a" * 40, "git_dirty": False, "architecture": "arm64", "build_profile": "production"}
    helper.write_text(f"#!{sys.executable}\nfrom pathlib import Path\nPath({str(executed)!r}).touch()\nprint({json.dumps(identity)!r})\n")
    helper.chmod(0o755)
    vm = tmp_path / "source/vm"
    vm.mkdir(parents=True)
    (vm / "build-info.py").write_text("import sys\nassert sys.argv[1:4] == ['verify', '--profile', 'production']\n")
    monkeypatch.setenv("PATH", f"{commands}:{os.environ['PATH']}")
    if signature_valid:
        assert staging.helper_identity(vm.parent, helper, "a" * 40) == identity
        assert executed.exists()
    else:
        with pytest.raises(subprocess.CalledProcessError):
            staging.helper_identity(vm.parent, helper, "a" * 40)
        assert not executed.exists(), "an invalid signature must stop before executing the transferred helper"


def test_generated_input_index_shapes_fail_without_executing_payload(staged_payload):
    payload, _, checkout, revision = staged_payload
    path = payload / staging.INDEX_NAME
    original = json.loads(path.read_text())
    values = st.recursive(st.none() | st.booleans() | st.integers() | st.text(max_size=60),
                          lambda child: st.lists(child, max_size=5) | st.dictionaries(st.text(max_size=30), child, max_size=5),
                          max_leaves=10)

    @given(field=st.sampled_from(["schema_version", "source_revision", "host", "source_hashes", "files", "wheel",
                                 "wheel_identity", "boot_inputs", "tmux_version"]), value=values)
    def reject_or_verify(field, value):
        document = {**original, field: value}
        path.write_text(json.dumps(document))
        try:
            verified = staging.verified_inputs(payload, staging._sha256(path), checkout, revision)
        except (OSError, ValueError):
            return
        assert verified["source_revision"] == revision
        assert verified["wheel_identity"] == original["wheel_identity"]

    reject_or_verify()
