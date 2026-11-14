"""Installed example preparation preserves authority and selects exact artifacts."""

import base64
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
SKILL = REPO / "cli/src/safeyolo/agent_context/skills/job-authoring"


@pytest.fixture
def installed(tmp_path):
    root = tmp_path / "installed"
    runtime = root / "assets/hyperlight"
    runtime.mkdir(parents=True)
    shutil.copytree(SKILL, root / "assets/skills/job-authoring")
    configuration = (REPO / "tests/blackbox/fixtures/hyperlight-adoption/config.toml").read_text()
    (root / "config.toml").write_text('policy_file="policy/current.toml"\n' + configuration)
    (root / "policy").mkdir()
    (root / "policy/current.toml").write_text('''# Retain existing operator choices.
[hosts."*"]
egress="deny"
[hosts."api.github.com"]
egress="deny"
[agents]
keeper={token="synthetic-local-token",services={github="read_work"}}
[lists]
existing="existing.txt"
''')
    (root / "policy/existing.txt").write_text("example.test\n")
    (root / "assets/services").mkdir()
    shutil.copyfile(REPO / "cli/src/safeyolo/services/github.yaml", root / "assets/services/github.yaml")
    for name in ("runtime.json", "core.elf", "checker.py", "service_checker.py", "artifact_checker.py"):
        (runtime / name).write_text(name)
    spec = importlib.util.spec_from_file_location("builder", REPO / "scripts/build_hyperlight_jobs.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    builder.write_job_definitions(runtime)
    return root


def run(root, output, engine="hyperlight", bundle=None):
    return subprocess.run([sys.executable, str(root / "assets/skills/job-authoring/scripts/prepare.py"),
        "--root", str(root), "--engine", engine, "--repository", "owner/repository", "--author-id", "42",
        "--issue", "1", "--room", "engineering", "--factory", "example", "--credential", "existing-github",
        "--output", str(output), *(["--bundle", str(bundle)] if bundle else [])], capture_output=True, text=True)


@pytest.mark.parametrize("engine", ["hyperlight", "hyperlight-unikraft"])
@pytest.mark.parametrize("linked_bundle", [False, True])
def test_installed_helper_proposes_scoped_authority_without_applying(installed, tmp_path, engine, linked_bundle):
    if linked_bundle:
        runtime = installed / "assets/hyperlight"
        runtime.rename(installed / "assets/selected-hyperlight")
        runtime.symlink_to("selected-hyperlight", target_is_directory=True)
    policy = installed / "policy/current.toml"
    original = policy.read_bytes()
    output = tmp_path / "candidate"
    result = run(installed, output, engine)
    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["root"] == str(installed)
    assert receipt["saved_policy"] == str(policy)
    assert receipt["bundle"] == str(installed / "assets/hyperlight")
    assert receipt["service_target"] == str(installed / "data/services/github.yaml")
    assert receipt["activation"] == "not applied"
    assert policy.read_bytes() == original
    assert not (installed / "data/services/github.yaml").exists()
    candidate = tomllib.loads((output / "candidate.toml").read_text())
    assert "# Retain existing operator choices." in (output / "candidate.toml").read_text()
    assert candidate["hosts"]["api.github.com"]["egress"] == "deny"
    assert candidate["agents"]["keeper"] == {"token": "synthetic-local-token", "services": {"github": "read_work"}}
    assert candidate["lists"]["existing"] == str(installed / "policy/existing.txt")
    author = candidate["checks"]["example_issue_author"]
    assert author["inputs"] == {"repository": "owner/repository", "expected_author_id": "42"}
    assert author.get("invokers", []) == []
    assert author["source"]["spec"] == str(installed / f"assets/hyperlight/{engine}-service.json")
    for name in ("example_issue_author", "example_artifact"):
        assert candidate["checks"][name]["source"]["limits"]["timeout_ms"] == (
            10000 if engine == "hyperlight" else 20000)
    assert [item["boundary"] for item in candidate["work_bindings"]] == ["admit_issue", "verify_output"]
    assert all(item["on_failure"] == "hold" for item in candidate["work_bindings"])
    service = yaml.safe_load((output / "github.yaml").read_text())
    assert service["capabilities"]["read_work"]
    assert service["capabilities"]["read_example_issues"]["routes"] == [
        {"methods": ["GET"], "path": "/repos/owner/repository/issues/*"}]
    assert candidate["agents"]["gate:hyperlight-service-check"]["services"]["github"] == {
        "capability": "read_example_issues", "token": "existing-github"}
    assert output.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in output.iterdir())


@pytest.mark.parametrize("engine", ["hyperlight", "hyperlight-unikraft"])
def test_preparation_selects_developed_bundle_without_replacing_installed_bytes(installed, tmp_path, engine):
    original = (installed / "policy/current.toml").read_bytes()
    runtime = installed / "assets/hyperlight"
    proposed = tmp_path / "proposed-bundle"
    shutil.copytree(runtime, proposed)
    spec_path = proposed / f"{engine}-service.json"
    spec = json.loads(spec_path.read_text())
    selected = spec["engine"]["guest" if engine == "hyperlight" else "checker"]
    artifact = proposed / selected["path"]
    installed_bytes = (runtime / selected["path"]).read_bytes()
    artifact.write_bytes(b"developed checker")
    output = tmp_path / "candidate"
    refused = run(installed, output, engine, proposed)
    assert refused.returncode != 0
    assert "Selected checker digest differs" in refused.stderr
    assert not output.exists()
    selected["sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
    spec_path.write_text(json.dumps(spec))
    artifact_spec_path = proposed / f"{engine}-artifact.json"
    artifact_spec = json.loads(artifact_spec_path.read_text())
    artifact_selection = artifact_spec["engine"]["guest" if engine == "hyperlight" else "checker"]
    if artifact_selection["path"] == selected["path"]:
        artifact_selection["sha256"] = selected["sha256"]
        artifact_spec_path.write_text(json.dumps(artifact_spec))
    result = run(installed, output, engine, proposed)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["bundle"] == str(proposed)
    candidate = tomllib.loads((output / "candidate.toml").read_text())
    author = candidate["checks"]["example_issue_author"]
    assert author["source"]["spec"] == str(spec_path)
    assert author["implementation_version"] == selected["sha256"]
    assert author["configuration_version"] == hashlib.sha256(spec_path.read_bytes()).hexdigest()
    assert (runtime / selected["path"]).read_bytes() == installed_bytes
    assert (installed / "policy/current.toml").read_bytes() == original


@pytest.mark.parametrize("conflict", ["grant", "binding", "artifact"])
def test_preparation_refuses_conflicts_instead_of_replacing_adopted_authority(installed, tmp_path, conflict):
    policy = installed / "policy/current.toml"
    if conflict == "grant":
        with policy.open("a") as stream:
            stream.write('\n[agents."gate:hyperlight-service-check".services]\ngithub={capability="other",token="keep"}\n')
    elif conflict == "binding":
        with policy.open("a") as stream:
            stream.write('\n[[work_bindings]]\nname="example_issue_author"\nroom="another"\n')
    else:
        (installed / "assets/hyperlight/core.elf").write_text("substituted guest")
    original = policy.read_bytes()
    output = tmp_path / "candidate"
    result = run(installed, output)
    assert result.returncode != 0
    assert not output.exists()
    assert policy.read_bytes() == original


def test_publication_fields_bind_the_actual_bytes(installed, tmp_path):
    artifact = tmp_path / "result.json"
    artifact.write_bytes(b'{"status":"ready","title":"\xcf\x80"}\n')
    result = subprocess.run([sys.executable, str(installed / "assets/skills/job-authoring/scripts/publication.py"),
                             str(artifact)], capture_output=True, text=True, check=True)
    fields = json.loads(result.stdout)
    assert fields["target_ref"] == "sha256:3d31719fb7270dfaf4cbe275dbf74d13209c40c1355a588b4ab53a44e8328b15"
    assert base64.b64decode(fields["artifact_base64"]) == artifact.read_bytes()
