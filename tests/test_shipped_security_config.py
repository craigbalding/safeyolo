"""Regression checks for shipped credential, scanner, and triage defaults."""

import tomllib
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
ADDONS_CONFIGS = [
    REPO_ROOT / "config/addons.yaml",
    REPO_ROOT / "cli/src/safeyolo/templates/addons.yaml",
]
POLICY_YAML_CONFIGS = [
    REPO_ROOT / "config/policy.yaml",
    REPO_ROOT / "cli/src/safeyolo/templates/policy.yaml",
]

PROVIDER_HOST_CREDENTIALS = {
    "api.openai.com": ["openai:*"],
    "api.anthropic.com": ["anthropic:*"],
    "openrouter.ai": ["openrouter:*"],
    "api.x.ai": ["xai:*"],
    "api.groq.com": ["groq:*"],
    "api.github.com": ["github:*"],
    "github.com": ["github:*"],
    "*.googleapis.com": ["google:*"],
    "huggingface.co": ["huggingface:*"],
    "*.huggingface.co": ["huggingface:*"],
}


@pytest.mark.parametrize("config_path", ADDONS_CONFIGS, ids=["source", "template"])
def test_shipped_addons_enable_secret_scanning(config_path):
    config = yaml.safe_load(config_path.read_text())

    assert config["addons"]["pattern_scanner"]["enabled"] is True
    assert config["addons"]["pattern_scanner"]["builtin_sets"] == ["secrets"]


@pytest.mark.parametrize("config_path", ADDONS_CONFIGS, ids=["source", "template"])
def test_shipped_addons_scan_google_api_key_header(config_path):
    config = yaml.safe_load(config_path.read_text())

    headers = config["addons"]["credential_guard"]["standard_auth_headers"]
    assert "x-goog-api-key" in headers


@pytest.mark.parametrize("config_path", ADDONS_CONFIGS, ids=["source", "template"])
def test_shipped_addons_quiet_all_anthropic_event_logging_batches(config_path):
    config = yaml.safe_load(config_path.read_text())

    paths = config["addons"]["request_logger"]["quiet_hosts"]["paths"]
    assert paths["api.anthropic.com"] == ["/api/event_logging/*batch"]


@pytest.mark.parametrize("config_path", POLICY_YAML_CONFIGS, ids=["source", "template"])
def test_shipped_yaml_policies_do_not_repeat_builtin_classifiers(config_path):
    credentials = yaml.safe_load(config_path.read_text()).get("credentials", {})

    assert set(credentials) <= {"safeyolo_gateway"}


def test_shipped_toml_policy_does_not_repeat_builtin_classifiers():
    config_path = REPO_ROOT / "cli/src/safeyolo/templates/policy.toml"
    credentials = tomllib.loads(config_path.read_text()).get("credential", {})

    assert credentials == {}


@pytest.mark.parametrize("config_path", POLICY_YAML_CONFIGS, ids=["source", "template"])
def test_shipped_yaml_policies_authorize_provider_specific_types(config_path):
    hosts = yaml.safe_load(config_path.read_text())["hosts"]

    for host, credential_types in PROVIDER_HOST_CREDENTIALS.items():
        assert hosts[host]["credentials"] == credential_types


def test_shipped_toml_policy_authorizes_provider_specific_types():
    config_path = REPO_ROOT / "cli/src/safeyolo/templates/policy.toml"
    hosts = tomllib.loads(config_path.read_text())["hosts"]

    for host, credential_types in PROVIDER_HOST_CREDENTIALS.items():
        assert hosts[host]["allow"] == credential_types


def test_credential_guard_triage_explains_default_rules():
    graph_path = (
        REPO_ROOT
        / "cli/src/safeyolo/agent_context/skills/safeyolo/references/graph"
        / "triage-credential-guard.yaml"
    )
    graph = yaml.safe_load(graph_path.read_text())
    node = next(node for node in graph["nodes"] if node["id"] == "ev.credguard_check_config_rules")

    assert "policy-supplied only" in node["label"]
    assert "DEFAULT_RULES load separately" in node["label"]
    assert "empty means entropy-only detection" not in node["label"]
