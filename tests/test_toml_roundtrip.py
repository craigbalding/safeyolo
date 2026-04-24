"""Tests for toml_roundtrip — TOML round-trip load/save with comment preservation.

Covers: load/save, comment preservation, atomic write (with real failure
simulation), mutation helpers (add_host_credential, update_host_field,
upsert_host, load_agents, upsert_agent, remove_agent, locked_policy_mutate,
policy_path_for_loader), error paths and fail-closed behaviour.
"""

from pathlib import Path
from unittest import mock

import pytest
import tomlkit


@pytest.fixture
def sample_toml() -> str:
    """Sample TOML policy content with comments."""
    return '''\
# SafeYolo baseline policy
version = "2.0"
description = "test policy"

budget = 12_000  # total req/min

required = ["credential_guard", "network_guard"]

[hosts]
# ── LLM APIs ──────────────────────
"api.openai.com"    = { allow = ["openai:*"], rate = 3_000 }
"api.anthropic.com" = { allow = ["anthropic:*"], rate = 3_000 }
# ── Defaults ──────────────────────
"*"                 = { unknown_creds = "prompt", rate = 600 }

[credential.openai]
match   = ['sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}']
headers = ["authorization", "x-api-key"]
'''


# =========================================================================
# load_roundtrip
# =========================================================================


class TestLoadRoundtrip:
    def test_loads_toml_and_preserves_values(self, sample_toml, tmp_path):
        from safeyolo.policy.toml_roundtrip import load_roundtrip

        path = tmp_path / "policy.toml"
        path.write_text(sample_toml)

        doc = load_roundtrip(path)
        assert doc["version"] == "2.0"
        assert doc["budget"] == 12000
        assert doc["hosts"]["api.openai.com"]["rate"] == 3000

    def test_missing_file_raises_file_not_found_error(self, tmp_path):
        from safeyolo.policy.toml_roundtrip import load_roundtrip

        with pytest.raises(FileNotFoundError):
            load_roundtrip(tmp_path / "nonexistent.toml")

    def test_malformed_toml_raises_parse_error(self, tmp_path):
        from safeyolo.policy.toml_roundtrip import load_roundtrip

        path = tmp_path / "bad.toml"
        path.write_text("this is = not valid [[[ toml")
        with pytest.raises(Exception) as exc_info:
            load_roundtrip(path)
        # tomlkit raises its own parse errors, not FileNotFoundError
        assert not isinstance(exc_info.value, FileNotFoundError)


# =========================================================================
# save_roundtrip — including real atomicity tests
# =========================================================================


class TestSaveRoundtrip:
    def test_round_trip_modification_survives_reload(self, sample_toml, tmp_path):
        from safeyolo.policy.toml_roundtrip import load_roundtrip, save_roundtrip

        path = tmp_path / "policy.toml"
        path.write_text(sample_toml)

        doc = load_roundtrip(path)
        doc["budget"] = 24000
        save_roundtrip(path, doc)

        reloaded = load_roundtrip(path)
        assert reloaded["budget"] == 24000

    def test_creates_parent_directories(self, tmp_path):
        from safeyolo.policy.toml_roundtrip import save_roundtrip

        path = tmp_path / "nested" / "sub" / "policy.toml"
        doc = tomlkit.document()
        doc.add("version", "2.0")
        save_roundtrip(path, doc)
        assert path.exists()

    def test_no_temp_file_leaked_after_success(self, sample_toml, tmp_path):
        """After a successful save, no .toml temp files should remain alongside."""
        from safeyolo.policy.toml_roundtrip import save_roundtrip

        path = tmp_path / "policy.toml"
        doc = tomlkit.parse(sample_toml)
        save_roundtrip(path, doc)

        # Only the target file should exist in the directory
        files = list(tmp_path.iterdir())
        assert files == [path]


class TestSaveRoundtripAtomicity:
    """Tests that prove the atomic-write promise by simulating failure."""

    def test_rename_failure_cleans_up_temp_file(self, sample_toml, tmp_path):
        """If shutil.move raises, save_roundtrip must unlink the temp file."""
        from safeyolo.policy.toml_roundtrip import save_roundtrip

        path = tmp_path / "policy.toml"
        doc = tomlkit.parse(sample_toml)

        with mock.patch("safeyolo.policy.toml_roundtrip.shutil.move", side_effect=OSError("simulated")):
            with pytest.raises(OSError, match="simulated"):
                save_roundtrip(path, doc)

        # No temp files should remain
        leftover = [p for p in tmp_path.iterdir() if p.suffix == ".toml"]
        assert leftover == []

    def test_rename_failure_preserves_original_file(self, sample_toml, tmp_path):
        """If the save fails, the original file must remain intact."""
        from safeyolo.policy.toml_roundtrip import load_roundtrip, save_roundtrip

        path = tmp_path / "policy.toml"
        path.write_text(sample_toml)
        original_content = path.read_text()

        doc = load_roundtrip(path)
        doc["budget"] = 99999

        with mock.patch("safeyolo.policy.toml_roundtrip.shutil.move", side_effect=OSError("fail")):
            with pytest.raises(OSError):
                save_roundtrip(path, doc)

        # Original content unchanged
        assert path.read_text() == original_content

    def test_fsync_is_called_on_tempfile(self, tmp_path):
        """save_roundtrip must fsync the tempfile before renaming (crash safety)."""
        from safeyolo.policy.toml_roundtrip import save_roundtrip

        path = tmp_path / "policy.toml"
        doc = tomlkit.document()
        doc.add("version", "2.0")

        with mock.patch("safeyolo.policy.toml_roundtrip.os.fsync") as fsync_mock:
            save_roundtrip(path, doc)

        # fsync called at least once (tempfile, and optionally parent dir)
        assert fsync_mock.called


# =========================================================================
# Comment preservation
# =========================================================================


class TestCommentPreservation:
    def test_comments_survive_budget_modification(self, sample_toml, tmp_path):
        from safeyolo.policy.toml_roundtrip import load_roundtrip, save_roundtrip

        path = tmp_path / "policy.toml"
        path.write_text(sample_toml)

        doc = load_roundtrip(path)
        doc["budget"] = 24000
        save_roundtrip(path, doc)

        content = path.read_text()
        assert "# SafeYolo baseline policy" in content
        assert "# total req/min" in content
        assert "# ── LLM APIs" in content
        assert "# ── Defaults" in content

    def test_comments_survive_inline_table_modification(self, sample_toml, tmp_path):
        from safeyolo.policy.toml_roundtrip import load_roundtrip, save_roundtrip

        path = tmp_path / "policy.toml"
        path.write_text(sample_toml)

        doc = load_roundtrip(path)
        doc["hosts"]["api.openai.com"]["rate"] = 5000
        save_roundtrip(path, doc)

        content = path.read_text()
        assert "# ── LLM APIs" in content
        reloaded = load_roundtrip(path)
        assert reloaded["hosts"]["api.openai.com"]["rate"] == 5000


# =========================================================================
# load_as_internal
# =========================================================================


class TestLoadAsInternal:
    def test_produces_normalized_internal_format(self, sample_toml, tmp_path):
        from safeyolo.policy.toml_roundtrip import load_as_internal

        path = tmp_path / "policy.toml"
        path.write_text(sample_toml)
        result = load_as_internal(path)

        assert result["metadata"]["version"] == "2.0"
        assert result["global_budget"] == 12000
        assert result["hosts"]["api.openai.com"]["credentials"] == ["openai:*"]
        assert result["hosts"]["api.openai.com"]["rate_limit"] == 3000
        assert result["hosts"]["*"]["unknown_credentials"] == "prompt"
        assert result["credentials"]["openai"]["patterns"] == [
            "sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}"
        ]
        assert result["required"] == ["credential_guard", "network_guard"]

    def test_file_not_found_error_propagates(self, tmp_path):
        from safeyolo.policy.toml_roundtrip import load_as_internal

        with pytest.raises(FileNotFoundError):
            load_as_internal(tmp_path / "missing.toml")


# =========================================================================
# add_host_credential
# =========================================================================


class TestAddHostCredential:
    def test_new_host_gets_allow_list(self, sample_toml, tmp_path):
        from safeyolo.policy.toml_roundtrip import add_host_credential, load_roundtrip

        path = tmp_path / "policy.toml"
        path.write_text(sample_toml)
        doc = load_roundtrip(path)
        add_host_credential(doc, "api.example.com", ["hmac:abc"])
        assert list(doc["hosts"]["api.example.com"]["allow"]) == ["hmac:abc"]

    def test_appends_to_existing_allow_list(self, sample_toml, tmp_path):
        from safeyolo.policy.toml_roundtrip import add_host_credential, load_roundtrip

        path = tmp_path / "policy.toml"
        path.write_text(sample_toml)
        doc = load_roundtrip(path)
        add_host_credential(doc, "api.openai.com", ["hmac:new"])
        allow = list(doc["hosts"]["api.openai.com"]["allow"])
        assert allow == ["openai:*", "hmac:new"]

    def test_does_not_duplicate_existing_credential(self, sample_toml, tmp_path):
        from safeyolo.policy.toml_roundtrip import add_host_credential, load_roundtrip

        path = tmp_path / "policy.toml"
        path.write_text(sample_toml)
        doc = load_roundtrip(path)
        add_host_credential(doc, "api.openai.com", ["openai:*"])
        allow = list(doc["hosts"]["api.openai.com"]["allow"])
        assert allow == ["openai:*"]

    def test_creates_hosts_table_if_missing(self):
        from safeyolo.policy.toml_roundtrip import add_host_credential

        doc = tomlkit.document()
        doc.add("version", "2.0")
        add_host_credential(doc, "api.example.com", ["hmac:abc"])
        assert "hosts" in doc
        assert list(doc["hosts"]["api.example.com"]["allow"]) == ["hmac:abc"]

    def test_empty_cred_ids_raises(self):
        from safeyolo.policy.toml_roundtrip import add_host_credential

        doc = tomlkit.document()
        with pytest.raises(ValueError, match="non-empty"):
            add_host_credential(doc, "api.example.com", [])

    def test_non_string_cred_ids_raises(self):
        from safeyolo.policy.toml_roundtrip import add_host_credential

        doc = tomlkit.document()
        with pytest.raises(ValueError, match="list of strings"):
            add_host_credential(doc, "api.example.com", [123])  # type: ignore[list-item]

    def test_scalar_host_entry_raises(self):
        """Pre-existing scalar value for a host is an operator error — must raise."""
        from safeyolo.policy.toml_roundtrip import add_host_credential

        doc = tomlkit.parse('[hosts]\n"api.example.com" = 3000\n')
        with pytest.raises(ValueError, match="not a table"):
            add_host_credential(doc, "api.example.com", ["hmac:abc"])


# =========================================================================
# update_host_field
# =========================================================================


class TestUpdateHostField:
    def test_updates_existing_field(self, sample_toml, tmp_path):
        from safeyolo.policy.toml_roundtrip import load_roundtrip, update_host_field

        path = tmp_path / "policy.toml"
        path.write_text(sample_toml)
        doc = load_roundtrip(path)
        update_host_field(doc, "api.openai.com", "rate", 5000)
        assert doc["hosts"]["api.openai.com"]["rate"] == 5000

    def test_creates_new_host_entry(self, sample_toml, tmp_path):
        from safeyolo.policy.toml_roundtrip import load_roundtrip, update_host_field

        path = tmp_path / "policy.toml"
        path.write_text(sample_toml)
        doc = load_roundtrip(path)
        update_host_field(doc, "new.example.com", "rate", 100)
        assert doc["hosts"]["new.example.com"]["rate"] == 100

    def test_creates_host_on_empty_hosts_table(self):
        from safeyolo.policy.toml_roundtrip import update_host_field

        doc = tomlkit.document()
        doc.add("hosts", tomlkit.table())
        update_host_field(doc, "new.host.com", "bypass", ["pattern-scanner"])
        assert list(doc["hosts"]["new.host.com"]["bypass"]) == ["pattern-scanner"]

    def test_none_value_raises(self):
        from safeyolo.policy.toml_roundtrip import update_host_field

        doc = tomlkit.document()
        with pytest.raises(ValueError, match="must not be None"):
            update_host_field(doc, "api.example.com", "rate", None)

    def test_scalar_host_entry_raises(self):
        from safeyolo.policy.toml_roundtrip import update_host_field

        doc = tomlkit.parse('[hosts]\n"api.example.com" = 3000\n')
        with pytest.raises(ValueError, match="not a table"):
            update_host_field(doc, "api.example.com", "rate", 5000)


# =========================================================================
# upsert_host
# =========================================================================


class TestUpsertHost:
    def test_inserts_new_host(self, sample_toml, tmp_path):
        from safeyolo.policy.toml_roundtrip import load_roundtrip, upsert_host

        path = tmp_path / "policy.toml"
        path.write_text(sample_toml)
        doc = load_roundtrip(path)
        upsert_host(doc, "new.api.com", {"allow": ["custom:*"], "rate": 1000})
        assert list(doc["hosts"]["new.api.com"]["allow"]) == ["custom:*"]
        assert doc["hosts"]["new.api.com"]["rate"] == 1000

    def test_replaces_existing_host_entirely(self, sample_toml, tmp_path):
        """upsert_host is a replace — existing fields not in the new config are dropped."""
        from safeyolo.policy.toml_roundtrip import load_roundtrip, upsert_host

        path = tmp_path / "policy.toml"
        path.write_text(sample_toml)
        doc = load_roundtrip(path)
        upsert_host(doc, "api.openai.com", {"rate": 9999})
        # The rate field is the new value, and the old allow field is gone
        assert doc["hosts"]["api.openai.com"]["rate"] == 9999
        assert "allow" not in doc["hosts"]["api.openai.com"]

    def test_creates_hosts_table_if_missing(self):
        from safeyolo.policy.toml_roundtrip import upsert_host

        doc = tomlkit.document()
        upsert_host(doc, "example.com", {"rate": 100})
        assert "hosts" in doc
        assert doc["hosts"]["example.com"]["rate"] == 100


# =========================================================================
# load_agents
# =========================================================================


class TestLoadAgents:
    def test_returns_empty_dict_when_no_agents_section(self):
        from safeyolo.policy.toml_roundtrip import load_agents

        doc = tomlkit.document()
        doc.add("version", "2.0")
        assert load_agents(doc) == {}

    def test_returns_plain_dict_of_agents(self):
        from safeyolo.policy.toml_roundtrip import load_agents

        doc = tomlkit.parse(
            '[agents.boris]\ntemplate = "claude-code"\nfolder = "/tmp/proj"\n'
        )
        result = load_agents(doc)
        assert result == {"boris": {"template": "claude-code", "folder": "/tmp/proj"}}

    def test_output_is_independent_of_document(self):
        """Mutating the returned dict must not affect the TOMLDocument."""
        from safeyolo.policy.toml_roundtrip import load_agents

        doc = tomlkit.parse('[agents.boris]\ntemplate = "claude-code"\n')
        result = load_agents(doc)
        result["boris"]["template"] = "changed"
        # Document is unchanged
        assert doc["agents"]["boris"]["template"] == "claude-code"


# =========================================================================
# upsert_agent
# =========================================================================


class TestUpsertAgent:
    def test_inserts_new_agent(self):
        from safeyolo.policy.toml_roundtrip import load_agents, upsert_agent

        doc = tomlkit.document()
        upsert_agent(doc, "boris", {"template": "claude-code", "folder": "/tmp/p"})
        assert load_agents(doc) == {
            "boris": {"template": "claude-code", "folder": "/tmp/p"}
        }

    def test_replaces_existing_agent(self):
        from safeyolo.policy.toml_roundtrip import load_agents, upsert_agent

        doc = tomlkit.document()
        upsert_agent(doc, "boris", {"template": "claude-code"})
        upsert_agent(doc, "boris", {"template": "openai-codex"})
        assert load_agents(doc) == {"boris": {"template": "openai-codex"}}

    def test_services_become_nested_tables(self):
        from safeyolo.policy.toml_roundtrip import load_agents, upsert_agent

        doc = tomlkit.document()
        upsert_agent(
            doc,
            "boris",
            {
                "template": "claude-code",
                "services": {
                    "gmail": {"capability": "read_and_send", "token": "gmail-oauth2"}
                },
            },
        )
        result = load_agents(doc)
        assert result["boris"]["services"]["gmail"] == {
            "capability": "read_and_send",
            "token": "gmail-oauth2",
        }

    def test_services_legacy_string_format_converted(self):
        from safeyolo.policy.toml_roundtrip import load_agents, upsert_agent

        doc = tomlkit.document()
        upsert_agent(doc, "boris", {"services": {"gmail": "reader"}})
        result = load_agents(doc)
        assert result["boris"]["services"]["gmail"] == {"capability": "reader"}

    def test_grants_become_array_of_tables(self):
        from safeyolo.policy.toml_roundtrip import load_agents, upsert_agent

        doc = tomlkit.document()
        upsert_agent(
            doc,
            "boris",
            {
                "grants": [
                    {
                        "grant_id": "g1",
                        "service": "slack",
                        "method": "POST",
                    }
                ]
            },
        )
        result = load_agents(doc)
        assert result["boris"]["grants"] == [
            {"grant_id": "g1", "service": "slack", "method": "POST"}
        ]

    def test_contract_bindings_with_nested_dict_values(self):
        from safeyolo.policy.toml_roundtrip import load_agents, upsert_agent

        doc = tomlkit.document()
        upsert_agent(
            doc,
            "boris",
            {
                "contract_bindings": [
                    {
                        "binding_id": "b1",
                        "service": "minifuse",
                        "bound_values": {"cat_id": 137},
                    }
                ]
            },
        )
        result = load_agents(doc)
        assert result["boris"]["contract_bindings"][0]["bound_values"] == {"cat_id": 137}

    def test_upsert_preserves_other_agents(self):
        from safeyolo.policy.toml_roundtrip import load_agents, upsert_agent

        doc = tomlkit.document()
        upsert_agent(doc, "boris", {"template": "claude-code"})
        upsert_agent(doc, "alice", {"template": "openai-codex"})
        upsert_agent(doc, "boris", {"template": "updated"})
        result = load_agents(doc)
        assert result == {
            "boris": {"template": "updated"},
            "alice": {"template": "openai-codex"},
        }


# =========================================================================
# remove_agent
# =========================================================================


class TestRemoveAgent:
    def test_returns_false_when_no_agents_section(self):
        from safeyolo.policy.toml_roundtrip import remove_agent

        doc = tomlkit.document()
        assert remove_agent(doc, "boris") is False

    def test_returns_false_when_agent_absent(self):
        from safeyolo.policy.toml_roundtrip import remove_agent, upsert_agent

        doc = tomlkit.document()
        upsert_agent(doc, "alice", {"template": "claude-code"})
        assert remove_agent(doc, "boris") is False

    def test_returns_true_and_removes_existing_agent(self):
        from safeyolo.policy.toml_roundtrip import load_agents, remove_agent, upsert_agent

        doc = tomlkit.document()
        upsert_agent(doc, "boris", {"template": "claude-code"})
        upsert_agent(doc, "alice", {"template": "openai-codex"})

        assert remove_agent(doc, "boris") is True
        assert load_agents(doc) == {"alice": {"template": "openai-codex"}}


# =========================================================================
# locked_policy_mutate
# =========================================================================


class TestLockedPolicyMutate:
    def _write_policy(self, path, content):
        path.write_text(content)

    def test_applies_mutation_and_persists(self, sample_toml, tmp_path):
        from safeyolo.policy.toml_roundtrip import load_roundtrip, locked_policy_mutate

        path = tmp_path / "policy.toml"
        self._write_policy(path, sample_toml)

        def bump_budget(doc):
            doc["budget"] = 99999
            return "done"

        result = locked_policy_mutate(path, bump_budget)
        assert result == "done"
        assert load_roundtrip(path)["budget"] == 99999

    def test_creates_lock_file(self, sample_toml, tmp_path):
        from safeyolo.policy.toml_roundtrip import locked_policy_mutate

        path = tmp_path / "policy.toml"
        self._write_policy(path, sample_toml)

        locked_policy_mutate(path, lambda doc: None)

        lock_file = tmp_path / ".policy.toml.lock"
        assert lock_file.exists()

    def test_mutate_fn_exception_propagates_and_releases_lock(self, sample_toml, tmp_path):
        from safeyolo.policy.toml_roundtrip import locked_policy_mutate

        path = tmp_path / "policy.toml"
        self._write_policy(path, sample_toml)

        def boom(doc):
            raise RuntimeError("mutate failed")

        with pytest.raises(RuntimeError, match="mutate failed"):
            locked_policy_mutate(path, boom)

        # Lock must be released — a subsequent call must succeed
        locked_policy_mutate(path, lambda doc: None)

    def test_sequential_calls_both_succeed(self, sample_toml, tmp_path):
        """Sequential mutations work (smoke test for lock acquire/release)."""
        from safeyolo.policy.toml_roundtrip import load_roundtrip, locked_policy_mutate

        path = tmp_path / "policy.toml"
        self._write_policy(path, sample_toml)

        locked_policy_mutate(path, lambda doc: doc.__setitem__("budget", 1))
        locked_policy_mutate(path, lambda doc: doc.__setitem__("budget", 2))
        locked_policy_mutate(path, lambda doc: doc.__setitem__("budget", 3))

        assert load_roundtrip(path)["budget"] == 3


# =========================================================================
# policy_path_for_loader
# =========================================================================


class TestPolicyPathForLoader:
    def test_returns_path_when_file_exists(self, tmp_path):
        from safeyolo.policy.toml_roundtrip import policy_path_for_loader

        policy_file = tmp_path / "policy.toml"
        policy_file.write_text("version = \"2.0\"\n")

        class FakeLoader:
            _baseline_path = policy_file

        assert policy_path_for_loader(FakeLoader()) == policy_file

    def test_raises_loader_not_configured_when_attribute_missing(self):
        from safeyolo.policy.toml_roundtrip import LoaderNotConfigured, policy_path_for_loader

        class FakeLoader:
            pass

        with pytest.raises(LoaderNotConfigured):
            policy_path_for_loader(FakeLoader())

    def test_raises_loader_not_configured_when_attribute_is_none(self):
        from safeyolo.policy.toml_roundtrip import LoaderNotConfigured, policy_path_for_loader

        class FakeLoader:
            _baseline_path = None

        with pytest.raises(LoaderNotConfigured):
            policy_path_for_loader(FakeLoader())

    def test_raises_loader_not_configured_when_attribute_is_not_path(self):
        from safeyolo.policy.toml_roundtrip import LoaderNotConfigured, policy_path_for_loader

        class FakeLoader:
            _baseline_path = "/some/string/not/a/path/object"

        with pytest.raises(LoaderNotConfigured):
            policy_path_for_loader(FakeLoader())

    def test_raises_baseline_missing_when_file_deleted(self, tmp_path):
        from safeyolo.policy.toml_roundtrip import LoaderBaselineMissing, policy_path_for_loader

        missing_path = tmp_path / "nonexistent.toml"

        class FakeLoader:
            _baseline_path = missing_path

        with pytest.raises(LoaderBaselineMissing):
            policy_path_for_loader(FakeLoader())


# =========================================================================
# Template round-trip (integration)
# =========================================================================


class TestTemplateRoundTrip:
    def test_template_loads_and_normalizes_to_internal_format(self):
        from safeyolo.policy.toml_roundtrip import load_as_internal

        template_path = (
            Path(__file__).parent.parent
            / "cli"
            / "src"
            / "safeyolo"
            / "templates"
            / "policy.toml"
        )
        if not template_path.exists():
            pytest.skip("Template not found")

        result = load_as_internal(template_path)
        assert result["metadata"]["version"] == "2.0"
        assert result["global_budget"] == 12000
        assert "api.openai.com" in result["hosts"]
        assert result["hosts"]["api.openai.com"]["credentials"] == ["openai:*"]
        assert result["hosts"]["*"]["unknown_credentials"] == "prompt"

    def test_template_roundtrip_preserves_comments(self, tmp_path):
        from safeyolo.policy.toml_roundtrip import load_roundtrip, save_roundtrip

        template_path = (
            Path(__file__).parent.parent
            / "cli"
            / "src"
            / "safeyolo"
            / "templates"
            / "policy.toml"
        )
        if not template_path.exists():
            pytest.skip("Template not found")

        path = tmp_path / "policy.toml"
        path.write_text(template_path.read_text())

        doc = load_roundtrip(path)
        doc["hosts"]["api.openai.com"]["rate"] = 5000
        save_roundtrip(path, doc)

        content = path.read_text()
        assert "# SafeYolo baseline policy" in content
        assert "# ── LLM APIs" in content

        reloaded = load_roundtrip(path)
        assert reloaded["hosts"]["api.openai.com"]["rate"] == 5000
