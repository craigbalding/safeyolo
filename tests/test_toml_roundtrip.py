"""
Tests for toml_roundtrip.py - TOML round-trip load/save with comment preservation.

Tests comment preservation, inline table modification, atomic writes,
and real template round-trip.
"""

import tempfile
from pathlib import Path

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


class TestLoadRoundtrip:
    """Test load_roundtrip function."""

    def test_loads_toml(self, sample_toml):
        from toml_roundtrip import load_roundtrip

        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(sample_toml)
            path = Path(f.name)

        doc = load_roundtrip(path)
        assert doc["version"] == "2.0"
        assert doc["budget"] == 12000
        assert "api.openai.com" in doc["hosts"]
        path.unlink()

    def test_file_not_found_raises(self):
        from toml_roundtrip import load_roundtrip

        with pytest.raises(FileNotFoundError):
            load_roundtrip(Path("/nonexistent/policy.toml"))


class TestSaveRoundtrip:
    """Test save_roundtrip function (atomic write)."""

    def test_atomic_write(self, sample_toml):
        from toml_roundtrip import load_roundtrip, save_roundtrip

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text(sample_toml)

            doc = load_roundtrip(path)
            doc["budget"] = 24000
            save_roundtrip(path, doc)

            # Reload and verify
            doc2 = load_roundtrip(path)
            assert doc2["budget"] == 24000

    def test_creates_parent_dirs(self):
        from toml_roundtrip import save_roundtrip

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "sub" / "policy.toml"
            doc = tomlkit.document()
            doc.add("version", "2.0")
            save_roundtrip(path, doc)
            assert path.exists()


class TestCommentPreservation:
    """Test that comments survive load/modify/save cycles."""

    def test_comments_preserved(self, sample_toml):
        from toml_roundtrip import load_roundtrip, save_roundtrip

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text(sample_toml)

            # Load, modify, save
            doc = load_roundtrip(path)
            doc["budget"] = 24000
            save_roundtrip(path, doc)

            # Read raw text and check comments survived
            content = path.read_text()
            assert "# SafeYolo baseline policy" in content
            assert "# total req/min" in content
            assert "# ── LLM APIs" in content
            assert "# ── Defaults" in content

    def test_inline_table_modification_preserves_comments(self, sample_toml):
        from toml_roundtrip import load_roundtrip, save_roundtrip

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text(sample_toml)

            doc = load_roundtrip(path)
            # Modify a rate in an inline table
            doc["hosts"]["api.openai.com"]["rate"] = 5000
            save_roundtrip(path, doc)

            content = path.read_text()
            assert "5000" in content or "5_000" in content
            # Comments should still be there
            assert "# ── LLM APIs" in content


class TestLoadAsInternal:
    """Test load_as_internal (load + unwrap + normalize)."""

    def test_produces_internal_format(self, sample_toml):
        from toml_roundtrip import load_as_internal

        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(sample_toml)
            path = Path(f.name)

        result = load_as_internal(path)

        # Check normalization happened
        assert result["metadata"]["version"] == "2.0"
        assert result["global_budget"] == 12000
        assert result["hosts"]["api.openai.com"]["credentials"] == ["openai:*"]
        assert result["hosts"]["api.openai.com"]["rate_limit"] == 3000
        assert result["hosts"]["*"]["unknown_credentials"] == "prompt"
        assert result["credentials"]["openai"]["patterns"] == ['sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}']
        assert result["required"] == ["credential_guard", "network_guard"]

        path.unlink()


class TestMutationHelpers:
    """Test add_host_credential, update_host_field, add_host."""

    def test_add_host_credential_new_host(self, sample_toml):
        from toml_roundtrip import add_host_credential, load_roundtrip, save_roundtrip

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text(sample_toml)

            doc = load_roundtrip(path)
            add_host_credential(doc, "api.example.com", ["hmac:abc123"])
            save_roundtrip(path, doc)

            doc2 = load_roundtrip(path)
            assert "api.example.com" in doc2["hosts"]
            assert doc2["hosts"]["api.example.com"]["allow"] == ["hmac:abc123"]

    def test_add_host_credential_existing_host(self, sample_toml):
        from toml_roundtrip import add_host_credential, load_roundtrip

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text(sample_toml)

            doc = load_roundtrip(path)
            add_host_credential(doc, "api.openai.com", ["hmac:new123"])

            # Should append, not replace
            allow = doc["hosts"]["api.openai.com"]["allow"]
            assert "openai:*" in allow
            assert "hmac:new123" in allow

    def test_add_host_credential_no_duplicate(self, sample_toml):
        from toml_roundtrip import add_host_credential, load_roundtrip

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text(sample_toml)

            doc = load_roundtrip(path)
            add_host_credential(doc, "api.openai.com", ["openai:*"])

            # Should not duplicate
            allow = list(doc["hosts"]["api.openai.com"]["allow"])
            assert allow.count("openai:*") == 1

    def test_update_host_field(self, sample_toml):
        from toml_roundtrip import load_roundtrip, update_host_field

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text(sample_toml)

            doc = load_roundtrip(path)
            update_host_field(doc, "api.openai.com", "rate", 5000)
            assert doc["hosts"]["api.openai.com"]["rate"] == 5000

    def test_update_host_field_new_host(self, sample_toml):
        from toml_roundtrip import load_roundtrip, update_host_field

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text(sample_toml)

            doc = load_roundtrip(path)
            update_host_field(doc, "new.example.com", "rate", 100)
            assert doc["hosts"]["new.example.com"]["rate"] == 100

    def test_add_host(self, sample_toml):
        from toml_roundtrip import add_host, load_roundtrip

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text(sample_toml)

            doc = load_roundtrip(path)
            add_host(doc, "new.api.com", {"allow": ["custom:*"], "rate": 1000})
            assert doc["hosts"]["new.api.com"]["allow"] == ["custom:*"]
            assert doc["hosts"]["new.api.com"]["rate"] == 1000

    def test_add_host_credential_creates_hosts_table(self):
        """Test that add_host_credential creates [hosts] if missing."""
        from toml_roundtrip import add_host_credential

        doc = tomlkit.document()
        doc.add("version", "2.0")
        add_host_credential(doc, "api.example.com", ["hmac:abc"])
        assert "hosts" in doc
        assert doc["hosts"]["api.example.com"]["allow"] == ["hmac:abc"]

    def test_update_host_field_bypass_list(self, sample_toml):
        """Test update_host_field with a bypass list."""
        from toml_roundtrip import load_roundtrip, update_host_field

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text(sample_toml)

            doc = load_roundtrip(path)
            update_host_field(doc, "api.openai.com", "bypass", ["pattern-scanner"])
            assert doc["hosts"]["api.openai.com"]["bypass"] == ["pattern-scanner"]

    def test_update_host_field_bypass_append(self, sample_toml):
        """Test appending to an existing bypass list via update_host_field."""
        from toml_roundtrip import load_roundtrip, save_roundtrip, update_host_field

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text(sample_toml)

            doc = load_roundtrip(path)
            # First bypass
            update_host_field(doc, "api.openai.com", "bypass", ["credential-guard"])
            save_roundtrip(path, doc)

            # Load again, read existing, append
            doc2 = load_roundtrip(path)
            existing = list(doc2["hosts"]["api.openai.com"]["bypass"])
            existing.append("pattern-scanner")
            update_host_field(doc2, "api.openai.com", "bypass", existing)
            save_roundtrip(path, doc2)

            # Verify both are present
            doc3 = load_roundtrip(path)
            bypass = list(doc3["hosts"]["api.openai.com"]["bypass"])
            assert "credential-guard" in bypass
            assert "pattern-scanner" in bypass

    def test_update_host_field_bypass_new_host(self):
        """Test bypass on a host that doesn't exist yet creates it."""
        from toml_roundtrip import update_host_field

        doc = tomlkit.document()
        doc.add("hosts", tomlkit.table())
        update_host_field(doc, "new.host.com", "bypass", ["pattern-scanner"])
        assert doc["hosts"]["new.host.com"]["bypass"] == ["pattern-scanner"]


class TestTemplateRoundTrip:
    """Test that the real policy.toml template survives load/modify/save."""

    def test_template_loads_and_normalizes(self):
        """The bundled template loads and normalizes to a valid internal format."""
        from toml_roundtrip import load_as_internal

        template_path = Path(__file__).parent.parent / "cli" / "src" / "safeyolo" / "templates" / "policy.toml"
        if not template_path.exists():
            pytest.skip("Template not found")

        result = load_as_internal(template_path)
        assert result["metadata"]["version"] == "2.0"
        assert result["global_budget"] == 12000
        assert "api.openai.com" in result["hosts"]
        assert result["hosts"]["api.openai.com"]["credentials"] == ["openai:*"]
        assert result["hosts"]["*"]["unknown_credentials"] == "prompt"

    def test_template_roundtrip_preserves_comments(self):
        """Load template, modify rate, save, reload — comments survive."""
        from toml_roundtrip import load_roundtrip, save_roundtrip

        template_path = Path(__file__).parent.parent / "cli" / "src" / "safeyolo" / "templates" / "policy.toml"
        if not template_path.exists():
            pytest.skip("Template not found")

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            # Copy template
            path.write_text(template_path.read_text())

            doc = load_roundtrip(path)
            doc["hosts"]["api.openai.com"]["rate"] = 5000
            save_roundtrip(path, doc)

            # Verify
            content = path.read_text()
            assert "5000" in content or "5_000" in content
            assert "# SafeYolo baseline policy" in content
            assert "# ── LLM APIs" in content

            doc2 = load_roundtrip(path)
            assert doc2["hosts"]["api.openai.com"]["rate"] == 5000
