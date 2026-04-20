"""
Tests for proxy.py — Host mitmproxy process management.

Tests command construction, token generation, cert management,
PID file lifecycle, and directory discovery.
"""

import os
import signal
import stat
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest


# ---------------------------------------------------------------------------
# TestAddonChain
# ---------------------------------------------------------------------------

class TestAddonChain:
    """Tests for ADDON_CHAIN ordering and completeness."""

    def test_addon_chain_has_expected_count(self):
        """ADDON_CHAIN contains exactly 20 addons (proxy_protocol added)."""
        from safeyolo.proxy import ADDON_CHAIN
        assert len(ADDON_CHAIN) == 20

    def test_addon_chain_starts_with_proxy_protocol(self):
        """First addon loaded is proxy_protocol.py.

        Parses the PROXY protocol v2 header from upstream TCP via
        next_layer, which must run before any other layer inspects
        the flow so the rewritten peername and stripped header are
        available to every downstream addon.
        """
        from safeyolo.proxy import ADDON_CHAIN
        assert ADDON_CHAIN[0] == "proxy_protocol.py"

    def test_addon_chain_ends_with_admin_api(self):
        """Last addon loaded is admin_api.py (observability layer)."""
        from safeyolo.proxy import ADDON_CHAIN
        assert ADDON_CHAIN[-1] == "admin_api.py"

    def test_policy_engine_before_network_guard(self):
        """policy_engine.py loads before network_guard.py (policy must exist before enforcement)."""
        from safeyolo.proxy import ADDON_CHAIN
        pe_idx = ADDON_CHAIN.index("policy_engine.py")
        ng_idx = ADDON_CHAIN.index("network_guard.py")
        assert pe_idx < ng_idx

    def test_credential_guard_after_network_guard(self):
        """credential_guard.py loads after network_guard.py (network check before credential inspection)."""
        from safeyolo.proxy import ADDON_CHAIN
        ng_idx = ADDON_CHAIN.index("network_guard.py")
        cg_idx = ADDON_CHAIN.index("credential_guard.py")
        assert ng_idx < cg_idx

    def test_request_id_before_all_guards(self):
        """request_id.py loads before network_guard and credential_guard (needed for correlation)."""
        from safeyolo.proxy import ADDON_CHAIN
        rid_idx = ADDON_CHAIN.index("request_id.py")
        ng_idx = ADDON_CHAIN.index("network_guard.py")
        cg_idx = ADDON_CHAIN.index("credential_guard.py")
        assert rid_idx < ng_idx
        assert rid_idx < cg_idx

    def test_service_discovery_before_policy_engine(self):
        """service_discovery.py loads before policy_engine.py (agent identity needed for policy)."""
        from safeyolo.proxy import ADDON_CHAIN
        sd_idx = ADDON_CHAIN.index("service_discovery.py")
        pe_idx = ADDON_CHAIN.index("policy_engine.py")
        assert sd_idx < pe_idx

    def test_all_addon_filenames_end_with_py(self):
        """Every entry in ADDON_CHAIN ends with .py."""
        from safeyolo.proxy import ADDON_CHAIN
        for addon in ADDON_CHAIN:
            assert addon.endswith(".py"), f"{addon} does not end with .py"


# ---------------------------------------------------------------------------
# TestFindAddonsDir
# ---------------------------------------------------------------------------

class TestFindAddonsDir:
    """Tests for _find_addons_dir() — locating addons directory."""

    def test_returns_none_when_no_addons_dir_exists(self, tmp_path):
        """When no candidate directory has request_id.py, returns None."""
        from safeyolo.proxy import _find_addons_dir

        # Patch __file__ to point to a location with no valid addons dir
        fake_file = tmp_path / "cli" / "src" / "safeyolo" / "proxy.py"
        fake_file.parent.mkdir(parents=True)
        fake_file.touch()

        with patch("safeyolo.proxy.__file__", str(fake_file)):
            result = _find_addons_dir()

        assert result is None

    def test_returns_path_when_marker_file_exists(self, tmp_path):
        """When a candidate has request_id.py, returns that path."""
        from safeyolo.proxy import _find_addons_dir

        # Create repo-like layout: repo/cli/src/safeyolo/proxy.py and repo/addons/request_id.py
        repo = tmp_path / "repo"
        proxy_file = repo / "cli" / "src" / "safeyolo" / "proxy.py"
        proxy_file.parent.mkdir(parents=True)
        proxy_file.touch()

        addons = repo / "addons"
        addons.mkdir()
        (addons / "request_id.py").touch()

        with patch("safeyolo.proxy.__file__", str(proxy_file)):
            result = _find_addons_dir()

        assert result == addons


# ---------------------------------------------------------------------------
# TestFindPdpDir
# ---------------------------------------------------------------------------

class TestFindPdpDir:
    """Tests for _find_pdp_dir() — locating PDP directory."""

    def test_returns_none_when_no_pdp_dir_exists(self, tmp_path):
        """When no candidate directory has __init__.py, returns None."""
        from safeyolo.proxy import _find_pdp_dir

        fake_file = tmp_path / "cli" / "src" / "safeyolo" / "proxy.py"
        fake_file.parent.mkdir(parents=True)
        fake_file.touch()

        with patch("safeyolo.proxy.__file__", str(fake_file)):
            result = _find_pdp_dir()

        assert result is None

    def test_returns_path_when_init_exists(self, tmp_path):
        """When a candidate has __init__.py, returns that path."""
        from safeyolo.proxy import _find_pdp_dir

        repo = tmp_path / "repo"
        proxy_file = repo / "cli" / "src" / "safeyolo" / "proxy.py"
        proxy_file.parent.mkdir(parents=True)
        proxy_file.touch()

        pdp = repo / "pdp"
        pdp.mkdir()
        (pdp / "__init__.py").touch()

        with patch("safeyolo.proxy.__file__", str(proxy_file)):
            result = _find_pdp_dir()

        assert result == pdp


# ---------------------------------------------------------------------------
# TestEnsureCerts
# ---------------------------------------------------------------------------

class TestEnsureCerts:
    """Tests for _ensure_certs() — CA certificate generation."""

    def test_generates_cert_when_missing(self, tmp_path):
        """When cert doesn't exist, runs mitmdump and returns cert path."""
        from safeyolo.proxy import _ensure_certs

        cert_dir = tmp_path / "certs"
        ca_cert = cert_dir / "mitmproxy-ca-cert.pem"

        def create_cert(*args, **kwargs):
            """Simulate mitmdump creating the cert."""
            cert_dir.mkdir(parents=True, exist_ok=True)
            ca_cert.write_text("FAKE CERT")
            return MagicMock(returncode=0)

        with patch("safeyolo.proxy.subprocess.run", side_effect=create_cert) as mock_run:
            result = _ensure_certs(cert_dir)

        assert result == ca_cert
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        cmd = call_args[0][0]
        assert cmd[0] == "mitmdump"
        assert f"confdir={cert_dir}" in " ".join(cmd)
        assert "-p" in cmd
        assert "0" in cmd

    def test_skips_generation_when_cert_exists(self, tmp_path):
        """When cert already exists, no subprocess call is made."""
        from safeyolo.proxy import _ensure_certs

        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        ca_cert = cert_dir / "mitmproxy-ca-cert.pem"
        ca_cert.write_text("EXISTING CERT")

        with patch("safeyolo.proxy.subprocess.run") as mock_run:
            result = _ensure_certs(cert_dir)

        assert result == ca_cert
        mock_run.assert_not_called()

    def test_raises_when_generation_fails(self, tmp_path):
        """When mitmdump runs but cert still missing, RuntimeError is raised."""
        from safeyolo.proxy import _ensure_certs

        cert_dir = tmp_path / "certs"

        with patch("safeyolo.proxy.subprocess.run", return_value=MagicMock()):
            with pytest.raises(RuntimeError, match="Failed to generate CA certificate"):
                _ensure_certs(cert_dir)

    def test_timeout_expired_is_swallowed(self, tmp_path):
        """TimeoutExpired from mitmdump is expected and swallowed."""
        import subprocess as sp

        from safeyolo.proxy import _ensure_certs

        cert_dir = tmp_path / "certs"
        ca_cert = cert_dir / "mitmproxy-ca-cert.pem"

        def timeout_then_cert(*args, **kwargs):
            cert_dir.mkdir(parents=True, exist_ok=True)
            ca_cert.write_text("CERT FROM TIMEOUT")
            raise sp.TimeoutExpired(cmd="mitmdump", timeout=5)

        with patch("safeyolo.proxy.subprocess.run", side_effect=timeout_then_cert):
            result = _ensure_certs(cert_dir)

        assert result == ca_cert

    def test_sets_permissions_on_generated_pem_files(self, tmp_path):
        """Generated .pem and .p12 files get 0o600 permissions."""
        from safeyolo.proxy import _ensure_certs

        cert_dir = tmp_path / "certs"

        def create_cert_files(*args, **kwargs):
            cert_dir.mkdir(parents=True, exist_ok=True)
            (cert_dir / "mitmproxy-ca-cert.pem").write_text("cert")
            (cert_dir / "mitmproxy-ca.pem").write_text("ca")
            (cert_dir / "mitmproxy-ca.p12").write_bytes(b"p12")
            (cert_dir / "readme.txt").write_text("not a cert")
            return MagicMock(returncode=0)

        with patch("safeyolo.proxy.subprocess.run", side_effect=create_cert_files):
            _ensure_certs(cert_dir)

        assert (cert_dir / "mitmproxy-ca-cert.pem").stat().st_mode & 0o777 == 0o600
        assert (cert_dir / "mitmproxy-ca.pem").stat().st_mode & 0o777 == 0o600
        assert (cert_dir / "mitmproxy-ca.p12").stat().st_mode & 0o777 == 0o600
        # Non-cert file not restricted
        assert (cert_dir / "readme.txt").stat().st_mode & 0o777 != 0o600

    def test_creates_cert_dir_if_missing(self, tmp_path):
        """cert_dir is created (with parents) if it doesn't exist."""
        from safeyolo.proxy import _ensure_certs

        cert_dir = tmp_path / "deep" / "nested" / "certs"
        ca_cert = cert_dir / "mitmproxy-ca-cert.pem"

        def create_cert(*args, **kwargs):
            ca_cert.write_text("CERT")
            return MagicMock(returncode=0)

        with patch("safeyolo.proxy.subprocess.run", side_effect=create_cert):
            _ensure_certs(cert_dir)

        assert cert_dir.is_dir()


# ---------------------------------------------------------------------------
# TestMergeSystemCasIntoCertifi
# ---------------------------------------------------------------------------

# Reusable PEM-like blocks for CA merge tests.  The function splits on
# "-----END CERTIFICATE-----" boundaries, so these need valid bookends.
_CERT_A = (
    "-----BEGIN CERTIFICATE-----\n"
    "AAAA-certifi-root-one\n"
    "-----END CERTIFICATE-----\n"
)
_CERT_B = (
    "-----BEGIN CERTIFICATE-----\n"
    "BBBB-certifi-root-two\n"
    "-----END CERTIFICATE-----\n"
)
_CERT_C = (
    "-----BEGIN CERTIFICATE-----\n"
    "CCCC-system-only-root\n"
    "-----END CERTIFICATE-----\n"
)
_CERT_D = (
    "-----BEGIN CERTIFICATE-----\n"
    "DDDD-system-only-extra\n"
    "-----END CERTIFICATE-----\n"
)


class TestMergeSystemCasIntoCertifi:
    """Tests for _merge_system_cas_into_certifi() — system CA merge into certifi."""

    def test_merges_new_certs_into_certifi_bundle(self, tmp_path):
        """System bundle has certs not in certifi -> they get appended."""
        from safeyolo.proxy import _merge_system_cas_into_certifi

        certifi_file = tmp_path / "certifi_bundle.pem"
        certifi_file.write_text(_CERT_A)

        fake_certifi = MagicMock()
        fake_certifi.where.return_value = str(certifi_file)

        original_exists = Path.exists
        original_read_text = Path.read_text

        def fake_exists(self):
            if str(self) == "/etc/ssl/certs/ca-certificates.crt":
                return True
            return original_exists(self)

        def fake_read_text(self, *args, **kwargs):
            if str(self) == "/etc/ssl/certs/ca-certificates.crt":
                return _CERT_C + _CERT_D
            return original_read_text(self, *args, **kwargs)

        with patch.dict("sys.modules", {"certifi": fake_certifi}), \
             patch.object(Path, "exists", fake_exists), \
             patch.object(Path, "read_text", fake_read_text):
            _merge_system_cas_into_certifi()

        result = certifi_file.read_text()
        assert "CCCC-system-only-root" in result
        assert "DDDD-system-only-extra" in result
        assert "AAAA-certifi-root-one" in result

    def test_skips_when_certs_already_present(self, tmp_path):
        """System bundle certs already in certifi -> no write occurs."""
        from safeyolo.proxy import _merge_system_cas_into_certifi

        both_certs = _CERT_A + _CERT_B
        certifi_file = tmp_path / "certifi_bundle.pem"
        certifi_file.write_text(both_certs)

        fake_certifi = MagicMock()
        fake_certifi.where.return_value = str(certifi_file)

        original_exists = Path.exists

        def fake_exists(self):
            if str(self) == "/etc/ssl/certs/ca-certificates.crt":
                return True
            return original_exists(self)

        original_read_text = Path.read_text

        def fake_read_text(self, *args, **kwargs):
            if str(self) == "/etc/ssl/certs/ca-certificates.crt":
                # System bundle has same certs as certifi
                return _CERT_A + _CERT_B
            return original_read_text(self, *args, **kwargs)

        with patch.dict("sys.modules", {"certifi": fake_certifi}), \
             patch.object(Path, "exists", fake_exists), \
             patch.object(Path, "read_text", fake_read_text):
            _merge_system_cas_into_certifi()

        # File should be unchanged — no new certs appended
        assert certifi_file.read_text() == both_certs

    def test_skips_when_no_system_bundle_found(self, tmp_path):
        """None of the 3 well-known paths exist -> returns silently."""
        from safeyolo.proxy import _merge_system_cas_into_certifi

        certifi_file = tmp_path / "certifi_bundle.pem"
        certifi_file.write_text(_CERT_A)

        fake_certifi = MagicMock()
        fake_certifi.where.return_value = str(certifi_file)

        original_exists = Path.exists

        def fake_exists(self):
            # None of the system paths exist
            if str(self) in (
                "/etc/ssl/certs/ca-certificates.crt",
                "/etc/pki/tls/certs/ca-bundle.crt",
                "/etc/ssl/cert.pem",
            ):
                return False
            return original_exists(self)

        with patch.dict("sys.modules", {"certifi": fake_certifi}), \
             patch.object(Path, "exists", fake_exists):
            _merge_system_cas_into_certifi()

        # certifi bundle should be unchanged
        assert certifi_file.read_text() == _CERT_A

    def test_skips_when_certifi_not_importable(self, tmp_path):
        """certifi import raises ImportError -> returns with warning log."""
        from safeyolo.proxy import _merge_system_cas_into_certifi

        # Remove certifi from sys.modules so the function's `import certifi`
        # hits our patched importer.
        import builtins

        original_import = builtins.__import__

        def fail_certifi(name, *args, **kwargs):
            if name == "certifi":
                raise ImportError("No module named 'certifi'")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=fail_certifi), \
             patch("safeyolo.proxy.log") as mock_log:
            _merge_system_cas_into_certifi()

        mock_log.warning.assert_called_once()
        assert "certifi" in mock_log.warning.call_args[0][0].lower() or \
               "certifi" in str(mock_log.warning.call_args[0])

    def test_deduplicates_certs(self, tmp_path):
        """System bundle has 3 certs, 1 already in certifi -> only 2 appended."""
        from safeyolo.proxy import _merge_system_cas_into_certifi

        certifi_file = tmp_path / "certifi_bundle.pem"
        certifi_file.write_text(_CERT_A)

        fake_certifi = MagicMock()
        fake_certifi.where.return_value = str(certifi_file)

        # System has CERT_A (already in certifi) + CERT_C + CERT_D (new)
        system_content = _CERT_A + _CERT_C + _CERT_D

        original_exists = Path.exists

        def fake_exists(self):
            if str(self) == "/etc/ssl/certs/ca-certificates.crt":
                return True
            return original_exists(self)

        original_read_text = Path.read_text

        def fake_read_text(self, *args, **kwargs):
            if str(self) == "/etc/ssl/certs/ca-certificates.crt":
                return system_content
            return original_read_text(self, *args, **kwargs)

        with patch.dict("sys.modules", {"certifi": fake_certifi}), \
             patch.object(Path, "exists", fake_exists), \
             patch.object(Path, "read_text", fake_read_text), \
             patch("safeyolo.proxy.log") as mock_log:
            _merge_system_cas_into_certifi()

        result = certifi_file.read_text()
        # Original cert still there
        assert "AAAA-certifi-root-one" in result
        # Two new certs appended
        assert "CCCC-system-only-root" in result
        assert "DDDD-system-only-extra" in result
        # The log message should say 2 certs merged
        mock_log.info.assert_called_once()
        assert mock_log.info.call_args[0][1] == 2

    def test_tries_debian_path_first(self, tmp_path):
        """Debian path exists -> uses it even if macOS path also exists."""
        from safeyolo.proxy import _merge_system_cas_into_certifi

        certifi_file = tmp_path / "certifi_bundle.pem"
        certifi_file.write_text(_CERT_A)

        fake_certifi = MagicMock()
        fake_certifi.where.return_value = str(certifi_file)

        debian_content = _CERT_C  # Unique to Debian bundle
        macos_content = _CERT_D   # Unique to macOS bundle

        original_exists = Path.exists

        def fake_exists(self):
            if str(self) == "/etc/ssl/certs/ca-certificates.crt":
                return True  # Debian exists
            if str(self) == "/etc/ssl/cert.pem":
                return True  # macOS also exists
            if str(self) == "/etc/pki/tls/certs/ca-bundle.crt":
                return False
            return original_exists(self)

        original_read_text = Path.read_text

        def fake_read_text(self, *args, **kwargs):
            if str(self) == "/etc/ssl/certs/ca-certificates.crt":
                return debian_content
            if str(self) == "/etc/ssl/cert.pem":
                return macos_content
            return original_read_text(self, *args, **kwargs)

        with patch.dict("sys.modules", {"certifi": fake_certifi}), \
             patch.object(Path, "exists", fake_exists), \
             patch.object(Path, "read_text", fake_read_text):
            _merge_system_cas_into_certifi()

        result = certifi_file.read_text()
        # Debian cert was used (CERT_C)
        assert "CCCC-system-only-root" in result
        # macOS cert NOT used — Debian was found first
        assert "DDDD-system-only-extra" not in result


# ---------------------------------------------------------------------------
# TestEnsureTokens
# ---------------------------------------------------------------------------

class TestEnsureTokens:
    """Tests for _ensure_tokens() — admin and agent token management."""

    def test_creates_new_admin_and_agent_tokens(self, tmp_path):
        """Fresh data_dir -> both tokens created and returned."""
        from safeyolo.proxy import _ensure_tokens

        data_dir = tmp_path / "data"
        admin_token, agent_token = _ensure_tokens(data_dir)

        assert len(admin_token) > 20  # token_urlsafe(32) is ~43 chars
        assert len(agent_token) == 64  # token_hex(32) is exactly 64 hex chars
        assert (data_dir / "admin_token").read_text() == admin_token
        assert (data_dir / "agent_token").read_text() == agent_token

    def test_preserves_existing_admin_token(self, tmp_path):
        """Existing admin_token file is read, not overwritten."""
        from safeyolo.proxy import _ensure_tokens

        data_dir = tmp_path / "data"
        data_dir.mkdir()
        (data_dir / "admin_token").write_text("my-existing-admin-token")

        admin_token, agent_token = _ensure_tokens(data_dir)

        assert admin_token == "my-existing-admin-token"
        assert (data_dir / "admin_token").read_text() == "my-existing-admin-token"

    def test_persists_agent_token_across_calls(self, tmp_path):
        """Agent token persists across restarts (microVM sandboxes hold a
        copy from boot; regenerating breaks running sandboxes with 401).
        """
        from safeyolo.proxy import _ensure_tokens

        data_dir = tmp_path / "data"
        _, agent1 = _ensure_tokens(data_dir)
        _, agent2 = _ensure_tokens(data_dir)

        assert agent1 == agent2

    def test_sets_file_permissions_to_600(self, tmp_path):
        """Both token files get 0o600 permissions."""
        from safeyolo.proxy import _ensure_tokens

        data_dir = tmp_path / "data"
        _ensure_tokens(data_dir)

        admin_mode = (data_dir / "admin_token").stat().st_mode & 0o777
        agent_mode = (data_dir / "agent_token").stat().st_mode & 0o777
        assert admin_mode == 0o600
        assert agent_mode == 0o600

    def test_creates_data_dir_if_missing(self, tmp_path):
        """data_dir is created (with parents) if it doesn't exist."""
        from safeyolo.proxy import _ensure_tokens

        data_dir = tmp_path / "deep" / "nested" / "data"
        _ensure_tokens(data_dir)

        assert data_dir.is_dir()

    def test_admin_token_whitespace_stripped(self, tmp_path):
        """Existing admin token file with whitespace is stripped."""
        from safeyolo.proxy import _ensure_tokens

        data_dir = tmp_path / "data"
        data_dir.mkdir()
        (data_dir / "admin_token").write_text("  my-token-with-spaces  \n")

        admin_token, _ = _ensure_tokens(data_dir)
        assert admin_token == "my-token-with-spaces"


# ---------------------------------------------------------------------------
# TestBuildCommand
# ---------------------------------------------------------------------------

class TestBuildCommand:
    """Tests for _build_command() — mitmdump command line construction."""

    @pytest.fixture
    def cmd_env(self, tmp_path):
        """Set up minimal filesystem for _build_command."""
        addons_dir = tmp_path / "addons"
        addons_dir.mkdir()
        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "data").mkdir()
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()

        # Create all addon files so they get included
        from safeyolo.proxy import ADDON_CHAIN
        for addon in ADDON_CHAIN:
            (addons_dir / addon).touch()

        # Create a policy file
        (config_dir / "policy.toml").touch()

        return {
            "addons_dir": addons_dir,
            "cert_dir": cert_dir,
            "config_dir": config_dir,
            "data_dir": config_dir / "data",
            "logs_dir": logs_dir,
        }

    def test_basic_command_structure(self, cmd_env):
        """Command starts with mitmdump, listen-host 0.0.0.0, and port."""
        from safeyolo.proxy import _build_command

        cmd = _build_command(
            admin_token="tok",
            proxy_port=8080,
            admin_port=9090,
            **cmd_env,
        )

        assert cmd[0] == "mitmdump" or cmd[0].endswith("/mitmdump")
        assert "--listen-host" in cmd
        idx = cmd.index("--listen-host")
        assert cmd[idx + 1] == "0.0.0.0"
        assert "-p" in cmd
        idx = cmd.index("-p")
        assert cmd[idx + 1] == "8080"

    def test_addons_loaded_in_chain_order(self, cmd_env):
        """Addons appear as -s flags in ADDON_CHAIN order."""
        from safeyolo.proxy import ADDON_CHAIN, _build_command

        cmd = _build_command(
            admin_token="tok",
            **cmd_env,
        )

        # Extract addon paths in order
        addon_paths = []
        for i, arg in enumerate(cmd):
            if arg == "-s":
                addon_paths.append(cmd[i + 1])

        # Should have all addons (all files exist)
        assert len(addon_paths) == len(ADDON_CHAIN)

        # Verify order matches ADDON_CHAIN
        for path, expected_name in zip(addon_paths, ADDON_CHAIN):
            assert path.endswith(expected_name)

    def test_missing_addon_skipped(self, cmd_env):
        """Addon file that doesn't exist on disk is not included in command."""
        from safeyolo.proxy import _build_command

        # Remove one addon file
        (cmd_env["addons_dir"] / "metrics.py").unlink()

        cmd = _build_command(
            admin_token="tok",
            **cmd_env,
        )

        addon_paths = [cmd[i + 1] for i, arg in enumerate(cmd) if arg == "-s"]
        assert not any(p.endswith("metrics.py") for p in addon_paths)

    def test_policy_toml_preferred_over_yaml(self, cmd_env):
        """When both policy.toml and policy.yaml exist, toml is used."""
        from safeyolo.proxy import _build_command

        (cmd_env["config_dir"] / "policy.yaml").touch()
        # policy.toml already exists from fixture

        cmd = _build_command(
            admin_token="tok",
            **cmd_env,
        )

        cmd_str = " ".join(cmd)
        assert "policy.toml" in cmd_str
        assert "policy.yaml" not in cmd_str

    def test_policy_yaml_used_when_no_toml(self, cmd_env):
        """When only policy.yaml exists, it is used."""
        from safeyolo.proxy import _build_command

        (cmd_env["config_dir"] / "policy.toml").unlink()
        (cmd_env["config_dir"] / "policy.yaml").touch()

        cmd = _build_command(
            admin_token="tok",
            **cmd_env,
        )

        cmd_str = " ".join(cmd)
        assert "policy.yaml" in cmd_str

    def test_raises_when_no_policy_file(self, cmd_env):
        """When neither policy file exists, RuntimeError is raised."""
        from safeyolo.proxy import _build_command

        (cmd_env["config_dir"] / "policy.toml").unlink()

        with pytest.raises(RuntimeError, match="No policy file found"):
            _build_command(admin_token="tok", **cmd_env)

    def test_gateway_enabled_when_vault_files_exist(self, cmd_env):
        """Gateway flags present when vault.key and vault.yaml.enc both exist."""
        from safeyolo.proxy import _build_command

        data = cmd_env["config_dir"] / "data"
        (data / "vault.key").touch()
        (data / "vault.yaml.enc").touch()

        cmd = _build_command(
            admin_token="tok",
            **cmd_env,
        )

        cmd_str = " ".join(cmd)
        assert "gateway_enabled=true" in cmd_str
        assert "gateway_services_dir=" in cmd_str
        assert "gateway_vault_path=" in cmd_str
        assert "gateway_vault_key=" in cmd_str

    def test_gateway_not_enabled_without_vault(self, cmd_env):
        """No gateway flags when vault files are missing."""
        from safeyolo.proxy import _build_command

        cmd = _build_command(
            admin_token="tok",
            **cmd_env,
        )

        cmd_str = " ".join(cmd)
        assert "gateway_enabled" not in cmd_str

    def test_gateway_not_enabled_with_only_vault_key(self, cmd_env):
        """Gateway needs both vault.key AND vault.yaml.enc."""
        from safeyolo.proxy import _build_command

        data = cmd_env["config_dir"] / "data"
        (data / "vault.key").touch()
        # vault.yaml.enc intentionally missing

        cmd = _build_command(
            admin_token="tok",
            **cmd_env,
        )

        cmd_str = " ".join(cmd)
        assert "gateway_enabled" not in cmd_str

    def test_agent_map_file_always_set(self, cmd_env):
        """agent_map_file option is always in the command."""
        from safeyolo.proxy import _build_command

        cmd = _build_command(
            admin_token="tok",
            **cmd_env,
        )

        cmd_str = " ".join(cmd)
        assert "agent_map_file=" in cmd_str

    def test_core_options_present(self, cmd_env):
        """Core options (confdir, block_global, stream_large_bodies, etc.) are set."""
        from safeyolo.proxy import _build_command

        cmd = _build_command(
            admin_token="my-admin-tok",
            admin_port=9090,
            **cmd_env,
        )

        cmd_str = " ".join(cmd)
        assert f"confdir={cmd_env['cert_dir']}" in cmd_str
        assert "block_global=false" in cmd_str
        assert "stream_large_bodies=10m" in cmd_str
        assert "admin_port=9090" in cmd_str
        assert "admin_api_token_file=" in cmd_str
        assert "network_guard_block=true" in cmd_str
        assert "credguard_block=true" in cmd_str

    def test_host_override_paths(self, cmd_env):
        """circuit_state_file and flow_store_db_path point to host paths."""
        from safeyolo.proxy import _build_command

        cmd = _build_command(
            admin_token="tok",
            **cmd_env,
        )

        cmd_str = " ".join(cmd)
        expected_data = str(cmd_env["config_dir"] / "data")
        expected_logs = str(cmd_env["logs_dir"])
        assert f"circuit_state_file={expected_data}" in cmd_str
        assert f"flow_store_db_path={expected_logs}" in cmd_str

    def test_custom_ports_in_command(self, cmd_env):
        """Custom proxy and admin ports appear in the command."""
        from safeyolo.proxy import _build_command

        cmd = _build_command(
            admin_token="tok",
            proxy_port=9999,
            admin_port=7777,
            **cmd_env,
        )

        idx = cmd.index("-p")
        assert cmd[idx + 1] == "9999"
        cmd_str = " ".join(cmd)
        assert "admin_port=7777" in cmd_str

    def test_mitmdump_found_via_shutil_which(self, cmd_env):
        """When shutil.which finds mitmdump, that path is used."""
        from safeyolo.proxy import _build_command

        with patch("safeyolo.proxy.shutil.which", return_value="/usr/local/bin/mitmdump"):
            cmd = _build_command(
                admin_token="tok",
                **cmd_env,
            )

        assert cmd[0] == "/usr/local/bin/mitmdump"

    def test_mitmdump_fallback_to_sibling_of_python(self, cmd_env):
        """When shutil.which fails, checks sibling of sys.executable."""
        from safeyolo.proxy import _build_command

        fake_python_dir = cmd_env["config_dir"] / "bin"
        fake_python_dir.mkdir(exist_ok=True)
        fake_mitmdump = fake_python_dir / "mitmdump"
        fake_mitmdump.touch()

        with patch("safeyolo.proxy.shutil.which", return_value=None), \
             patch("safeyolo.proxy.sys.executable", str(fake_python_dir / "python")):
            cmd = _build_command(
                admin_token="tok",
                **cmd_env,
            )

        assert cmd[0] == str(fake_mitmdump)

    def test_mitmdump_fallback_to_bare_name(self, cmd_env, tmp_path):
        """When shutil.which and sibling both fail, falls back to 'mitmdump'."""
        from safeyolo.proxy import _build_command

        fake_python = tmp_path / "nowhere" / "python"
        fake_python.parent.mkdir(parents=True)
        fake_python.touch()

        with patch("safeyolo.proxy.shutil.which", return_value=None), \
             patch("safeyolo.proxy.sys.executable", str(fake_python)):
            cmd = _build_command(
                admin_token="tok",
                **cmd_env,
            )

        assert cmd[0] == "mitmdump"


# ---------------------------------------------------------------------------
# TestBlockingModes
# ---------------------------------------------------------------------------

class TestBlockingModes:
    """Tests for blocking mode configuration in _build_command() (lines 172-197).

    Each addon has a default mode controlled by an env var.
    SAFEYOLO_BLOCK=true overrides all addons to block mode.
    """

    @pytest.fixture
    def cmd_env(self, tmp_path):
        """Set up minimal filesystem for _build_command."""
        addons_dir = tmp_path / "addons"
        addons_dir.mkdir()
        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "data").mkdir()
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()

        from safeyolo.proxy import ADDON_CHAIN
        for addon in ADDON_CHAIN:
            (addons_dir / addon).touch()

        (config_dir / "policy.toml").touch()

        return {
            "addons_dir": addons_dir,
            "cert_dir": cert_dir,
            "config_dir": config_dir,
            "data_dir": config_dir / "data",
            "logs_dir": logs_dir,
        }

    def test_default_blocking_modes(self, cmd_env, monkeypatch):
        """With no env vars, defaults are: network_guard=true, credguard=true,
        pattern not set, test_context=true."""
        from safeyolo.proxy import _build_command

        monkeypatch.delenv("SAFEYOLO_BLOCK", raising=False)
        monkeypatch.delenv("NETWORK_GUARD_BLOCK", raising=False)
        monkeypatch.delenv("CREDGUARD_BLOCK", raising=False)
        monkeypatch.delenv("PATTERN_BLOCK", raising=False)
        monkeypatch.delenv("TEST_CONTEXT_BLOCK", raising=False)

        cmd = _build_command(admin_token="tok", **cmd_env)
        cmd_str = " ".join(cmd)

        assert "network_guard_block=true" in cmd_str
        assert "credguard_block=true" in cmd_str
        assert "pattern_block_input" not in cmd_str
        assert "pattern_block_output" not in cmd_str
        assert "test_context_block=true" in cmd_str

    def test_safeyolo_block_forces_all_to_block(self, cmd_env, monkeypatch):
        """SAFEYOLO_BLOCK=true forces all four addons to block mode,
        including pattern_block_input and pattern_block_output."""
        from safeyolo.proxy import _build_command

        monkeypatch.setenv("SAFEYOLO_BLOCK", "true")
        monkeypatch.delenv("NETWORK_GUARD_BLOCK", raising=False)
        monkeypatch.delenv("CREDGUARD_BLOCK", raising=False)
        monkeypatch.delenv("PATTERN_BLOCK", raising=False)
        monkeypatch.delenv("TEST_CONTEXT_BLOCK", raising=False)

        cmd = _build_command(admin_token="tok", **cmd_env)
        cmd_str = " ".join(cmd)

        assert "network_guard_block=true" in cmd_str
        assert "credguard_block=true" in cmd_str
        assert "pattern_block_input=true" in cmd_str
        assert "pattern_block_output=true" in cmd_str
        assert "test_context_block=true" in cmd_str

    def test_network_guard_warn_only(self, cmd_env, monkeypatch):
        """NETWORK_GUARD_BLOCK=false sets network_guard_block=false."""
        from safeyolo.proxy import _build_command

        monkeypatch.delenv("SAFEYOLO_BLOCK", raising=False)
        monkeypatch.setenv("NETWORK_GUARD_BLOCK", "false")

        cmd = _build_command(admin_token="tok", **cmd_env)
        cmd_str = " ".join(cmd)

        assert "network_guard_block=false" in cmd_str

    def test_credguard_warn_only(self, cmd_env, monkeypatch):
        """CREDGUARD_BLOCK=false sets credguard_block=false."""
        from safeyolo.proxy import _build_command

        monkeypatch.delenv("SAFEYOLO_BLOCK", raising=False)
        monkeypatch.setenv("CREDGUARD_BLOCK", "false")

        cmd = _build_command(admin_token="tok", **cmd_env)
        cmd_str = " ".join(cmd)

        assert "credguard_block=false" in cmd_str

    def test_pattern_block_enabled(self, cmd_env, monkeypatch):
        """PATTERN_BLOCK=true adds pattern_block_input=true and pattern_block_output=true."""
        from safeyolo.proxy import _build_command

        monkeypatch.delenv("SAFEYOLO_BLOCK", raising=False)
        monkeypatch.setenv("PATTERN_BLOCK", "true")

        cmd = _build_command(admin_token="tok", **cmd_env)
        cmd_str = " ".join(cmd)

        assert "pattern_block_input=true" in cmd_str
        assert "pattern_block_output=true" in cmd_str

    def test_pattern_block_default_not_in_command(self, cmd_env, monkeypatch):
        """When PATTERN_BLOCK is not set, pattern_block_input and
        pattern_block_output do not appear in the command at all."""
        from safeyolo.proxy import _build_command

        monkeypatch.delenv("SAFEYOLO_BLOCK", raising=False)
        monkeypatch.delenv("PATTERN_BLOCK", raising=False)

        cmd = _build_command(admin_token="tok", **cmd_env)
        cmd_str = " ".join(cmd)

        assert "pattern_block_input" not in cmd_str
        assert "pattern_block_output" not in cmd_str

    def test_test_context_warn_only(self, cmd_env, monkeypatch):
        """TEST_CONTEXT_BLOCK=false sets test_context_block=false."""
        from safeyolo.proxy import _build_command

        monkeypatch.delenv("SAFEYOLO_BLOCK", raising=False)
        monkeypatch.setenv("TEST_CONTEXT_BLOCK", "false")

        cmd = _build_command(admin_token="tok", **cmd_env)
        cmd_str = " ".join(cmd)

        assert "test_context_block=false" in cmd_str

    def test_safeyolo_block_overrides_individual_false(self, cmd_env, monkeypatch):
        """SAFEYOLO_BLOCK=true overrides CREDGUARD_BLOCK=false -- credguard stays in block mode."""
        from safeyolo.proxy import _build_command

        monkeypatch.setenv("SAFEYOLO_BLOCK", "true")
        monkeypatch.setenv("CREDGUARD_BLOCK", "false")

        cmd = _build_command(admin_token="tok", **cmd_env)
        cmd_str = " ".join(cmd)

        assert "credguard_block=true" in cmd_str


# ---------------------------------------------------------------------------
# TestTlsPassthrough
# ---------------------------------------------------------------------------

class TestTlsPassthrough:
    """Tests for TLS passthrough (--ignore-hosts) in _build_command()."""

    @pytest.fixture
    def cmd_env(self, tmp_path):
        addons_dir = tmp_path / "addons"
        addons_dir.mkdir()
        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "data").mkdir()
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        from safeyolo.proxy import ADDON_CHAIN
        for addon in ADDON_CHAIN:
            (addons_dir / addon).touch()
        (config_dir / "policy.toml").touch()
        return {"addons_dir": addons_dir, "cert_dir": cert_dir, "config_dir": config_dir, "data_dir": config_dir / "data", "logs_dir": logs_dir}

    def test_ignore_hosts_always_present(self, cmd_env):
        """--ignore-hosts with the frp pattern is in every command."""
        from safeyolo.proxy import _build_command

        cmd = _build_command(
            admin_token="tok",
            **cmd_env,
        )

        assert "--ignore-hosts" in cmd
        idx = cmd.index("--ignore-hosts")
        assert cmd[idx + 1] == r"^api\.asterfold\.ai:7000$"


# ---------------------------------------------------------------------------
# TestIgnoreCidrsEnv — SAFEYOLO_IGNORE_CIDRS: converter + integration
# ---------------------------------------------------------------------------

class TestCidrToIgnoreRegex:
    """Pin the CIDR → --ignore-hosts regex conversion shape.

    These tests exist because the generated regex is the user-facing result
    of a CIDR they supplied — any silent drift in what gets exempted is a
    security-posture change.
    """

    def test_slash_32_single_host(self):
        from safeyolo.proxy import _cidr_to_ignore_regex
        assert _cidr_to_ignore_regex("10.0.0.5/32") == r"^10\.0\.0\.5(?::\d+)?$"

    def test_slash_24(self):
        from safeyolo.proxy import _cidr_to_ignore_regex
        assert _cidr_to_ignore_regex("192.168.1.0/24") == r"^192\.168\.1\.\d+(?::\d+)?$"

    def test_slash_16(self):
        from safeyolo.proxy import _cidr_to_ignore_regex
        assert _cidr_to_ignore_regex("192.168.0.0/16") == r"^192\.168\.\d+\.\d+(?::\d+)?$"

    def test_slash_8(self):
        from safeyolo.proxy import _cidr_to_ignore_regex
        assert _cidr_to_ignore_regex("10.0.0.0/8") == r"^10\.\d+\.\d+\.\d+(?::\d+)?$"

    def test_slash_10_tailscale_cgnat(self):
        """Tailscale CGNAT: the main driving case. 100.64.0.0 – 100.127.x.x."""
        from safeyolo.proxy import _cidr_to_ignore_regex
        import re
        regex = _cidr_to_ignore_regex("100.64.0.0/10")
        # Structural shape
        assert regex.startswith(r"^100\.(?:64|")
        assert regex.endswith(r")\.\d+\.\d+(?::\d+)?$")
        # And it actually matches the range boundaries
        pat = re.compile(regex)
        assert pat.match("100.64.0.0:443")
        assert pat.match("100.127.255.255:22")
        assert pat.match("100.100.50.50")  # no port
        # And excludes outside-range IPs
        assert not pat.match("100.63.0.0:22")
        assert not pat.match("100.128.0.0:22")
        assert not pat.match("99.64.0.0:22")

    def test_normalises_host_bits(self):
        """`strict=False` means a non-network address still parses; it should
        normalise to the actual network and produce the same regex as the
        canonical form."""
        from safeyolo.proxy import _cidr_to_ignore_regex
        a = _cidr_to_ignore_regex("192.168.1.5/24")    # host bits set
        b = _cidr_to_ignore_regex("192.168.1.0/24")    # canonical
        assert a == b

    def test_rejects_invalid_cidr(self):
        from safeyolo.proxy import _cidr_to_ignore_regex
        import pytest as _pytest
        with _pytest.raises(ValueError, match="Invalid CIDR"):
            _cidr_to_ignore_regex("not-a-cidr")
        with _pytest.raises(ValueError, match="Invalid CIDR"):
            _cidr_to_ignore_regex("10.0.0.0/99")

    def test_rejects_ipv6(self):
        from safeyolo.proxy import _cidr_to_ignore_regex
        import pytest as _pytest
        with _pytest.raises(ValueError, match="IPv6"):
            _cidr_to_ignore_regex("fd00::/8")

    def test_rejects_too_wide(self):
        """Prefixes < /8 are refused — footgun guard against opening huge
        ranges by typo."""
        from safeyolo.proxy import _cidr_to_ignore_regex
        import pytest as _pytest
        with _pytest.raises(ValueError, match="too wide"):
            _cidr_to_ignore_regex("0.0.0.0/0")
        with _pytest.raises(ValueError, match="too wide"):
            _cidr_to_ignore_regex("10.0.0.0/7")


class TestIgnoreCidrsIntegration:
    """_build_command picks up SAFEYOLO_IGNORE_CIDRS and appends extra
    --ignore-hosts entries alongside the built-in frp pattern."""

    @pytest.fixture
    def cmd_env(self, tmp_path):
        addons_dir = tmp_path / "addons"
        addons_dir.mkdir()
        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "data").mkdir()
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        from safeyolo.proxy import ADDON_CHAIN
        for addon in ADDON_CHAIN:
            (addons_dir / addon).touch()
        (config_dir / "policy.toml").touch()
        return {"addons_dir": addons_dir, "cert_dir": cert_dir, "config_dir": config_dir, "data_dir": config_dir / "data", "logs_dir": logs_dir}

    def _ignore_hosts(self, cmd: list[str]) -> list[str]:
        """Extract every value passed to --ignore-hosts in order."""
        out = []
        for i, arg in enumerate(cmd):
            if arg == "--ignore-hosts" and i + 1 < len(cmd):
                out.append(cmd[i + 1])
        return out

    def test_no_env_is_a_noop(self, cmd_env, monkeypatch):
        """With the env unset, only the built-in frp pattern is present."""
        from safeyolo.proxy import _build_command
        monkeypatch.delenv("SAFEYOLO_IGNORE_CIDRS", raising=False)
        cmd = _build_command(admin_token="tok", **cmd_env)
        assert self._ignore_hosts(cmd) == [r"^api\.asterfold\.ai:7000$"]

    def test_single_cidr_appended(self, cmd_env, monkeypatch):
        from safeyolo.proxy import _build_command
        monkeypatch.setenv("SAFEYOLO_IGNORE_CIDRS", "100.64.0.0/10")
        cmd = _build_command(admin_token="tok", **cmd_env)
        entries = self._ignore_hosts(cmd)
        assert len(entries) == 2
        assert entries[0] == r"^api\.asterfold\.ai:7000$"
        assert entries[1].startswith(r"^100\.(?:64|")

    def test_multiple_cidrs_with_whitespace(self, cmd_env, monkeypatch):
        from safeyolo.proxy import _build_command
        monkeypatch.setenv(
            "SAFEYOLO_IGNORE_CIDRS",
            " 100.64.0.0/10 , 10.0.0.0/8 ,,  192.168.1.0/24 ",
        )
        cmd = _build_command(admin_token="tok", **cmd_env)
        entries = self._ignore_hosts(cmd)
        # frp + 3 CIDRs = 4
        assert len(entries) == 4
        assert entries[1].startswith(r"^100\.(?:64|")
        assert entries[2] == r"^10\.\d+\.\d+\.\d+(?::\d+)?$"
        assert entries[3] == r"^192\.168\.1\.\d+(?::\d+)?$"

    def test_empty_env_is_a_noop(self, cmd_env, monkeypatch):
        """Empty/whitespace-only env value shouldn't add anything."""
        from safeyolo.proxy import _build_command
        monkeypatch.setenv("SAFEYOLO_IGNORE_CIDRS", "  ,, ")
        cmd = _build_command(admin_token="tok", **cmd_env)
        assert self._ignore_hosts(cmd) == [r"^api\.asterfold\.ai:7000$"]

    def test_invalid_cidr_fails_startup(self, cmd_env, monkeypatch):
        """Fail-fast: one bad entry refuses to build the command at all, so
        the proxy never starts with a silently-dropped passthrough."""
        from safeyolo.proxy import _build_command
        monkeypatch.setenv("SAFEYOLO_IGNORE_CIDRS", "100.64.0.0/10,not-a-cidr")
        with pytest.raises(ValueError, match="Invalid CIDR"):
            _build_command(admin_token="tok", **cmd_env)

    def test_too_wide_cidr_fails_startup(self, cmd_env, monkeypatch):
        from safeyolo.proxy import _build_command
        monkeypatch.setenv("SAFEYOLO_IGNORE_CIDRS", "0.0.0.0/0")
        with pytest.raises(ValueError, match="too wide"):
            _build_command(admin_token="tok", **cmd_env)


# ---------------------------------------------------------------------------
# TestRateLimitConfig
# ---------------------------------------------------------------------------

class TestRateLimitConfig:
    """Tests for rate_limits.json conditional loading in _build_command()."""

    @pytest.fixture
    def cmd_env(self, tmp_path):
        addons_dir = tmp_path / "addons"
        addons_dir.mkdir()
        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "data").mkdir()
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        from safeyolo.proxy import ADDON_CHAIN
        for addon in ADDON_CHAIN:
            (addons_dir / addon).touch()
        (config_dir / "policy.toml").touch()
        return {"addons_dir": addons_dir, "cert_dir": cert_dir, "config_dir": config_dir, "data_dir": config_dir / "data", "logs_dir": logs_dir}

    def test_ratelimit_config_loaded_when_file_exists(self, cmd_env):
        """rate_limits.json present -> ratelimit_config option in command."""
        from safeyolo.proxy import _build_command

        ratelimit_file = cmd_env["config_dir"] / "rate_limits.json"
        ratelimit_file.write_text("{}")

        cmd = _build_command(
            admin_token="tok",
            **cmd_env,
        )

        cmd_str = " ".join(cmd)
        assert f"ratelimit_config={ratelimit_file}" in cmd_str

    def test_ratelimit_config_absent_when_no_file(self, cmd_env):
        """No rate_limits.json -> ratelimit_config option not in command."""
        from safeyolo.proxy import _build_command

        cmd = _build_command(
            admin_token="tok",
            **cmd_env,
        )

        cmd_str = " ".join(cmd)
        assert "ratelimit_config=" not in cmd_str


# ---------------------------------------------------------------------------
# TestSafeyoloCaCert
# ---------------------------------------------------------------------------

class TestSafeyoloCaCert:
    """Tests for SAFEYOLO_CA_CERT env var handling in _build_command()."""

    @pytest.fixture
    def cmd_env(self, tmp_path):
        addons_dir = tmp_path / "addons"
        addons_dir.mkdir()
        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "data").mkdir()
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        from safeyolo.proxy import ADDON_CHAIN
        for addon in ADDON_CHAIN:
            (addons_dir / addon).touch()
        (config_dir / "policy.toml").touch()
        return {"addons_dir": addons_dir, "cert_dir": cert_dir, "config_dir": config_dir, "data_dir": config_dir / "data", "logs_dir": logs_dir}

    def test_upstream_ca_set_when_env_var_and_file_exist(self, cmd_env, tmp_path, monkeypatch):
        """SAFEYOLO_CA_CERT points to existing file -> ssl_verify_upstream_trusted_ca in command,
        backed by a combined bundle that contains the custom cert."""
        from safeyolo.proxy import _build_command

        ca_file = tmp_path / "custom-ca.pem"
        ca_file.write_text("CUSTOM CA CERT")
        monkeypatch.setenv("SAFEYOLO_CA_CERT", str(ca_file))

        cmd = _build_command(
            admin_token="tok",
            **cmd_env,
        )

        cmd_str = " ".join(cmd)
        assert "ssl_verify_upstream_trusted_ca=" in cmd_str
        # Bundle path is in cmd; bundle should contain our custom cert
        bundle_arg = next(a for a in cmd if a.startswith("ssl_verify_upstream_trusted_ca="))
        bundle_path = Path(bundle_arg.split("=", 1)[1])
        assert bundle_path.exists()
        assert "CUSTOM CA CERT" in bundle_path.read_text()

    def test_raises_when_ca_cert_file_missing(self, cmd_env, tmp_path, monkeypatch):
        """SAFEYOLO_CA_CERT points to nonexistent file -> RuntimeError."""
        from safeyolo.proxy import _build_command

        nonexistent = tmp_path / "does-not-exist.pem"
        monkeypatch.setenv("SAFEYOLO_CA_CERT", str(nonexistent))

        with pytest.raises(RuntimeError, match="CA cert not found"):
            _build_command(admin_token="tok", **cmd_env)

    def test_no_upstream_ca_when_env_var_unset(self, cmd_env, monkeypatch):
        """No SAFEYOLO_CA_CERT env var -> ssl_verify_upstream_trusted_ca not in command."""
        from safeyolo.proxy import _build_command

        monkeypatch.delenv("SAFEYOLO_CA_CERT", raising=False)

        cmd = _build_command(
            admin_token="tok",
            **cmd_env,
        )

        cmd_str = " ".join(cmd)
        assert "ssl_verify_upstream_trusted_ca" not in cmd_str


# ---------------------------------------------------------------------------
# TestCertDirPermissions
# ---------------------------------------------------------------------------

class TestCertDirPermissions:
    """Tests for cert directory permission hardening in _ensure_certs()."""

    def test_cert_dir_gets_700_on_generation(self, tmp_path):
        """After generating certs, cert_dir mode is 0o700."""
        from safeyolo.proxy import _ensure_certs

        cert_dir = tmp_path / "certs"

        def create_cert_files(*args, **kwargs):
            cert_dir.mkdir(parents=True, exist_ok=True)
            (cert_dir / "mitmproxy-ca-cert.pem").write_text("cert")
            (cert_dir / "mitmproxy-ca.pem").write_text("ca-key")
            return MagicMock(returncode=0)

        with patch("safeyolo.proxy.subprocess.run", side_effect=create_cert_files):
            _ensure_certs(cert_dir)

        assert cert_dir.stat().st_mode & 0o777 == 0o700


# ---------------------------------------------------------------------------
# TestPidFileManagement
# ---------------------------------------------------------------------------

class TestPidFileManagement:
    """Tests for is_proxy_running() and stop_proxy() PID file handling."""

    def test_is_running_false_when_no_pid_file(self, tmp_path, monkeypatch):
        """No PID file -> is_proxy_running returns False."""
        from safeyolo.proxy import is_proxy_running

        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
        (tmp_path / "data").mkdir(exist_ok=True)

        assert is_proxy_running() is False

    def test_is_running_true_when_process_alive(self, tmp_path, monkeypatch):
        """PID file with live PID -> returns True."""
        from safeyolo.proxy import is_proxy_running

        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
        data_dir = tmp_path / "data"
        data_dir.mkdir(exist_ok=True)
        (data_dir / "proxy.pid").write_text(str(os.getpid()))

        assert is_proxy_running() is True

    def test_is_running_cleans_stale_pid_file(self, tmp_path, monkeypatch):
        """PID file with dead PID -> returns False and removes PID file."""
        from safeyolo.proxy import is_proxy_running

        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
        data_dir = tmp_path / "data"
        data_dir.mkdir(exist_ok=True)
        pid_file = data_dir / "proxy.pid"
        pid_file.write_text("99999999")  # Almost certainly not a real PID

        with patch("safeyolo.proxy.os.kill", side_effect=ProcessLookupError):
            result = is_proxy_running()

        assert result is False
        assert not pid_file.exists()

    def test_stop_sends_sigterm(self, tmp_path, monkeypatch):
        """stop_proxy sends SIGTERM to the PID from the file."""
        from safeyolo.proxy import stop_proxy

        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
        data_dir = tmp_path / "data"
        data_dir.mkdir(exist_ok=True)
        (data_dir / "proxy.pid").write_text("12345")

        kill_calls = []

        def mock_kill(pid, sig):
            kill_calls.append((pid, sig))
            if sig == signal.SIGTERM:
                return  # "Process received signal"
            raise ProcessLookupError  # Process already exited when we check

        with patch("safeyolo.proxy.os.kill", side_effect=mock_kill), \
             patch("safeyolo.proxy.time.sleep"):
            stop_proxy()

        # First call is SIGTERM
        assert kill_calls[0] == (12345, signal.SIGTERM)

    def test_stop_noop_when_no_pid_file(self, tmp_path, monkeypatch):
        """stop_proxy does nothing when no PID file exists."""
        from safeyolo.proxy import stop_proxy

        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
        (tmp_path / "data").mkdir(exist_ok=True)

        # Should not raise
        stop_proxy()

    def test_stop_cleans_pid_file_when_process_already_dead(self, tmp_path, monkeypatch):
        """stop_proxy cleans up PID file when SIGTERM fails with ProcessLookupError."""
        from safeyolo.proxy import stop_proxy

        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
        data_dir = tmp_path / "data"
        data_dir.mkdir(exist_ok=True)
        pid_file = data_dir / "proxy.pid"
        pid_file.write_text("12345")

        with patch("safeyolo.proxy.os.kill", side_effect=ProcessLookupError):
            stop_proxy()

        assert not pid_file.exists()

    def test_stop_force_kills_after_timeout(self, tmp_path, monkeypatch):
        """Process that doesn't exit after SIGTERM gets SIGKILL."""
        from safeyolo.proxy import stop_proxy

        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
        data_dir = tmp_path / "data"
        data_dir.mkdir(exist_ok=True)
        (data_dir / "proxy.pid").write_text("12345")

        kill_calls = []

        def mock_kill(pid, sig):
            kill_calls.append((pid, sig))
            # Process never dies — signal 0 always succeeds (no exception)
            return None

        with patch("safeyolo.proxy.os.kill", side_effect=mock_kill), \
             patch("safeyolo.proxy.time.sleep"):
            stop_proxy()

        signals_sent = [sig for _, sig in kill_calls]
        assert signal.SIGTERM in signals_sent
        assert signal.SIGKILL in signals_sent


# ---------------------------------------------------------------------------
# TestGetCaCertPath
# ---------------------------------------------------------------------------

class TestGetCaCertPath:
    """Tests for get_ca_cert_path() — CA certificate path lookup."""

    def test_returns_path_when_cert_exists(self, tmp_path, monkeypatch):
        """When cert file exists, returns its Path."""
        from safeyolo.proxy import get_ca_cert_path

        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
        certs = tmp_path / "certs"
        certs.mkdir()
        cert = certs / "mitmproxy-ca-cert.pem"
        cert.write_text("CERT")

        result = get_ca_cert_path()

        assert result == cert

    def test_returns_none_when_cert_missing(self, tmp_path, monkeypatch):
        """When cert file doesn't exist, returns None."""
        from safeyolo.proxy import get_ca_cert_path

        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))

        result = get_ca_cert_path()

        assert result is None


# ---------------------------------------------------------------------------
# TestStartProxy
# ---------------------------------------------------------------------------

class TestStartProxy:
    """Tests for start_proxy() — the orchestrator function."""

    def test_skips_when_already_running(self, tmp_path, monkeypatch):
        """start_proxy returns early if proxy is already running."""
        from safeyolo.proxy import start_proxy

        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))

        with patch("safeyolo.proxy.is_proxy_running", return_value=True), \
             patch("safeyolo.proxy._find_addons_dir") as mock_find:
            start_proxy()

        # _find_addons_dir should never be called if already running
        mock_find.assert_not_called()

    def test_raises_when_addons_dir_not_found(self, tmp_path, monkeypatch):
        """start_proxy raises RuntimeError when addons dir is not found."""
        from safeyolo.proxy import start_proxy

        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
        (tmp_path / "data").mkdir(exist_ok=True)

        with patch("safeyolo.proxy.is_proxy_running", return_value=False), \
             patch("safeyolo.proxy._find_addons_dir", return_value=None):
            with pytest.raises(RuntimeError, match="Cannot find addons directory"):
                start_proxy()

    def test_writes_pid_file_on_success(self, tmp_path, monkeypatch):
        """start_proxy writes PID file after launching the process."""
        from safeyolo.proxy import start_proxy

        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
        monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(tmp_path / "logs"))
        data_dir = tmp_path / "data"
        data_dir.mkdir(exist_ok=True)
        (tmp_path / "logs").mkdir(exist_ok=True)
        (tmp_path / "policy.toml").touch()

        # Create minimal addons dir
        addons_dir = tmp_path / "addons"
        addons_dir.mkdir()

        mock_proc = MagicMock()
        mock_proc.pid = 42

        with patch("safeyolo.proxy.is_proxy_running", return_value=False), \
             patch("safeyolo.proxy._find_addons_dir", return_value=addons_dir), \
             patch("safeyolo.proxy._find_pdp_dir", return_value=None), \
             patch("safeyolo.proxy._ensure_certs", return_value=tmp_path / "certs" / "ca.pem"), \
             patch("safeyolo.proxy._ensure_tokens", return_value=("admin", "agent")), \
             patch("safeyolo.proxy._build_command", return_value=["mitmdump"]), \
             patch("safeyolo.proxy.subprocess.Popen", return_value=mock_proc), \
             patch("builtins.open", MagicMock()):
            start_proxy()

        pid_file = data_dir / "proxy.pid"
        assert pid_file.exists()
        assert pid_file.read_text() == "42"


# ---------------------------------------------------------------------------
# TestWaitForHealthy
# ---------------------------------------------------------------------------

class TestWaitForHealthy:
    """Tests for wait_for_healthy() — admin API health polling."""

    def test_returns_true_on_immediate_health(self, tmp_path, monkeypatch):
        """Returns True when health endpoint responds 200 immediately."""
        from safeyolo.proxy import wait_for_healthy

        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
        data_dir = tmp_path / "data"
        data_dir.mkdir(exist_ok=True)
        (data_dir / "admin_token").write_text("test-token")

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = wait_for_healthy(timeout=1, admin_port=9090)

        assert result is True

    def test_returns_false_on_timeout(self, tmp_path, monkeypatch):
        """Returns False when health endpoint never responds within timeout."""
        import urllib.error

        from safeyolo.proxy import wait_for_healthy

        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
        data_dir = tmp_path / "data"
        data_dir.mkdir(exist_ok=True)

        with patch("urllib.request.urlopen", side_effect=ConnectionError), \
             patch("safeyolo.proxy.time.sleep"):
            result = wait_for_healthy(timeout=2, admin_port=9090)

        assert result is False

    def test_reads_token_from_file(self, tmp_path, monkeypatch):
        """Health check uses Bearer token from admin_token file."""
        from safeyolo.proxy import wait_for_healthy

        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
        data_dir = tmp_path / "data"
        data_dir.mkdir(exist_ok=True)
        (data_dir / "admin_token").write_text("secret-tok-123")

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        captured_request = None

        def capture_urlopen(req, **kwargs):
            nonlocal captured_request
            captured_request = req
            return mock_resp

        with patch("urllib.request.urlopen", side_effect=capture_urlopen):
            wait_for_healthy(timeout=1, admin_port=9090)

        assert captured_request is not None
        assert captured_request.get_header("Authorization") == "Bearer secret-tok-123"
