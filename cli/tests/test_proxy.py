"""
Tests for proxy.py — Host mitmproxy process management.

Tests command construction, token generation, cert management,
PID file lifecycle, and directory discovery.
"""

import json
import os
import signal
import socket
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest


class _HealthResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

# ---------------------------------------------------------------------------
# TestAddonChain
# ---------------------------------------------------------------------------

class TestAddonChain:
    """Tests for ADDON_CHAIN ordering and completeness."""

    def test_all_addons_load_as_one_package_generation(self):
        """The production container imports every configured package module."""
        from importlib import import_module

        from safeyolo.mitm_addons import ADDON_CHAIN, ProductionAddons

        production = ProductionAddons()
        expected = []
        for addon_file in ADDON_CHAIN:
            module_name = addon_file.removesuffix(".py")
            module = import_module(f"safeyolo.mitm_addons.{module_name}")
            expected.extend(module.addons)

        assert production.addons == expected

    def test_addon_chain_has_expected_count(self):
        """ADDON_CHAIN contains the complete ordered addon set."""
        from safeyolo.proxy import ADDON_CHAIN
        assert len(ADDON_CHAIN) == 27

    def test_addon_chain_starts_with_readiness_writer(self):
        """Script addons start with the readiness writer.

        Unix listener registration is handled directly by TrafficMaster and
        bootstrap_mode is obsolete now that initial modes bind in setup.
        """
        from safeyolo.proxy import ADDON_CHAIN
        assert ADDON_CHAIN[0] == "pid_writer.py"

    def test_reserved_destination_guards_have_required_order(self):
        """Request and transport containment occupy their required layers.

        Reserved-host layering requires:
          - agent_api.py: normal Agent API handler, loaded earlier
          - agent_api_guard.py: independent request containment immediately
            after the handler and before policy/security/observability addons
          - probe_sink.py: normal terminator, MUST run after every
            security addon
          - transport_guard.py: probe request failsafe and final structural
            server-connect backstop

        Any change to this ordering needs matching updates to both
        addons' docstrings and the ADDON_CHAIN comment block.
        """
        from safeyolo.proxy import ADDON_CHAIN
        assert ADDON_CHAIN[-1] == "transport_guard.py"
        # And probe_sink is immediately before it:
        assert ADDON_CHAIN[-2] == "probe_sink.py"
        api_index = ADDON_CHAIN.index("agent_api.py")
        assert ADDON_CHAIN[api_index + 1] == "agent_api_guard.py"
        assert ADDON_CHAIN.index("agent_api_guard.py") < ADDON_CHAIN.index(
            "network_guard.py"
        )

    def test_agent_api_import_failure_keeps_independent_containment(
        self, monkeypatch
    ):
        """Only handler import failure is recoverable; its guards still load."""
        from mitmproxy.test import tflow

        import safeyolo.mitm_addons as addon_package

        real_import = addon_package.import_module

        def import_with_broken_handler(module_name):
            if module_name == "safeyolo.mitm_addons.agent_api":
                raise ImportError("deliberate handler import failure")
            return real_import(module_name)

        monkeypatch.setattr(addon_package, "import_module", import_with_broken_handler)
        production = addon_package.ProductionAddons()
        names = [getattr(addon, "name", None) for addon in production.addons]

        assert "agent-api" not in names
        assert "agent-api-request-guard" in names
        assert names.index("agent-api-request-guard") < names.index("network-guard")
        assert names[-1] == "transport-guard"

        flow = tflow.tflow()
        flow.request.url = "http://_safeyolo.proxy.internal/health?token=secret"
        guard = next(
            addon for addon in production.addons
            if getattr(addon, "name", None) == "agent-api-request-guard"
        )
        with patch(
            "safeyolo.mitm_addons.agent_api_guard.write_event", autospec=True
        ):
            guard.request(flow)

        assert flow.response.status_code == 503
        assert flow.request.path == "/health"

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

    def test_returns_none_when_no_addons_dir_exists(self, tmp_path, monkeypatch):
        """When no candidate directory has request_id.py, returns None."""
        from safeyolo.proxy import _find_addons_dir

        monkeypatch.delenv("SAFEYOLO_ADDONS_DIR", raising=False)
        # Patch __file__ to point to a location with no valid addons dir
        fake_file = tmp_path / "cli" / "src" / "safeyolo" / "proxy.py"
        fake_file.parent.mkdir(parents=True)
        fake_file.touch()

        with patch("safeyolo.proxy.__file__", str(fake_file)):
            result = _find_addons_dir()

        assert result is None

    def test_returns_path_when_marker_file_exists(self, tmp_path, monkeypatch):
        """When the sibling mitm_addons dir has request_id.py, returns it.

        Post-#200-phase-5: addons ship inside the safeyolo package, so
        `_find_addons_dir` looks next to `proxy.py` for a
        `mitm_addons/` sibling — no more reaching up to a repo root.
        """
        from safeyolo.proxy import _find_addons_dir

        monkeypatch.delenv("SAFEYOLO_ADDONS_DIR", raising=False)
        package_dir = tmp_path / "cli" / "src" / "safeyolo"
        package_dir.mkdir(parents=True)
        (package_dir / "__init__.py").touch()
        proxy_file = package_dir / "proxy.py"
        proxy_file.touch()

        mitm_addons = package_dir / "mitm_addons"
        mitm_addons.mkdir()
        (mitm_addons / "__init__.py").touch()
        (mitm_addons / "request_id.py").touch()

        with patch("safeyolo.proxy.__file__", str(proxy_file)):
            result = _find_addons_dir()

        assert result == mitm_addons

    def test_override_selects_containing_checkout_package(self, tmp_path, monkeypatch):
        """The traffic child imports all safeyolo modules from the override checkout."""
        from safeyolo.proxy import _child_pythonpath, _find_addons_dir

        cli_src = tmp_path / "checkout" / "cli" / "src"
        package_dir = cli_src / "safeyolo"
        addons_dir = package_dir / "mitm_addons"
        addons_dir.mkdir(parents=True)
        (package_dir / "__init__.py").touch()
        (addons_dir / "__init__.py").touch()
        (addons_dir / "request_id.py").touch()
        monkeypatch.setenv("SAFEYOLO_ADDONS_DIR", str(addons_dir))

        selected = _find_addons_dir()

        assert selected == addons_dir
        assert _child_pythonpath(selected, None).split(os.pathsep)[0] == str(cli_src)


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
    """Tests for _ensure_certs() — CA certificate generation via mitmdump.

    The implementation launches mitmdump as a background Popen and polls
    the filesystem for ``mitmproxy-ca-cert.pem``. The tests mock
    ``subprocess.Popen`` with a lightweight fake that lets us control the
    perceived state of the child process.
    """

    def _fake_popen_factory(self, on_start=None, exit_after=None,
                            exit_code=0):
        """Build a Popen-compatible stub.

        - ``on_start``: callable invoked on construction (typically used to
          simulate mitmdump writing the cert).
        - ``exit_after``: how many ``poll()`` calls return None before
          surfacing ``exit_code`` (None = never exit).
        """
        class _FakePopen:
            def __init__(self, *args, **kwargs):
                self._polls = 0
                if on_start is not None:
                    on_start()

            def poll(self):
                if exit_after is not None and self._polls >= exit_after:
                    self.returncode = exit_code
                    return exit_code
                self._polls += 1
                return None

            def terminate(self):
                pass

            def wait(self, timeout=None):  # noqa: ARG002
                self.returncode = exit_code
                return exit_code

            def kill(self):
                pass

        return _FakePopen

    def test_generates_cert_when_missing(self, tmp_path):
        """When cert doesn't exist, Popen is spawned and returns cert path."""
        from safeyolo.proxy import _ensure_certs

        cert_dir = tmp_path / "certs"
        ca_cert = cert_dir / "mitmproxy-ca-cert.pem"

        def create_cert():
            cert_dir.mkdir(parents=True, exist_ok=True)
            ca_cert.write_text("FAKE CERT")

        fake_popen = self._fake_popen_factory(on_start=create_cert)

        with patch("safeyolo.proxy.subprocess.Popen", fake_popen) as _:
            result = _ensure_certs(cert_dir)

        assert result == ca_cert

    def test_skips_generation_when_cert_exists(self, tmp_path):
        """When cert already exists, no subprocess call is made."""
        from safeyolo.proxy import _ensure_certs

        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        ca_cert = cert_dir / "mitmproxy-ca-cert.pem"
        ca_cert.write_text("EXISTING CERT")

        with patch("safeyolo.proxy.subprocess.Popen", autospec=True,) as mock_popen:
            result = _ensure_certs(cert_dir)

        assert result == ca_cert
        mock_popen.assert_not_called()

    def test_raises_when_mitmdump_exits_before_cert(self, tmp_path):
        """mitmdump crashing before writing the cert surfaces as RuntimeError."""
        from safeyolo.proxy import _ensure_certs

        cert_dir = tmp_path / "certs"

        # No on_start, immediate exit with non-zero rc — cert never written.
        fake_popen = self._fake_popen_factory(exit_after=0, exit_code=3)

        with patch("safeyolo.proxy.subprocess.Popen", fake_popen):
            with pytest.raises(RuntimeError, match="mitmdump exited"):
                _ensure_certs(cert_dir)

    def test_sets_permissions_on_generated_pem_files(self, tmp_path):
        """Generated .pem and .p12 files get 0o600 permissions."""
        from safeyolo.proxy import _ensure_certs

        cert_dir = tmp_path / "certs"

        def create_cert_files():
            cert_dir.mkdir(parents=True, exist_ok=True)
            (cert_dir / "mitmproxy-ca-cert.pem").write_text("cert")
            (cert_dir / "mitmproxy-ca.pem").write_text("ca")
            (cert_dir / "mitmproxy-ca.p12").write_bytes(b"p12")
            (cert_dir / "readme.txt").write_text("not a cert")

        fake_popen = self._fake_popen_factory(on_start=create_cert_files)

        with patch("safeyolo.proxy.subprocess.Popen", fake_popen):
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

        def create_cert():
            ca_cert.write_text("CERT")

        fake_popen = self._fake_popen_factory(on_start=create_cert)

        with patch("safeyolo.proxy.subprocess.Popen", fake_popen):
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

        fake_certifi = SimpleNamespace(where=lambda: str(certifi_file))

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

        fake_certifi = SimpleNamespace(where=lambda: str(certifi_file))

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

        fake_certifi = SimpleNamespace(where=lambda: str(certifi_file))

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
        # Remove certifi from sys.modules so the function's `import certifi`
        # hits our patched importer.
        import builtins

        from safeyolo.proxy import _merge_system_cas_into_certifi

        original_import = builtins.__import__

        def fail_certifi(name, *args, **kwargs):
            if name == "certifi":
                raise ImportError("No module named 'certifi'")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=fail_certifi, autospec=True,), \
             patch("safeyolo.proxy.log", autospec=True,) as mock_log:
            _merge_system_cas_into_certifi()

        mock_log.warning.assert_called_once()
        assert "certifi" in mock_log.warning.call_args[0][0].lower() or \
               "certifi" in str(mock_log.warning.call_args[0])

    def test_deduplicates_certs(self, tmp_path):
        """System bundle has 3 certs, 1 already in certifi -> only 2 appended."""
        from safeyolo.proxy import _merge_system_cas_into_certifi

        certifi_file = tmp_path / "certifi_bundle.pem"
        certifi_file.write_text(_CERT_A)

        fake_certifi = SimpleNamespace(where=lambda: str(certifi_file))

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
             patch("safeyolo.proxy.log", autospec=True,) as mock_log:
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

        fake_certifi = SimpleNamespace(where=lambda: str(certifi_file))

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

class TestFlowCacheConfiguration:
    def test_cli_overrides_environment(self):
        from safeyolo.proxy import resolve_flow_cache

        assert resolve_flow_cache(123, {"SAFEYOLO_FLOW_CACHE": "456"}) == 123

    def test_environment_overrides_default(self):
        from safeyolo.proxy import resolve_flow_cache

        assert resolve_flow_cache(None, {"SAFEYOLO_FLOW_CACHE": "456"}) == 456

    def test_default_is_used_when_unconfigured(self):
        from safeyolo.proxy import resolve_flow_cache

        assert resolve_flow_cache(None, {}) == 5000

    @pytest.mark.parametrize("value", ["", "invalid", "0", "-1"])
    def test_invalid_environment_fails(self, value):
        from safeyolo.proxy import resolve_flow_cache

        with pytest.raises(ValueError, match="positive integer"):
            resolve_flow_cache(None, {"SAFEYOLO_FLOW_CACHE": value})

    def test_body_bytes_environment_overrides_default(self):
        from safeyolo.proxy import resolve_flow_cache_bytes

        assert resolve_flow_cache_bytes(None, {"SAFEYOLO_FLOW_CACHE_BYTES": "456"}) == 456

    def test_body_bytes_default_is_one_gibibyte(self):
        from safeyolo.proxy import resolve_flow_cache_bytes

        assert resolve_flow_cache_bytes(None, {}) == 1024**3

    @pytest.mark.parametrize("value", ["", "invalid", "0", "-1"])
    def test_invalid_body_bytes_environment_fails(self, value):
        from safeyolo.proxy import resolve_flow_cache_bytes

        with pytest.raises(ValueError, match="positive integer"):
            resolve_flow_cache_bytes(None, {"SAFEYOLO_FLOW_CACHE_BYTES": value})


class TestBuildCommand:
    """Tests for _build_command() — mitmdump command line construction."""

    @pytest.fixture
    def cmd_env(self, tmp_path):
        """Set up minimal filesystem for _build_command."""
        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "data").mkdir()
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()

        # Create a policy file
        (config_dir / "policy.toml").touch()

        return {
            "cert_dir": cert_dir,
            "config_dir": config_dir,
            "data_dir": config_dir / "data",
            "logs_dir": logs_dir,
        }

    def test_basic_command_structure(self, cmd_env):
        """Command delegates initial listener binding to TrafficMaster.

        TrafficMaster registers UnixMode before parsing options and applies
        host-generated modes immediately before Master.run(), so there is no
        bootstrap addon or transient TCP listener in the command.
        """
        from safeyolo.proxy import _build_command

        cmd = _build_command(
            admin_token="tok",
            proxy_port=8080,
            admin_port=9090,
            **cmd_env,
        )

        assert cmd[1:5] == ["-P", "-s", "-m", "safeyolo.traffic_master"]
        assert "--listen-host" not in cmd
        assert not any(a.startswith("mode=") for a in cmd)
        assert "listen_host=127.0.0.1" not in cmd
        assert "listen_port=0" not in cmd
        assert "flow_pruner_max=5000" in cmd
        assert "flow_pruner_max_body_bytes=1073741824" in cmd

    def test_explicit_flow_cache_is_forwarded(self, cmd_env):
        from safeyolo.proxy import _build_command

        cmd = _build_command(admin_token="tok", flow_cache=4321, **cmd_env)

        assert "flow_pruner_max=4321" in cmd

    def test_explicit_flow_cache_bytes_is_forwarded(self, cmd_env):
        from safeyolo.proxy import _build_command

        cmd = _build_command(admin_token="tok", flow_cache_bytes=987654, **cmd_env)

        assert "flow_pruner_max_body_bytes=987654" in cmd

    def test_production_addons_are_not_watched_scripts(self, cmd_env):
        """The production command leaves mitmproxy's scripts option empty."""
        from safeyolo.proxy import _build_command

        cmd = _build_command(
            admin_token="tok",
            **cmd_env,
        )

        assert "-s" not in cmd[5:]
        assert not any(arg.startswith("scripts=") for arg in cmd)

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
        assert "gateway_builtin_services_dir=" in cmd_str
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

    def test_gateway_service_schema_failure_aborts_command_build(self, cmd_env):
        from safeyolo.proxy import _build_command

        data = cmd_env["config_dir"] / "data"
        (data / "vault.key").touch()
        (data / "vault.yaml.enc").touch()
        services = cmd_env["config_dir"] / "services"
        services.mkdir()
        (services / "broken.yaml").write_text("not: valid: yaml: [")

        with pytest.raises(RuntimeError, match="broken.yaml"):
            _build_command(admin_token="tok", **cmd_env)

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

    def test_custom_admin_port_in_command(self, cmd_env):
        """Custom admin port appears in --set admin_port=…

        Post-refactor: `proxy_port` is kept in the signature for
        backwards compatibility but no longer binds a TCP listener —
        mitmproxy ingress is UDS-only (one UnixInstance per agent).
        """
        from safeyolo.proxy import _build_command

        cmd = _build_command(
            admin_token="tok",
            proxy_port=9999,
            admin_port=7777,
            **cmd_env,
        )

        cmd_str = " ".join(cmd)
        assert "admin_port=7777" in cmd_str
        # No TCP listener bind flags remain.
        assert "-p" not in cmd
        assert "--listen-host" not in cmd

    def test_hybrid_master_uses_active_python_environment(self, cmd_env):
        """The hybrid entrypoint runs in SafeYolo's active Python runtime."""
        from safeyolo.proxy import _build_command

        fake_python_dir = cmd_env["config_dir"] / "bin"
        fake_python_dir.mkdir(exist_ok=True)

        with patch("safeyolo.proxy.sys.executable", str(fake_python_dir / "python")):
            cmd = _build_command(
                admin_token="tok",
                **cmd_env,
            )

        assert cmd[:5] == [
            str(fake_python_dir / "python"),
            "-P",
            "-s",
            "-m",
            "safeyolo.traffic_master",
        ]


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
        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "data").mkdir()
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()

        (config_dir / "policy.toml").touch()

        return {
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
        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "data").mkdir()
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        (config_dir / "policy.toml").touch()
        return {"cert_dir": cert_dir, "config_dir": config_dir, "data_dir": config_dir / "data", "logs_dir": logs_dir}

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
        from safeyolo.ignore_hosts import cidr_to_ignore_regex
        assert cidr_to_ignore_regex("10.0.0.5/32") == r"^10\.0\.0\.5(?::\d+)?$"

    def test_slash_24(self):
        from safeyolo.ignore_hosts import cidr_to_ignore_regex
        assert cidr_to_ignore_regex("192.168.1.0/24") == r"^192\.168\.1\.\d+(?::\d+)?$"

    def test_slash_16(self):
        from safeyolo.ignore_hosts import cidr_to_ignore_regex
        assert cidr_to_ignore_regex("192.168.0.0/16") == r"^192\.168\.\d+\.\d+(?::\d+)?$"

    def test_slash_8(self):
        from safeyolo.ignore_hosts import cidr_to_ignore_regex
        assert cidr_to_ignore_regex("10.0.0.0/8") == r"^10\.\d+\.\d+\.\d+(?::\d+)?$"

    def test_slash_10_tailscale_cgnat(self):
        """Tailscale CGNAT: the main driving case. 100.64.0.0 – 100.127.x.x."""
        import re

        from safeyolo.ignore_hosts import cidr_to_ignore_regex
        regex = cidr_to_ignore_regex("100.64.0.0/10")
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
        from safeyolo.ignore_hosts import cidr_to_ignore_regex
        a = cidr_to_ignore_regex("192.168.1.5/24")    # host bits set
        b = cidr_to_ignore_regex("192.168.1.0/24")    # canonical
        assert a == b

    def test_rejects_invalid_cidr(self):
        import pytest as _pytest

        from safeyolo.ignore_hosts import cidr_to_ignore_regex
        with _pytest.raises(ValueError, match="Invalid CIDR"):
            cidr_to_ignore_regex("not-a-cidr")
        with _pytest.raises(ValueError, match="Invalid CIDR"):
            cidr_to_ignore_regex("10.0.0.0/99")

    def test_rejects_ipv6(self):
        import pytest as _pytest

        from safeyolo.ignore_hosts import cidr_to_ignore_regex
        with _pytest.raises(ValueError, match="IPv6"):
            cidr_to_ignore_regex("fd00::/8")

    def test_rejects_too_wide(self):
        """Prefixes < /8 are refused — footgun guard against opening huge
        ranges by typo."""
        import pytest as _pytest

        from safeyolo.ignore_hosts import cidr_to_ignore_regex
        with _pytest.raises(ValueError, match="too wide"):
            cidr_to_ignore_regex("0.0.0.0/0")
        with _pytest.raises(ValueError, match="too wide"):
            cidr_to_ignore_regex("10.0.0.0/7")


class TestIgnoreCidrsIntegration:
    """_build_command picks up SAFEYOLO_IGNORE_CIDRS and appends extra
    --ignore-hosts entries alongside the built-in frp pattern."""

    @pytest.fixture
    def cmd_env(self, tmp_path):
        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "data").mkdir()
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        (config_dir / "policy.toml").touch()
        return {"cert_dir": cert_dir, "config_dir": config_dir, "data_dir": config_dir / "data", "logs_dir": logs_dir}

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

    def test_operator_hosts_are_appended_as_exact_patterns(self, cmd_env, monkeypatch):
        from safeyolo.proxy import _build_command
        monkeypatch.delenv("SAFEYOLO_IGNORE_CIDRS", raising=False)
        cmd = _build_command(
            admin_token="tok",
            proxy_config={"ignore_hosts": ["Service.Example.Test:443"]},
            **cmd_env,
        )
        assert self._ignore_hosts(cmd) == [
            r"^api\.asterfold\.ai:7000$",
            r"^service\.example\.test:443$",
        ]

    def test_invalid_operator_host_fails_startup(self, cmd_env, monkeypatch):
        from safeyolo.proxy import _build_command
        monkeypatch.delenv("SAFEYOLO_IGNORE_CIDRS", raising=False)
        with pytest.raises(ValueError, match="valid hostname"):
            _build_command(
                admin_token="tok",
                proxy_config={"ignore_hosts": ["*.example.test"]},
                **cmd_env,
            )

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
        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "data").mkdir()
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        (config_dir / "policy.toml").touch()
        return {"cert_dir": cert_dir, "config_dir": config_dir, "data_dir": config_dir / "data", "logs_dir": logs_dir}

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
    """Tests for additional upstream CA handling in _build_command()."""

    @pytest.fixture
    def cmd_env(self, tmp_path):
        cert_dir = tmp_path / "certs"
        cert_dir.mkdir()
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "data").mkdir()
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        (config_dir / "policy.toml").touch()
        return {"cert_dir": cert_dir, "config_dir": config_dir, "data_dir": config_dir / "data", "logs_dir": logs_dir}

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

    def test_upstream_ca_set_from_persistent_proxy_config(
        self, cmd_env, tmp_path, monkeypatch
    ):
        from safeyolo.proxy import _build_command

        monkeypatch.delenv("SAFEYOLO_CA_CERT", raising=False)
        ca_file = tmp_path / "persistent-ca.pem"
        ca_file.write_text("PERSISTENT CA CERT")

        cmd = _build_command(
            admin_token="tok",
            proxy_config={"upstream_ca_cert": str(ca_file)},
            **cmd_env,
        )

        bundle_arg = next(
            arg for arg in cmd if arg.startswith("ssl_verify_upstream_trusted_ca=")
        )
        bundle_path = Path(bundle_arg.split("=", 1)[1])
        assert "PERSISTENT CA CERT" in bundle_path.read_text()

    def test_environment_ca_overrides_persistent_config(
        self, cmd_env, tmp_path, monkeypatch
    ):
        from safeyolo.proxy import _build_command

        environment_ca = tmp_path / "environment-ca.pem"
        environment_ca.write_text("ENVIRONMENT CA CERT")
        persistent_ca = tmp_path / "persistent-ca.pem"
        persistent_ca.write_text("PERSISTENT CA CERT")
        monkeypatch.setenv("SAFEYOLO_CA_CERT", str(environment_ca))

        cmd = _build_command(
            admin_token="tok",
            proxy_config={"upstream_ca_cert": str(persistent_ca)},
            **cmd_env,
        )

        bundle_arg = next(
            arg for arg in cmd if arg.startswith("ssl_verify_upstream_trusted_ca=")
        )
        bundle = Path(bundle_arg.split("=", 1)[1]).read_text()
        assert "ENVIRONMENT CA CERT" in bundle
        assert "PERSISTENT CA CERT" not in bundle

    def test_raises_when_persistent_ca_file_missing(
        self, cmd_env, tmp_path, monkeypatch
    ):
        from safeyolo.proxy import _build_command

        monkeypatch.delenv("SAFEYOLO_CA_CERT", raising=False)
        nonexistent = tmp_path / "missing-persistent.pem"

        with pytest.raises(RuntimeError, match="CA cert not found"):
            _build_command(
                admin_token="tok",
                proxy_config={"upstream_ca_cert": str(nonexistent)},
                **cmd_env,
            )

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


class TestNestedProxyConfiguration:
    def test_upstream_proxy_environment_is_normalized(self, monkeypatch):
        from safeyolo.proxy import resolve_upstream_proxy

        monkeypatch.setenv("SAFEYOLO_UPSTREAM_PROXY", "http://127.0.0.1:8080")

        assert resolve_upstream_proxy({"upstream_proxy": ""}) == (
            "http://127.0.0.1:8080"
        )

    def test_persistent_upstream_proxy_is_supported(self, monkeypatch):
        from safeyolo.proxy import resolve_upstream_proxy

        monkeypatch.delenv("SAFEYOLO_UPSTREAM_PROXY", raising=False)

        assert resolve_upstream_proxy(
            {"upstream_proxy": "https://proxy.example"}
        ) == "https://proxy.example:443"

    @pytest.mark.parametrize(
        "value",
        [
            "socks5://127.0.0.1:1080",
            "http://user:secret@proxy.example:8080",
            "http://proxy.example:8080/path",
            "http://proxy.example:not-a-port",
        ],
    )
    def test_invalid_upstream_proxy_is_rejected(self, monkeypatch, value):
        from safeyolo.proxy import resolve_upstream_proxy

        monkeypatch.setenv("SAFEYOLO_UPSTREAM_PROXY", value)

        with pytest.raises(ValueError, match="upstream proxy|UPSTREAM_PROXY"):
            resolve_upstream_proxy({})

    def test_via_token_defaults_to_instance_identity(self, monkeypatch):
        from safeyolo.proxy import resolve_via_token

        monkeypatch.delenv("SAFEYOLO_VIA_TOKEN", raising=False)
        monkeypatch.setattr(
            "safeyolo.coord.identity.get_or_create_instance_id",
            lambda: "sy-inner-instance",
        )

        assert resolve_via_token({"via_token": ""}) == "sy-inner-instance"

    def test_via_token_environment_overrides_config(self, monkeypatch):
        from safeyolo.proxy import resolve_via_token

        monkeypatch.setenv("SAFEYOLO_VIA_TOKEN", "safeyolo-explicit-inner")

        assert resolve_via_token({"via_token": "persistent-token"}) == (
            "safeyolo-explicit-inner"
        )

    @pytest.mark.parametrize("value", ["two words", "bad,comma", "x" * 129])
    def test_invalid_via_token_is_rejected(self, monkeypatch, value):
        from safeyolo.proxy import resolve_via_token

        monkeypatch.setenv("SAFEYOLO_VIA_TOKEN", value)

        with pytest.raises(ValueError, match="via_token"):
            resolve_via_token({})


# ---------------------------------------------------------------------------
# TestCertDirPermissions
# ---------------------------------------------------------------------------

class TestCertDirPermissions:
    """Tests for cert directory permission hardening in _ensure_certs()."""

    def test_cert_dir_gets_700_on_generation(self, tmp_path):
        """After generating certs, cert_dir mode is 0o700."""
        from safeyolo.proxy import _ensure_certs

        cert_dir = tmp_path / "certs"

        # _ensure_certs launches mitmdump as a Popen and polls for the cert
        # file. We stub Popen so the test doesn't actually need mitmdump on
        # PATH — CI's cli-only environment doesn't install mitmproxy.
        class _FakePopen:
            def __init__(self, *args, **kwargs):
                cert_dir.mkdir(parents=True, exist_ok=True)
                (cert_dir / "mitmproxy-ca-cert.pem").write_text("cert")
                (cert_dir / "mitmproxy-ca.pem").write_text("ca-key")

            def poll(self):
                self.returncode = 0
                return 0

            def terminate(self):
                pass

            def wait(self, timeout=None):  # noqa: ARG002
                self.returncode = 0
                return 0

            def kill(self):
                pass

        with patch("safeyolo.proxy.subprocess.Popen", _FakePopen):
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

        with patch("safeyolo.proxy.os.kill", side_effect=ProcessLookupError, autospec=True,):
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

        with patch("safeyolo.proxy.os.kill", side_effect=mock_kill, autospec=True,), \
             patch("safeyolo.proxy.time.sleep", autospec=True,):
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

        with patch("safeyolo.proxy.os.kill", side_effect=ProcessLookupError, autospec=True,):
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

        with patch("safeyolo.proxy.os.kill", side_effect=mock_kill, autospec=True,), \
             patch("safeyolo.proxy.time.sleep", autospec=True,):
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
# TestProxyStartupSmoke
# ---------------------------------------------------------------------------

class TestProxyStartupSmoke:
    """Exercise the production addon chain in a real mitmdump process."""

    def test_real_full_addon_chain_reaches_running(self, tmp_config_dir, monkeypatch):
        """The command used by ``safeyolo start`` reaches its ready hook.

        Unit tests mock ``Popen`` for process-management edge cases.  This
        smoke test deliberately launches mitmdump so addon registration,
        option configuration, and startup lifecycle hooks are exercised
        together.  A temporary local port also verifies that the final addon,
        the admin API, completed its ``running`` hook.
        """
        from safeyolo import proxy

        # CA merging mutates the active Python environment and is unrelated
        # to addon startup. Certificate generation itself remains real.
        monkeypatch.setattr(proxy, "_merge_system_cas_into_certifi", lambda: None)

        try:
            with socket.socket() as port_reservation:
                port_reservation.bind(("127.0.0.1", 0))
                admin_port = port_reservation.getsockname()[1]
            with socket.socket() as port_reservation:
                port_reservation.bind(("127.0.0.1", 0))
                web_port = port_reservation.getsockname()[1]

            from safeyolo.config import save_config

            config = proxy.load_config()
            config["proxy"]["web_port"] = web_port
            save_config(config)

            proxy.start_proxy(admin_port=admin_port)

            pid_file = tmp_config_dir / "data" / "proxy.pid"
            assert pid_file.exists()
            proxy_pid = int(pid_file.read_text().strip())
            os.kill(proxy_pid, 0)
            assert proxy.wait_for_healthy(timeout=5, admin_port=admin_port)

            from safeyolo.api import AdminAPI

            token = (tmp_config_dir / "data" / "admin_token").read_text().strip()
            api = AdminAPI(base_url=f"http://127.0.0.1:{admin_port}", token=token)
            scoped = api.set_traffic_scope(agent="cody", test_id="FLOW-05")
            assert scoped["agent"] == "cody"
            assert scoped["test_id"] == "FLOW-05"
            stats = api.stats()
            assert stats["flow-pruner"]["configured_max"] == 5000
            assert stats["safeyolo-web-tailnet-share"]["state"] == "disabled"

            reconciled, web_tailnet = proxy.sync_web_tailnet(
                False,
                443,
                admin_port=admin_port,
            )
            assert reconciled is True
            assert web_tailnet["state"] == "disabled"

            import httpx

            admin_headers = {"Authorization": f"Bearer {token}"}
            runtime_response = httpx.get(
                f"http://127.0.0.1:{admin_port}/admin/runtime-identity",
                headers=admin_headers,
            )
            assert runtime_response.status_code == 200
            runtime_identity = runtime_response.json()
            assert runtime_identity["mode"] == "production"
            assert runtime_identity["process"]["pid"] == proxy_pid
            assert runtime_identity["process"]["started_at"]
            assert runtime_identity["process"]["start_token_state"] == "known"
            health_response = httpx.get(
                f"http://127.0.0.1:{admin_port}/health"
            )
            assert health_response.json() == {"status": "ok"}

            with httpx.Client(
                base_url=f"http://127.0.0.1:{web_port}",
                headers={"Authorization": f"Bearer {token}"},
            ) as web_client:
                web_response = web_client.get("/")
                assert web_response.status_code == 200
                assert "SafeYolo Traffic" in web_response.text
                scope_response = web_client.get("/safeyolo/scope")
                assert scope_response.status_code == 200
                assert scope_response.json()["scope"]["agent"] == "cody"
                xsrf = web_client.cookies.get("_mitmproxy_xsrf") or web_client.cookies.get("_xsrf")
                assert xsrf is not None
                update_response = web_client.put(
                    "/safeyolo/scope",
                    headers={"X-XSRFToken": xsrf},
                    json={"agent": "alice", "unattributed": False},
                )
                assert update_response.status_code == 200
                assert update_response.json()["scope"]["agent"] == "alice"

            startup_log = proxy.get_logs_dir() / "mitmproxy.log"
            startup_output = startup_log.read_text()
            assert "error in script" not in startup_output
            assert "Traceback (most recent call last)" not in startup_output
        finally:
            proxy.stop_proxy()


# ---------------------------------------------------------------------------
# TestStartProxy
# ---------------------------------------------------------------------------

class TestStartProxy:
    """Tests for start_proxy() — the orchestrator function."""

    def test_skips_when_already_running(self, tmp_path, monkeypatch):
        """start_proxy returns early if proxy is already running."""
        from safeyolo.proxy import start_proxy

        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))

        with patch("safeyolo.proxy.is_proxy_running", return_value=True, autospec=True,), \
             patch("safeyolo.proxy._find_addons_dir", autospec=True,) as mock_find:
            start_proxy()

        # _find_addons_dir should never be called if already running
        mock_find.assert_not_called()

    def test_raises_when_addons_dir_not_found(self, tmp_path, monkeypatch):
        """start_proxy raises RuntimeError when addons dir is not found."""
        from safeyolo.proxy import start_proxy

        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
        (tmp_path / "data").mkdir(exist_ok=True)

        with patch("safeyolo.proxy.is_proxy_running", return_value=False, autospec=True,), \
             patch("safeyolo.proxy._find_addons_dir", return_value=None, autospec=True,):
            with pytest.raises(RuntimeError, match="Cannot find the SafeYolo addons directory"):
                start_proxy()

    @pytest.mark.parametrize("dev", [False, True])
    def test_success_when_pid_file_appears(self, tmp_path, monkeypatch, dev):
        """start_proxy returns when addons/pid_writer.py writes the pid file.

        The CLI no longer writes the pid file itself -- it polls for the
        file to appear, signalling mitmproxy's `running` lifecycle event
        (= listener bound, addons loaded). Simulate the addon by writing
        the file from Popen's side_effect.
        """
        from safeyolo.proxy import start_proxy

        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
        monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(tmp_path / "logs"))
        monkeypatch.setenv(
            "SAFEYOLO_COORD_DATA_DIR", str(tmp_path / "data" / "coord")
        )
        monkeypatch.setenv("SAFEYOLO_UPSTREAM_PROXY", "http://127.0.0.1:8080")
        data_dir = tmp_path / "data"
        data_dir.mkdir(exist_ok=True)
        (tmp_path / "logs").mkdir(exist_ok=True)
        (tmp_path / "policy.toml").touch()

        package_dir = tmp_path / "checkout" / "cli" / "src" / "safeyolo"
        addons_dir = package_dir / "mitm_addons"
        addons_dir.mkdir(parents=True)
        (package_dir / "__init__.py").touch()
        (addons_dir / "__init__.py").touch()
        pdp_dir = tmp_path / "checkout" / "pdp"
        pdp_dir.mkdir(parents=True)
        (pdp_dir / "__init__.py").touch()
        pid_file = data_dir / "proxy.pid"
        launched = {}

        def _start_simulate_addon(*args, **kwargs):
            # Simulate addons/pid_writer.py's `running` hook writing the
            # pid file after mitmproxy binds the listener.
            pid_file.write_text("42\n")
            launched.update(kwargs)

        with patch("safeyolo.proxy.is_proxy_running", return_value=False, autospec=True,), \
             patch("safeyolo.proxy._find_addons_dir", return_value=addons_dir, autospec=True,), \
             patch("safeyolo.proxy._find_pdp_dir", return_value=pdp_dir if dev else None, autospec=True,), \
             patch("safeyolo.proxy._ensure_certs", return_value=tmp_path / "certs" / "ca.pem", autospec=True,), \
             patch("safeyolo.proxy._ensure_tokens", return_value=("admin", "agent"), autospec=True,), \
             patch("safeyolo.proxy._build_command", return_value=["traffic-master"], autospec=True,), \
             patch(
                 "safeyolo.proxy._profile_child_environment",
                 return_value={
                     "SAFEYOLO_PROFILE_PATH": "/tmp/profile.jsonl",
                     "SAFEYOLO_PROFILE_OPERATION": "proxy start",
                     "SAFEYOLO_PROFILE_PROCESS": "traffic-master",
                 },
             autospec=True,
             ), \
             patch("safeyolo.proxy.start_session", side_effect=_start_simulate_addon, autospec=True,):
            start_proxy(dev=dev)

        assert pid_file.exists()
        assert pid_file.read_text().strip() == "42"
        assert launched["env"]["SAFEYOLO_WEB_TAILNET_ENABLED"] == "0"
        assert launched["env"]["SAFEYOLO_WEB_TAILNET_PORT"] == "443"
        assert launched["env"]["SAFEYOLO_WEB_TAILNET_STATUS_FILE"] == str(
            data_dir / "web-tailnet-status.json"
        )
        assert json.loads(launched["env"]["SAFEYOLO_INITIAL_MODES"]) == []
        assert launched["env"]["SAFEYOLO_UPSTREAM_PROXY"] == (
            "http://127.0.0.1:8080"
        )
        assert launched["env"]["SAFEYOLO_VIA_TOKEN"].startswith("sy-")
        assert launched["env"]["SAFEYOLO_PROFILE_PROCESS"] == "traffic-master"
        assert launched["env"]["PYTHONPATH"].split(os.pathsep)[0] == str(
            package_dir.parent
        )
        assert launched["env"]["SAFEYOLO_DEV_MODE"] == ("1" if dev else "0")
        if dev:
            assert json.loads(launched["env"]["SAFEYOLO_DEV_SOURCE_ROOTS"]) == {
                "pdp": str(pdp_dir.resolve()),
                "safeyolo": str(package_dir.resolve()),
            }
        else:
            assert "SAFEYOLO_DEV_SOURCE_ROOTS" not in launched["env"]

    def test_raises_when_mitmdump_dies_during_startup(self, tmp_path, monkeypatch):
        """start_proxy surfaces exit code + log tail when mitmdump dies early."""
        from safeyolo.proxy import start_proxy

        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
        monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(tmp_path / "logs"))
        data_dir = tmp_path / "data"
        data_dir.mkdir(exist_ok=True)
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir(exist_ok=True)
        (tmp_path / "policy.toml").touch()
        (logs_dir / "mitmproxy.log").write_text(
            "Loading script /app/addons/file_logging.py\n"
            "ModuleNotFoundError: No module named 'yaml'\n"
        )

        package_dir = tmp_path / "checkout" / "cli" / "src" / "safeyolo"
        addons_dir = package_dir / "mitm_addons"
        addons_dir.mkdir(parents=True)
        (package_dir / "__init__.py").touch()
        (addons_dir / "__init__.py").touch()

        def _write_structured_failure(*args, **kwargs):
            (logs_dir / "safeyolo.jsonl").write_text(json.dumps({
                "event": "ops.proxy_start_failed",
                "summary": "Traffic master startup failed: address already in use",
            }) + "\n")

        with patch("safeyolo.proxy.is_proxy_running", return_value=False, autospec=True,), \
             patch("safeyolo.proxy._find_addons_dir", return_value=addons_dir, autospec=True,), \
             patch("safeyolo.proxy._find_pdp_dir", return_value=None, autospec=True,), \
             patch("safeyolo.proxy._ensure_certs", return_value=tmp_path / "certs" / "ca.pem", autospec=True,), \
             patch("safeyolo.proxy._ensure_tokens", return_value=("admin", "agent"), autospec=True,), \
             patch("safeyolo.proxy._build_command", return_value=["traffic-master"], autospec=True,), \
             patch("safeyolo.proxy.start_session", side_effect=_write_structured_failure, autospec=True,), \
             patch("safeyolo.proxy.session_process_alive", return_value=False, autospec=True,), \
             patch("safeyolo.proxy.stop_session", autospec=True,) as stop_session:
            with pytest.raises(RuntimeError, match="address already in use"):
                start_proxy()
        stop_session.assert_called_once_with()


def test_pid_writer_defers_until_traffic_master_signals_ready(tmp_path, monkeypatch):
    from safeyolo.mitm_addons.pid_writer import PidWriter

    pid_file = tmp_path / "proxy.pid"
    monkeypatch.setenv("SAFEYOLO_PROXY_PID_FILE", str(pid_file))
    monkeypatch.setenv("SAFEYOLO_DEFER_PROXY_READY", "1")
    writer = PidWriter()

    writer.running()
    assert not pid_file.exists()

    writer.signal_ready()
    assert pid_file.read_text().strip().isdigit()


def test_missing_structured_startup_failure_is_reported_by_caller_context(tmp_path):
    from safeyolo.proxy import _read_startup_failure

    assert _read_startup_failure(tmp_path / "missing.jsonl", 0) is None


def test_startup_diagnostics_capture_state_before_cleanup(tmp_path, monkeypatch):
    from safeyolo.proxy import _startup_diagnostics

    event_log = tmp_path / "safeyolo.jsonl"
    event_log.write_text('old\n{"event":"ops.proxy_start_failed"}\n')
    mitmproxy_log = tmp_path / "mitmproxy.log"
    mitmproxy_log.write_text("addon load stalled\n")
    profile = tmp_path / "startup-profile.jsonl"
    profile.write_text('{"name":"traffic-master: listeners"}\n')
    monkeypatch.setenv("SAFEYOLO_PROFILE_PATH", str(profile))
    monkeypatch.setattr("safeyolo.proxy.capture_session", lambda: "pane traceback")
    monkeypatch.setattr("safeyolo.proxy.session_process_alive", lambda: True)

    diagnostics = _startup_diagnostics(
        event_log=event_log,
        event_offset=4,
        logs_dir=tmp_path,
        pid_file=tmp_path / "proxy.pid",
    )

    assert "traffic session alive: True" in diagnostics
    assert "readiness marker exists: False" in diagnostics
    assert "ops.proxy_start_failed" in diagnostics
    assert "addon load stalled" in diagnostics
    assert "pane traceback" in diagnostics
    assert "traffic-master: listeners" in diagnostics


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

        mock_resp = _HealthResponse()

        with patch("safeyolo.proxy.is_proxy_running", return_value=True, autospec=True,), \
             patch("urllib.request.urlopen", return_value=mock_resp, autospec=True,):
            result = wait_for_healthy(timeout=1, admin_port=9090)

        assert result is True

    def test_returns_false_on_timeout(self, tmp_path, monkeypatch):
        """Returns False when health endpoint never responds within timeout."""

        from safeyolo.proxy import wait_for_healthy

        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
        data_dir = tmp_path / "data"
        data_dir.mkdir(exist_ok=True)

        with patch("safeyolo.proxy.is_proxy_running", return_value=True, autospec=True,), \
             patch("urllib.request.urlopen", side_effect=ConnectionError, autospec=True,), \
             patch("safeyolo.proxy.time.sleep", autospec=True,):
            result = wait_for_healthy(timeout=2, admin_port=9090)

        assert result is False

    def test_reads_token_from_file(self, tmp_path, monkeypatch):
        """Health check uses Bearer token from admin_token file."""
        from safeyolo.proxy import wait_for_healthy

        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
        data_dir = tmp_path / "data"
        data_dir.mkdir(exist_ok=True)
        (data_dir / "admin_token").write_text("secret-tok-123")

        mock_resp = _HealthResponse()

        captured_request = None

        def capture_urlopen(req, **kwargs):
            nonlocal captured_request
            captured_request = req
            return mock_resp

        with patch("safeyolo.proxy.is_proxy_running", return_value=True, autospec=True,), \
             patch("urllib.request.urlopen", side_effect=capture_urlopen, autospec=True,):
            wait_for_healthy(timeout=1, admin_port=9090)

        assert captured_request is not None
        assert captured_request.get_header("Authorization") == "Bearer secret-tok-123"

    def test_returns_false_immediately_when_proxy_dies(self, tmp_path, monkeypatch):
        from safeyolo.proxy import wait_for_healthy

        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
        (tmp_path / "data").mkdir()

        with patch("safeyolo.proxy.is_proxy_running", return_value=False, autospec=True,), \
             patch("urllib.request.urlopen", autospec=True,) as urlopen, \
             patch("safeyolo.proxy.time.sleep", autospec=True,) as sleep:
            result = wait_for_healthy(timeout=30, admin_port=9090)

        assert result is False
        urlopen.assert_not_called()
        sleep.assert_not_called()
