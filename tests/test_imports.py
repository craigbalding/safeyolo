"""
Test that all addons can be imported in standalone mode.

This catches missing try/except ImportError fallbacks for relative imports.
When mitmproxy loads addons via `-s addons/foo.py`, they run standalone
(not as a package), so `from .utils import X` fails without a fallback.
"""

import subprocess
import sys
from pathlib import Path

ADDON_MODULES = [
    "admin_api",
    "admin_shield",
    "base",
    "budget_tracker",
    "circuit_breaker",
    "credential_guard",
    "metrics",
    "network_guard",
    "pattern_scanner",
    "policy_engine",
    "policy_loader",
    "request_id",
    "request_logger",
    "sensor_utils",
    "service_discovery",
    "sse_streaming",
    "utils",
]

# Names that must be importable in each module (used at runtime)
# Format: module_name -> [required_names]
REQUIRED_NAMES = {
    "circuit_breaker": ["SecurityAddon", "atomic_write_json", "BackgroundWorker", "make_block_response"],
    "pattern_scanner": ["SecurityAddon", "make_block_response"],
    "credential_guard": ["SecurityAddon", "get_policy_client", "looks_like_secret", "hmac_fingerprint"],
    "network_guard": ["SecurityAddon", "get_client_ip", "get_policy_client"],
    "base": ["make_block_response", "write_event", "get_option_safe", "get_policy_client"],
    "policy_engine": ["write_event", "GCRABudgetTracker", "PolicyLoader"],
    "budget_tracker": ["atomic_write_json", "BackgroundWorker"],
    "request_logger": ["write_audit_event", "BackgroundWorker"],
    "admin_api": ["write_event", "get_admin_client"],
    "policy_loader": ["write_event"],
    "sensor_utils": ["build_http_event_from_flow"],
}


class TestStandaloneImports:
    """Test addons import without package context."""

    def test_all_addons_import_standalone(self):
        """Each addon must be importable when not in a package.

        Simulates: python -c "import sys; sys.path.insert(0, 'addons'); import foo"

        This catches missing fallback imports like:
            try:
                from .utils import X
            except ImportError:
                from utils import X  # <-- This fallback must exist
        """
        addons_dir = Path(__file__).parent.parent / "addons"
        assert addons_dir.exists(), f"Addons dir not found: {addons_dir}"

        failures = []

        for module in ADDON_MODULES:
            # Import in subprocess with addons dir in path (standalone mode)
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    f"import sys; sys.path.insert(0, '{addons_dir}'); import {module}",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                # Extract the key error line
                stderr_lines = result.stderr.strip().split("\n")
                error_line = stderr_lines[-1] if stderr_lines else "Unknown error"
                failures.append(f"{module}: {error_line}")

        assert not failures, (
            "Addons failed standalone import (missing fallback imports?):\n"
            + "\n".join(f"  - {f}" for f in failures)
        )

    def test_required_names_available_standalone(self):
        """Verify required names are importable in standalone mode.

        Catches bugs where fallback import exists but is missing a name:
            try:
                from .utils import X, Y, Z
            except ImportError:
                from utils import X, Y  # Z is missing!
        """
        addons_dir = Path(__file__).parent.parent / "addons"
        failures = []

        for module, required_names in REQUIRED_NAMES.items():
            # Check each required name exists after standalone import
            missing_expr = f"[n for n in {required_names!r} if not hasattr(m, n)]"

            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    f"""
import sys
sys.path.insert(0, '{addons_dir}')
import {module} as m
missing = {missing_expr}
if missing:
    print(','.join(missing))
    exit(1)
""",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                missing = result.stdout.strip() or result.stderr.strip().split("\n")[-1]
                failures.append(f"{module}: missing {missing}")

        assert not failures, (
            "Addons missing required names in standalone mode:\n"
            + "\n".join(f"  - {f}" for f in failures)
        )

    def test_addon_module_list_complete(self):
        """Ensure ADDON_MODULES covers all .py files in addons/."""
        addons_dir = Path(__file__).parent.parent / "addons"
        actual_modules = {
            p.stem for p in addons_dir.glob("*.py") if not p.name.startswith("_")
        }
        expected = set(ADDON_MODULES)

        missing = actual_modules - expected
        assert not missing, f"ADDON_MODULES missing: {missing}"

        extra = expected - actual_modules
        assert not extra, f"ADDON_MODULES has non-existent: {extra}"

    def test_get_policy_engine_deleted(self):
        """Verify legacy get_policy_engine() has been deleted.

        After PDP migration, PolicyEngine is created only by PDPCore (via
        LocalPolicyClient). The global singleton get_policy_engine() is dead code.
        """
        addons_dir = Path(__file__).parent.parent / "addons"
        source = (addons_dir / "policy_engine.py").read_text()

        # Should not define get_policy_engine function
        assert "def get_policy_engine" not in source, (
            "get_policy_engine() should be deleted. "
            "Use get_policy_client() instead."
        )

        # Should not define init_policy_engine function
        assert "def init_policy_engine" not in source, (
            "init_policy_engine() should be deleted. "
            "PolicyClientConfigurator configures the client."
        )

        # Should not have the _policy_engine global singleton
        assert "_policy_engine: PolicyEngine" not in source, (
            "_policy_engine global should be deleted. "
            "PolicyClient registry owns the singleton."
        )

    def test_no_addon_imports_get_policy_engine(self):
        """Ensure no addon references the legacy get_policy_engine function."""
        addons_dir = Path(__file__).parent.parent / "addons"
        violations = []

        for module in ADDON_MODULES:
            source = (addons_dir / f"{module}.py").read_text()
            if "get_policy_engine" in source:
                violations.append(module)

        assert not violations, (
            f"Addons referencing legacy get_policy_engine: {violations}. "
            f"Use get_policy_client() or get_admin_client() instead."
        )

    def test_no_addon_imports_pdp_core(self):
        """Ensure no addon imports pdp.core directly.

        Addons should use PolicyClient (enforcement) or PDPAdminClient (management).
        Only client implementations import pdp.core.
        """
        addons_dir = Path(__file__).parent.parent / "addons"
        violations = []

        for module in ADDON_MODULES:
            source = (addons_dir / f"{module}.py").read_text()
            if "from pdp.core" in source or "import pdp.core" in source:
                violations.append(module)

        assert not violations, (
            f"Addons importing pdp.core directly (use PolicyClient or PDPAdminClient): {violations}"
        )


class TestAddonContracts:
    """Contract tests ensuring addons agree on shared conventions."""

    def test_no_addon_uses_policy_engine_metadata(self):
        """Verify no addon accesses flow.metadata["policy_engine"].

        Addons should use get_policy_client() instead of the legacy
        flow.metadata["policy_engine"] shim. This test ensures the shim
        was fully removed.
        """
        addons_dir = Path(__file__).parent.parent / "addons"
        violations = []

        for module in ADDON_MODULES:
            source = (addons_dir / f"{module}.py").read_text()
            # Check for any access to policy_engine in metadata
            if 'metadata["policy_engine"]' in source or "metadata['policy_engine']" in source:
                violations.append(f"{module}: sets metadata['policy_engine']")
            if 'metadata.get("policy_engine")' in source or "metadata.get('policy_engine')" in source:
                violations.append(f"{module}: reads metadata.get('policy_engine')")

        assert not violations, (
            "Addons should use get_policy_client() not flow.metadata:\n"
            + "\n".join(f"  - {v}" for v in violations)
        )

    def test_no_addon_accesses_pdp_internals(self):
        """Verify no addon accesses ._pdp or ._engine internals.

        Addons should use the public PolicyClient interface, not reach into
        PDPCore or PolicyEngine internals. This ensures proper encapsulation.
        """
        import re

        addons_dir = Path(__file__).parent.parent / "addons"
        violations = []

        # Patterns that indicate internal access (excluding definitions/docstrings)
        internal_patterns = [
            (r'\._pdp\b', '._pdp'),
            (r'\._engine\b', '._engine'),
            (r'client\._pdp', 'client._pdp'),
        ]

        for module in ADDON_MODULES:
            source = (addons_dir / f"{module}.py").read_text()
            for pattern, desc in internal_patterns:
                if re.search(pattern, source):
                    violations.append(f"{module}: accesses {desc}")

        assert not violations, (
            "Addons should not access PDPCore internals:\n"
            + "\n".join(f"  - {v}" for v in violations)
        )


class TestPolicyClientRegistry:
    """Test PolicyClient singleton registry behavior."""

    def test_get_policy_client_fails_before_configure(self):
        """get_policy_client() must fail if configure_policy_client() not called.

        This is the fail-closed behavior that prevents silent use of an
        unconfigured/empty policy.
        """
        import pytest

        from pdp import get_policy_client, reset_policy_client

        reset_policy_client()  # Ensure clean state

        with pytest.raises(RuntimeError) as exc_info:
            get_policy_client()

        assert "not configured" in str(exc_info.value).lower()

    def test_configure_then_get_policy_client(self):
        """configure_policy_client() + get_policy_client() returns valid client."""
        from pdp import (
            PolicyClient,
            PolicyClientConfig,
            configure_policy_client,
            get_policy_client,
            is_policy_client_configured,
            reset_policy_client,
        )

        reset_policy_client()  # Ensure clean state

        # Before: not configured
        assert not is_policy_client_configured()

        # Configure with local mode (no paths = empty policy)
        config = PolicyClientConfig(mode="local")
        configure_policy_client(config)

        # After: configured
        assert is_policy_client_configured()
        client = get_policy_client()
        assert isinstance(client, PolicyClient)

        # Cleanup
        reset_policy_client()

    def test_configure_with_baseline_path(self, tmp_path):
        """configure_policy_client() with baseline_path loads the policy."""
        from pdp import (
            LocalPolicyClient,
            PolicyClientConfig,
            configure_policy_client,
            get_policy_client,
            reset_policy_client,
        )

        reset_policy_client()

        # Create a minimal baseline policy
        baseline_path = tmp_path / "baseline.yaml"
        baseline_path.write_text("""
metadata:
  version: "1.0"
permissions:
  - action: credential:use
    resource: "api.openai.com/*"
    effect: allow
    condition:
      credential: ["openai:*"]
""")

        config = PolicyClientConfig(
            mode="local",
            baseline_path=baseline_path,
        )
        configure_policy_client(config)

        client = get_policy_client()
        assert isinstance(client, LocalPolicyClient)

        # Verify policy was loaded
        assert client._pdp._engine.get_baseline() is not None

        reset_policy_client()

    def test_single_policy_engine_instance(self, tmp_path):
        """Verify only one PolicyEngine exists (via PDPCore), not two.

        This is the regression test for the dual-engine bug where:
        - PolicyEngineAddon created its own PolicyEngine
        - LocalPolicyClient/PDPCore created another PolicyEngine
        """
        from pdp import (
            LocalPolicyClient,
            PolicyClientConfig,
            configure_policy_client,
            get_policy_client,
            reset_policy_client,
        )

        reset_policy_client()

        baseline_path = tmp_path / "baseline.yaml"
        baseline_path.write_text("""
metadata:
  version: "1.0"
clients:
  agent:claude-dev:
    bypass: [credential-guard]
""")

        config = PolicyClientConfig(
            mode="local",
            baseline_path=baseline_path,
        )
        configure_policy_client(config)

        client = get_policy_client()
        assert isinstance(client, LocalPolicyClient)

        # The is_addon_enabled check should use the SAME engine that loaded
        # the baseline, not an empty one
        result = client.is_addon_enabled(
            "credential-guard",
            client_id="agent:claude-dev",
        )
        assert result is False, (
            "is_addon_enabled should return False for bypassed addon. "
            "If True, there may be multiple PolicyEngine instances."
        )

        reset_policy_client()
