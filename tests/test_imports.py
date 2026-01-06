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

    def test_no_addon_imports_get_policy_engine(self):
        """Ensure no addon imports the legacy get_policy_engine function.

        After PDP migration, addons should use PolicyClient or PDPAdminClient.

        TODO: Once confirmed safe, delete get_policy_engine() from policy_engine.py
        entirely. PDPCore creates its own PolicyEngine instance, so the global
        singleton is dead code. Then this test can check that the symbol doesn't
        exist at all.
        """
        addons_dir = Path(__file__).parent.parent / "addons"
        # policy_engine.py defines get_policy_engine (but nothing should call it)
        excluded = {"policy_engine"}
        violations = []

        for module in ADDON_MODULES:
            if module in excluded:
                continue
            source = (addons_dir / f"{module}.py").read_text()
            if "get_policy_engine" in source:
                violations.append(module)

        assert not violations, (
            f"Addons importing legacy get_policy_engine: {violations}. "
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

    def test_policy_metadata_key_consistent(self):
        """Verify producer and consumers use same metadata key for policy.

        policy_engine.py sets flow.metadata["X"], consumers read flow.metadata.get("X").
        If keys don't match, consumers silently get None - a hard-to-find bug.
        """
        import re

        addons_dir = Path(__file__).parent.parent / "addons"

        # Producer: policy_engine.py sets the key
        producer_source = (addons_dir / "policy_engine.py").read_text()
        producer_match = re.search(r'flow\.metadata\["(\w+)"\]\s*=\s*self\.engine', producer_source)
        assert producer_match, "Could not find policy_engine setting flow.metadata"
        producer_key = producer_match.group(1)

        # Consumers: addons that read the key
        consumers = ["credential_guard.py", "sse_streaming.py"]
        for consumer_file in consumers:
            consumer_source = (addons_dir / consumer_file).read_text()
            consumer_match = re.search(r'flow\.metadata\.get\(["\'](\w+)["\']\)', consumer_source)
            if consumer_match:
                consumer_key = consumer_match.group(1)
                assert consumer_key == producer_key, (
                    f"{consumer_file} uses key '{consumer_key}' but "
                    f"policy_engine.py sets '{producer_key}'"
                )
