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
    "base": ["make_block_response", "write_event", "get_option_safe", "get_policy_engine"],
    "policy_engine": ["write_event", "GCRABudgetTracker", "PolicyLoader"],
    "budget_tracker": ["atomic_write_json", "BackgroundWorker"],
    "request_logger": ["write_audit_event", "BackgroundWorker"],
    "admin_api": ["write_event", "get_policy_engine"],
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
