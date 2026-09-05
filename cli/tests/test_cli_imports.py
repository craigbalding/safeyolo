"""Regression tests for the CLI startup import boundary."""

import subprocess
import sys


def test_cli_import_defers_command_only_dependencies() -> None:
    """Registering commands must not initialize their runtime dependencies."""
    command_only_modules = (
        "asyncio",
        "httpx",
        "safeyolo.api",
        "safeyolo.coord.api",
        "safeyolo.coord.nats_client",
        "safeyolo.core.audit_schema",
        "safeyolo.core.service_loader",
        "safeyolo.events",
    )
    script = (
        "import sys\n"
        "import safeyolo.cli\n"
        f"modules = {command_only_modules!r}\n"
        "print('\\n'.join(name for name in modules if name in sys.modules))\n"
    )

    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
    )

    assert completed.stdout.strip() == ""
