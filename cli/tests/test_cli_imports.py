"""Regression tests for the CLI startup import boundary."""

import subprocess
import sys

import pytest


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


@pytest.mark.parametrize(
    "modules",
    [
        ("safeyolo.agent_launchers",),
        ("safeyolo.agent_lifecycle",),
        ("safeyolo.agent_launchers", "safeyolo.agent_lifecycle"),
        ("safeyolo.agent_lifecycle", "safeyolo.agent_launchers"),
    ],
)
def test_agent_runtime_imports_do_not_load_agent_commands(modules: tuple[str, ...]) -> None:
    """Lower-level agent operations stay usable before the CLI command module."""
    script = (
        "from contextlib import nullcontext\n"
        "import importlib\n"
        "import sys\n"
        "from pathlib import Path\n"
        f"modules = {modules!r}\n"
        "for module in modules:\n"
        "    importlib.import_module(module)\n"
        "launchers = sys.modules.get('safeyolo.agent_launchers')\n"
        "if launchers is not None:\n"
        "    launchers.get_agents_dir = lambda: Path('/not-a-safeyolo-agent-dir')\n"
        "    assert launchers.read_launch('probe') is None\n"
        "    launchers.validate_script(launchers.Launcher('interactive', 'test'))\n"
        "lifecycle = sys.modules.get('safeyolo.agent_lifecycle')\n"
        "if lifecycle is not None:\n"
        "    lifecycle.load_all_agents = lambda: {}\n"
        "    assert lifecycle.list_agent_runtimes() == []\n"
        "    lifecycle._agent_host_setup_lock = lambda name: nullcontext()\n"
        "    lifecycle._stop_agent_by_name = lambda *args, **kwargs: None\n"
        "    assert lifecycle.stop_agent_by_name('probe') is None\n"
        "assert 'safeyolo.commands.agent' not in sys.modules\n"
        "assert 'safeyolo.commands.mount' not in sys.modules\n"
    )

    subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
    )
