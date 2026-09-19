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


def test_native_cli_registration_does_not_import_python_proxy_runtime() -> None:
    """Native CLI registration must not require the retained Python proxy."""
    script = r'''
import importlib.abc
import sys


class BlockPythonProxyRuntime(importlib.abc.MetaPathFinder):
    blocked = ("mitmproxy", "safeyolo.mitm_addons", "safeyolo.traffic_master")

    def find_spec(self, fullname, path=None, target=None):
        if any(fullname == name or fullname.startswith(name + ".") for name in self.blocked):
            raise AssertionError(f"native CLI imported retained Python runtime: {fullname}")
        return None


sys.meta_path.insert(0, BlockPythonProxyRuntime())
import safeyolo.cli  # noqa: E402
from safeyolo.proxy import selected_backend  # noqa: E402

assert selected_backend({"proxy": {}}) == "rust"
assert not any(
    module == "mitmproxy"
    or module.startswith("mitmproxy.")
    or module == "safeyolo.mitm_addons"
    or module.startswith("safeyolo.mitm_addons.")
    or module == "safeyolo.traffic_master"
    or module.startswith("safeyolo.traffic_master.")
    for module in sys.modules
)
print("native registration is Python-runtime clean")
'''

    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
    )

    assert completed.stdout.strip() == "native registration is Python-runtime clean"
