"""Platform guards for blackbox tests.

Blackbox tests drive real infrastructure — sinkhole, proxy, and (on Linux)
a gVisor-sandboxed agent. When the underlying platform or its dependencies
aren't available, collecting these tests causes indefinite hangs or
multi-GB runaway fixtures. Deselect them at collection time instead.

Collection rules:
- ``isolation/`` is collected only when ``SAFEYOLO_BLACKBOX_ISOLATION=1``
  is set in the environment. ``run-tests.sh`` sets this when it shells
  into the dedicated blackbox test VM (``bbtest``); any other context
  — including a user's own Claude Code / BYOA agent session running
  inside a SafeYolo sandbox — is NOT a valid place to run these. They
  probe VM-only properties (SOCK_RAW, /dev/mem, setuid, etc.) and make
  assertions tied to the ``bbtest`` image specifically.
- ``host/`` is collected on Linux only if ``runsc`` is on PATH, and on
  macOS unconditionally (the Linux harness shells out to ``runsc`` to
  boot the test agent; without it the harness hangs booting the VM).
- Anything other than linux/darwin is deselected entirely.

The runsc check emits a pytest warning rather than a silent skip because
``runsc`` is a required SafeYolo runtime dependency on Linux, not just a
test-time nicety — a missing runsc means the user's local SafeYolo install
is also broken.
"""

import os
import shutil
import sys
import warnings
from pathlib import Path

collect_ignore_glob: list[str] = []


def _in_blackbox_test_vm() -> bool:
    """True only when pytest was launched by the blackbox runner.

    Matching on a mere SafeYolo-guest marker (e.g. /safeyolo/guest-init)
    would be wrong — any BYOA agent, including the user's coding-agent
    session, has that. ``run-tests.sh`` exports this env var explicitly
    when it shells into the dedicated ``bbtest`` VM.
    """
    return os.environ.get("SAFEYOLO_BLACKBOX_ISOLATION") == "1"


def _runsc_available() -> bool:
    """True when the gVisor runsc binary is installed."""
    if shutil.which("runsc"):
        return True
    return any(
        Path(p).is_file() for p in ("/usr/local/bin/runsc", "/usr/bin/runsc")
    )


# --- isolation/ : only inside the dedicated blackbox test VM ---------------
if not _in_blackbox_test_vm():
    collect_ignore_glob.append("isolation/*")


# --- host/ : platform- and dependency-gated --------------------------------
# Only relevant on the host itself. When run inside the bbtest VM (isolation
# pytest invocation), host/* is already deselected by path (the tests don't
# exist inside the VM's view of the repo anyway) and runsc obviously won't
# be installed inside the sandbox — so the warning is a false alarm there.
if sys.platform == "linux" and not _in_blackbox_test_vm():
    if not _runsc_available():
        warnings.warn(
            "runsc (gVisor) not found — skipping blackbox host tests.\n"
            "runsc is a REQUIRED SafeYolo runtime dependency on Linux; "
            "the agent sandbox will not function without it.\n"
            "Install gVisor:\n"
            "  curl -fsSL https://gvisor.dev/archive.key | "
            "sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg\n"
            "  echo \"deb [arch=$(dpkg --print-architecture) "
            "signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] "
            "https://storage.googleapis.com/gvisor/releases release main\" | "
            "sudo tee /etc/apt/sources.list.d/gvisor.list\n"
            "  sudo apt update && sudo apt install -y runsc",
            stacklevel=1,
        )
        collect_ignore_glob.append("host/*")
elif sys.platform == "darwin":
    # macOS uses Virtualization.framework, available on all supported macOS
    # versions; no pre-collection dependency check needed.
    pass
else:
    # Windows / BSD / etc. — SafeYolo does not ship a harness for these.
    collect_ignore_glob.append("host/*")
    collect_ignore_glob.append("isolation/*")
