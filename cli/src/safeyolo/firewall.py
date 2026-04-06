"""macOS pf firewall management for SafeYolo VM network isolation.

Manages a pf anchor (com.safeyolo) that restricts VM egress to only
the mitmproxy proxy port. All other outbound traffic from VMs is dropped.
"""

import logging
import re
import subprocess
from pathlib import Path

log = logging.getLogger("safeyolo.firewall")

ANCHOR_NAME = "com.safeyolo"
ANCHOR_FILE = Path("/etc/pf.anchors") / ANCHOR_NAME


def _detect_bridge_interface() -> str:
    """Detect the vmnet bridge interface used by Apple Virtualization.framework.

    Apple Vz creates bridge100 (or similar) dynamically. We look for
    bridge interfaces with a vmnet member, or fall back to bridge100.
    """
    try:
        result = subprocess.run(
            ["ifconfig", "-a"],
            capture_output=True, text=True, timeout=5,
        )
        # Look for bridge interfaces (bridge100, bridge101, etc.)
        bridges = re.findall(r"^(bridge\d+):", result.stdout, re.MULTILINE)
        if bridges:
            return bridges[0]
    except (subprocess.SubprocessError, OSError):
        pass

    return "bridge100"


def generate_rules(proxy_port: int = 8080, admin_port: int = 9090) -> str:
    """Generate pf anchor rules for SafeYolo VM isolation.

    Rules:
    1. Allow DHCP (guest needs to get an IP)
    2. Allow DNS (guest resolves via host gateway)
    3. Allow traffic to mitmproxy port (the intended egress path)
    4. Block traffic to admin API port (admin_shield addon is defense-in-depth)
    5. Block all other egress from VMs
    """
    bridge = _detect_bridge_interface()

    return f"""\
# SafeYolo VM egress control — anchor {ANCHOR_NAME}
# Bridge interface: {bridge}

# Allow DHCP (UDP 67/68) for VM network setup
pass in quick on {bridge} proto udp from any to any port {{ 67 68 }}

# Allow DNS to host gateway (name resolution goes through proxy)
pass in quick on {bridge} proto {{ tcp udp }} from any to any port 53

# Allow VMs to reach mitmproxy proxy port
pass in quick on {bridge} proto tcp from any to any port {proxy_port}

# Block VMs from reaching admin API
block in quick on {bridge} proto tcp from any to any port {admin_port}

# Block all other VM egress
block in on {bridge} all
"""


def load_rules(proxy_port: int = 8080, admin_port: int = 9090) -> None:
    """Write and load pf anchor rules. Requires sudo."""
    rules = generate_rules(proxy_port=proxy_port, admin_port=admin_port)

    # Write anchor file
    anchor_file = ANCHOR_FILE
    _sudo_write_file(anchor_file, rules)

    # Ensure anchor reference exists in /etc/pf.conf
    _ensure_anchor_in_pf_conf()

    # Load the anchor rules
    _sudo_run(["pfctl", "-a", ANCHOR_NAME, "-f", str(anchor_file)])

    # Enable pf if not already enabled
    result = _sudo_run(["pfctl", "-s", "info"], capture=True)
    if "Status: Disabled" in (result.stdout or ""):
        _sudo_run(["pfctl", "-e"])

    log.info("pf rules loaded for anchor %s", ANCHOR_NAME)


def unload_rules() -> None:
    """Flush pf anchor rules."""
    _sudo_run(["pfctl", "-a", ANCHOR_NAME, "-F", "all"], check=False)
    log.info("pf rules unloaded for anchor %s", ANCHOR_NAME)


def is_loaded() -> bool:
    """Check if pf anchor rules are active."""
    result = _sudo_run(
        ["pfctl", "-a", ANCHOR_NAME, "-s", "rules"],
        capture=True, check=False,
    )
    return bool(result.stdout and result.stdout.strip())


def validate(proxy_port: int = 8080) -> bool:
    """Validate that pf rules are active and contain the proxy port rule."""
    if not is_loaded():
        return False

    result = _sudo_run(
        ["pfctl", "-a", ANCHOR_NAME, "-s", "rules"],
        capture=True, check=False,
    )
    return str(proxy_port) in (result.stdout or "")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sudo_run(
    cmd: list[str],
    capture: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess:
    """Run a command with sudo."""
    full_cmd = ["sudo"] + cmd
    return subprocess.run(
        full_cmd,
        capture_output=capture,
        text=True,
        check=check,
    )


def _sudo_write_file(path: Path, content: str) -> None:
    """Write a file as root via sudo tee."""
    path.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["sudo", "tee", str(path)],
        input=content,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to write {path}: {proc.stderr}")


def _ensure_anchor_in_pf_conf() -> None:
    """Ensure /etc/pf.conf references our anchor."""
    pf_conf = Path("/etc/pf.conf")
    anchor_line = f'anchor "{ANCHOR_NAME}"'
    load_line = f'load anchor "{ANCHOR_NAME}" from "{ANCHOR_FILE}"'

    try:
        content = pf_conf.read_text()
    except PermissionError:
        result = _sudo_run(["cat", "/etc/pf.conf"], capture=True)
        content = result.stdout or ""

    if anchor_line in content:
        return  # Already referenced

    # Append anchor reference
    addition = f"\n# SafeYolo VM isolation\n{anchor_line}\n{load_line}\n"
    proc = subprocess.run(
        ["sudo", "tee", "-a", str(pf_conf)],
        input=addition,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to update /etc/pf.conf: {proc.stderr}")

    log.info("Added SafeYolo anchor to /etc/pf.conf")
