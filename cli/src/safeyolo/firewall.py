"""macOS pf firewall and feth interface management for SafeYolo VM isolation.

Creates feth (fake Ethernet) interface pairs for VM networking. Unlike vmnet
bridge interfaces, feth interfaces are regular network interfaces where pf
rules work. Each VM gets its own feth pair and /24 subnet.

Subnet allocation: agent index → 192.168.(65+index).0/24
"""

import logging
import subprocess
from pathlib import Path

log = logging.getLogger("safeyolo.firewall")

ANCHOR_NAME = "com.safeyolo"
ANCHOR_FILE = Path("/etc/pf.anchors") / ANCHOR_NAME

# Base subnet: 192.168.65.0/24 for first VM, .66 for second, etc.
SUBNET_BASE = 65


def allocate_subnet(agent_index: int) -> dict:
    """Allocate a subnet for a VM.

    Returns dict with host_ip, guest_ip, subnet, feth_vm, feth_host.
    """
    third_octet = SUBNET_BASE + agent_index
    feth_idx = agent_index * 2
    return {
        "host_ip": f"192.168.{third_octet}.1",
        "guest_ip": f"192.168.{third_octet}.2",
        "subnet": f"192.168.{third_octet}.0/24",
        "feth_vm": f"feth{feth_idx}",
        "feth_host": f"feth{feth_idx + 1}",
        "third_octet": third_octet,
    }


def setup_feth(agent_index: int) -> dict:
    """Create a feth pair and configure the host side. Requires sudo.

    Returns the subnet allocation dict.
    """
    alloc = allocate_subnet(agent_index)
    feth_vm = alloc["feth_vm"]
    feth_host = alloc["feth_host"]
    host_ip = alloc["host_ip"]

    # Destroy stale feth interfaces if they exist from a previous run
    _sudo_run(["ifconfig", feth_vm, "destroy"], check=False, capture=True)
    _sudo_run(["ifconfig", feth_host, "destroy"], check=False, capture=True)

    # Create feth pair
    _sudo_run(["ifconfig", feth_vm, "create"])
    _sudo_run(["ifconfig", feth_host, "create"])
    _sudo_run(["ifconfig", feth_vm, "peer", feth_host])

    # Configure host side with IP
    _sudo_run(["ifconfig", feth_host, host_ip, "netmask", "255.255.255.0", "up"])
    _sudo_run(["ifconfig", feth_vm, "up"])

    # Enable IP forwarding (required for NAT)
    _sudo_run(["sysctl", "-w", "net.inet.ip.forwarding=1"], capture=True)

    log.info("feth pair created: %s <-> %s (host=%s)", feth_vm, feth_host, host_ip)
    return alloc


def teardown_feth(agent_index: int) -> None:
    """Destroy a feth pair."""
    alloc = allocate_subnet(agent_index)
    _sudo_run(["ifconfig", alloc["feth_vm"], "destroy"], check=False)
    # Destroying one end also destroys the peer
    log.info("feth pair destroyed: %s", alloc["feth_vm"])


def generate_rules(proxy_port: int = 8080, admin_port: int = 9090, active_subnets: list[str] | None = None) -> str:
    """Generate pf anchor rules for all active VM feth interfaces.

    Args:
        proxy_port: mitmproxy listening port
        admin_port: admin API port to block
        active_subnets: list of subnet strings (e.g., ["192.168.65.0/24"])
    """
    if not active_subnets:
        return f"# SafeYolo anchor {ANCHOR_NAME} — no active VMs\n"

    # Detect outbound interface for NAT
    outbound_if = _detect_outbound_interface()

    rules = f"# SafeYolo VM egress control — anchor {ANCHOR_NAME}\n\n"

    # NAT: allow proxy's upstream connections from feth subnets
    for subnet in active_subnets:
        rules += f"nat on {outbound_if} from {subnet} to any -> ({outbound_if})\n"

    rules += "\n"

    # Per-feth rules (applied to all feth interfaces via interface group)
    for subnet in active_subnets:
        # Derive host IP from subnet (x.x.x.1)
        host_ip = subnet.replace(".0/24", ".1")
        rules += f"# Subnet {subnet}\n"
        rules += f"pass in quick on feth proto tcp from {subnet} to {host_ip} port {proxy_port}\n"
        rules += f"block in quick on feth proto tcp from {subnet} to any port {admin_port}\n"
        rules += f"block in on feth from {subnet} to any\n\n"

    return rules


def load_rules(proxy_port: int = 8080, admin_port: int = 9090, active_subnets: list[str] | None = None) -> None:
    """Write and load pf anchor rules. Requires sudo."""
    rules = generate_rules(proxy_port=proxy_port, admin_port=admin_port, active_subnets=active_subnets)

    _sudo_write_file(ANCHOR_FILE, rules)
    _ensure_anchor_in_pf_conf()
    _sudo_run(["pfctl", "-a", ANCHOR_NAME, "-f", str(ANCHOR_FILE)], capture=True)

    # Enable pf if not already
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _detect_outbound_interface() -> str:
    """Detect the primary outbound network interface (e.g., en0)."""
    try:
        result = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            if "interface:" in line:
                return line.split(":")[1].strip()
    except (subprocess.SubprocessError, OSError):
        pass
    return "en0"


def _sudo_run(cmd, capture=False, check=True):
    return subprocess.run(
        ["sudo"] + cmd,
        capture_output=capture,
        text=True,
        check=check,
    )


def _sudo_write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["sudo", "tee", str(path)],
        input=content, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to write {path}: {proc.stderr}")


def _ensure_anchor_in_pf_conf() -> None:
    pf_conf = Path("/etc/pf.conf")
    anchor_line = f'anchor "{ANCHOR_NAME}"'
    nat_anchor_line = f'nat-anchor "{ANCHOR_NAME}"'
    load_line = f'load anchor "{ANCHOR_NAME}" from "{ANCHOR_FILE}"'

    try:
        content = pf_conf.read_text()
    except PermissionError:
        result = _sudo_run(["cat", "/etc/pf.conf"], capture=True)
        content = result.stdout or ""

    needs_update = False
    addition = ""

    if nat_anchor_line not in content:
        addition += f"\n# SafeYolo VM isolation (NAT)\n{nat_anchor_line}\n"
        needs_update = True

    if anchor_line not in content:
        addition += f"# SafeYolo VM isolation (filter)\n{anchor_line}\n{load_line}\n"
        needs_update = True

    if needs_update:
        subprocess.run(
            ["sudo", "tee", "-a", str(pf_conf)],
            input=addition, capture_output=True, text=True,
        )
        log.info("Added SafeYolo anchors to /etc/pf.conf")
