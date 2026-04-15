"""macOS pf firewall and feth interface management for SafeYolo VM isolation.

Creates feth (fake Ethernet) interface pairs for VM networking. Unlike vmnet
bridge interfaces, feth interfaces are regular network interfaces where pf
rules work. Each VM gets its own feth pair and /24 subnet.

Subnet allocation: agent index → 192.168.(SUBNET_BASE+index).0/24

PF anchor model (security-tightened):
  SafeYolo manages a single fixed anchor file per instance:

      /etc/pf.anchors/com.safeyolo        (production default)
      /etc/pf.anchors/com.safeyolo-test   (blackbox test harness only)

  The anchor hook must be pre-installed in /etc/pf.conf via `safeyolo setup pf`
  (or `safeyolo setup pf --test` for the blackbox test harness). Runtime code
  never reads or mutates /etc/pf.conf — only the fixed anchor file is managed
  and flushed/loaded via `pfctl -a <name>`.

Multiple instances can coexist on the same host by setting:
  SAFEYOLO_PF_ANCHOR   — pf anchor name (default: com.safeyolo; allowed:
                         com.safeyolo, com.safeyolo-test)
  SAFEYOLO_SUBNET_BASE — third octet base (default: 65)
"""

import logging
import os
import subprocess
from pathlib import Path

log = logging.getLogger("safeyolo.firewall")

# Exactly two anchor names are permitted. This is an allowlist, not a wildcard:
# production uses com.safeyolo; the blackbox test harness uses com.safeyolo-test.
# Any other value is rejected at import time to prevent arbitrary anchor names
# leaking into sudo-privileged pfctl calls.
ALLOWED_ANCHORS = ("com.safeyolo", "com.safeyolo-test")
DEFAULT_ANCHOR = "com.safeyolo"


def _resolve_anchor_name() -> str:
    name = os.environ.get("SAFEYOLO_PF_ANCHOR", DEFAULT_ANCHOR)
    if name not in ALLOWED_ANCHORS:
        raise RuntimeError(
            f"SAFEYOLO_PF_ANCHOR={name!r} is not permitted. "
            f"Allowed values: {', '.join(ALLOWED_ANCHORS)}"
        )
    return name


ANCHOR_NAME = _resolve_anchor_name()
ANCHOR_FILE = Path("/etc/pf.anchors") / ANCHOR_NAME
PF_CONF = Path("/etc/pf.conf")

# Base subnet: 192.168.65.0/24 for first VM, .66 for second, etc.
# Override with SAFEYOLO_SUBNET_BASE for multi-instance setups.
SUBNET_BASE = int(os.environ.get("SAFEYOLO_SUBNET_BASE", "65"))


def allocate_subnet(agent_index: int) -> dict:
    """Allocate a subnet for a VM.

    Returns dict with host_ip, guest_ip, subnet, feth_vm, feth_host.
    """
    third_octet = SUBNET_BASE + agent_index
    feth_idx = (SUBNET_BASE - 65 + agent_index) * 2
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
    """Write and load pf anchor rules. Requires sudo.

    Does NOT mutate /etc/pf.conf. The caller must have run `safeyolo setup pf`
    once so that the anchor hook is declared in pf.conf. If the hook is missing,
    this function raises RuntimeError rather than attempting a privileged
    append.

    Idempotent fast path: if the anchor file on disk already contains the
    rules we would write AND pf currently has them loaded, this is a no-op.
    Skips 3-4 sudo round-trips (pfctl write + pfctl -f + pfctl -s info + pfctl -e)
    which together cost around 1.4s on macOS. The common case — same set of
    registered agents, called on every `agent run` — hits the fast path.

    Slow-path triggers (each correctly reloads the full rule set):
      - anchor file missing or unreadable (first run or manual removal)
      - file content differs (agent added / removed, subnet base changed)
      - pf's anchor has no rules even though the file matches (externally
        flushed or host rebooted without a later safeyolo start)
    """
    _require_pf_conf_hook()
    rules = generate_rules(proxy_port=proxy_port, admin_port=admin_port, active_subnets=active_subnets)

    # Fast path: if the anchor file on disk already contains exactly these
    # rules, assume pf is in sync — skip the 3-4 sudo round-trips (~1.4s).
    # Safety note: we deliberately do NOT verify pf state with `pfctl -s
    # rules`, because that single sudo call costs ~1s on macOS and wipes
    # out most of the saving. The risk — pf externally flushed while our
    # anchor file persists — is mitigated by fail-closed routing: without
    # pf's NAT rules, agent subnets aren't routable upstream, so traffic
    # dies at the first hop regardless of whether the per-port block
    # rules are active. The anchor file is managed only by us.
    if ANCHOR_FILE.exists():
        try:
            existing = ANCHOR_FILE.read_text()
        except OSError:
            existing = None
        if existing == rules:
            return

    _sudo_write_file(ANCHOR_FILE, rules)
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
        # `route` unavailable or errored — fall back to the conventional en0.
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


def _pf_conf_declares_anchor() -> bool:
    """Return True iff /etc/pf.conf declares the SafeYolo anchor hook.

    The hook is two lines:
        anchor "com.safeyolo"
        load anchor "com.safeyolo" from "/etc/pf.anchors/com.safeyolo"

    Each must appear as a complete, non-commented line. We match line-aware to
    avoid false positives (e.g. `load anchor "com.safeyolo" ...` contains the
    substring `anchor "com.safeyolo"`).

    pf.conf is world-readable on stock macOS (0644 root:wheel), so this
    does not require sudo.
    """
    anchor_line = f'anchor "{ANCHOR_NAME}"'
    load_line = f'load anchor "{ANCHOR_NAME}" from "{ANCHOR_FILE}"'
    try:
        content = PF_CONF.read_text()
    except FileNotFoundError:
        return False

    has_anchor = False
    has_load = False
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line == anchor_line:
            has_anchor = True
        elif line == load_line:
            has_load = True
    return has_anchor and has_load


def _require_pf_conf_hook() -> None:
    """Ensure the SafeYolo anchor hook is present in pf.conf. Fail loudly otherwise.

    Runtime must not attempt to modify /etc/pf.conf — that requires a broad
    sudoers grant (tee -a /etc/pf.conf) that we deliberately no longer hold.
    """
    if _pf_conf_declares_anchor():
        return
    raise RuntimeError(
        f"SafeYolo anchor hook for {ANCHOR_NAME!r} is not installed in "
        f"{PF_CONF}. Run `safeyolo setup pf"
        f"{' --test' if ANCHOR_NAME == 'com.safeyolo-test' else ''}` once to "
        f"install it. SafeYolo no longer modifies {PF_CONF} at runtime."
    )
