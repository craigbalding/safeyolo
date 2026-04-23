"""Host-side mitmproxy process management for SafeYolo.

Replaces the Docker-based proxy container with a direct host process.
The addon stack, options, and behavior are identical — only the
execution environment changes (host process vs. container).
"""

import ipaddress
import logging
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from .config import get_config_dir, get_data_dir, get_logs_dir, load_config

log = logging.getLogger("safeyolo.proxy")

# Addon load order — mirrors scripts/start-safeyolo.sh exactly
ADDON_CHAIN = [
    # Layer -1: Connection identity (must be first — monkeypatches
    # handle_stream before any connections arrive)
    "proxy_protocol.py",
    # Layer 0: Infrastructure
    "pid_writer.py",     # writes SAFEYOLO_PROXY_PID_FILE on `running`
    "file_logging.py",
    "memory_monitor.py",
    "admin_shield.py",
    "agent_api.py",
    "loop_guard.py",
    "request_id.py",
    "service_discovery.py",
    "sse_streaming.py",
    "policy_engine.py",
    # Layer 0.5: Service Gateway
    "service_gateway.py",
    # Layer 1: Network Policy
    "network_guard.py",
    "circuit_breaker.py",
    # Layer 2: Security Inspection
    "credential_guard.py",
    "pattern_scanner.py",
    "test_context.py",
    # Layer 3: Observability
    "flow_recorder.py",
    "request_logger.py",
    "metrics.py",
    "admin_api.py",
]


def _pid_file() -> Path:
    return get_data_dir() / "proxy.pid"


def _read_log_tail(path: Path, lines: int = 15) -> str:
    """Read the last N lines of a log file for user-facing error output.

    Used on startup failure: the log already contains mitmdump's own
    error output (stdout+stderr are redirected to it), so a tail tells
    the user what actually went wrong (ImportError, port collision,
    config typo, etc.).
    """
    try:
        with open(path, "rb") as f:
            try:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                # 8KB is plenty for ~15 log lines even with long addon
                # tracebacks; avoids reading megabytes of prior runs.
                read_size = min(size, 8192)
                f.seek(size - read_size)
                data = f.read()
            except OSError:
                f.seek(0)
                data = f.read()
        return b"\n".join(data.splitlines()[-lines:]).decode(errors="replace")
    except OSError:
        return "(log file not readable)"


def _find_addons_dir() -> Path | None:
    """Find the addons directory. Check repo layout first, then installed package."""
    # Repo layout: safeyolo/addons/
    candidates = [
        Path(__file__).resolve().parents[3] / "addons",  # cli/src/safeyolo -> repo root
        Path(__file__).resolve().parents[4] / "addons",  # one more level up
    ]
    for p in candidates:
        if p.is_dir() and (p / "request_id.py").exists():
            return p
    return None


def _find_pdp_dir() -> Path | None:
    """Find the pdp directory for PYTHONPATH."""
    candidates = [
        Path(__file__).resolve().parents[3] / "pdp",
        Path(__file__).resolve().parents[4] / "pdp",
    ]
    for p in candidates:
        if p.is_dir() and (p / "__init__.py").exists():
            return p
    return None


def _ensure_certs(cert_dir: Path) -> Path:
    """Generate mitmproxy CA cert if not present. Returns path to public cert.

    mitmdump generates its CA lazily on first startup. We boot it just long
    enough for the ``mitmproxy-ca-cert.pem`` file to land in ``confdir`` —
    then kill it. Rather than guessing how long that takes (cold cache vs
    warm cache differ by an order of magnitude on modest hardware), poll
    for the file and give up only after a generous wall-clock deadline.
    """
    cert_dir.mkdir(parents=True, exist_ok=True)
    ca_cert = cert_dir / "mitmproxy-ca-cert.pem"

    if ca_cert.exists():
        return ca_cert

    log.info("Generating mitmproxy CA certificate...")
    # Prefer the mitmdump sibling of the current interpreter (same reason
    # as _build_command below: avoids Homebrew's sealed-env mitmdump when
    # PATH ordering would otherwise pick it).
    python_dir = Path(sys.executable).parent
    candidate = python_dir / "mitmdump"
    mitmdump = str(candidate) if candidate.exists() else (shutil.which("mitmdump") or "mitmdump")

    # Start mitmdump detached; poll for the cert file. 60s deadline is
    # generous for a cold-cache first run (Python + mitmproxy imports +
    # RSA keypair gen) while still terminating in reasonable time on
    # pathological hosts.
    proc = subprocess.Popen(
        [mitmdump, "--set", f"confdir={cert_dir}", "-p", "0"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 60.0
        while time.monotonic() < deadline:
            if ca_cert.exists():
                break
            if proc.poll() is not None:
                # mitmdump exited before writing the cert — unusual, but
                # if the file landed in the meantime we still win.
                if ca_cert.exists():
                    break
                raise RuntimeError(
                    f"mitmdump exited (rc={proc.returncode}) before writing "
                    f"{ca_cert}. Check that mitmproxy is installed and "
                    f"importable in the current environment."
                )
            time.sleep(0.1)
        else:
            raise RuntimeError(
                f"Timed out waiting 60s for mitmproxy to generate {ca_cert}. "
                f"Re-run after confirming mitmdump starts on this host."
            )
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)

    if not ca_cert.exists():
        raise RuntimeError(f"Failed to generate CA certificate in {cert_dir}")

    # Tighten permissions on private key material
    for f in cert_dir.iterdir():
        if f.suffix in (".pem", ".p12"):
            f.chmod(0o600)
    cert_dir.chmod(0o700)

    return ca_cert


def _ensure_tokens(data_dir: Path) -> tuple[str, str]:
    """Ensure admin and agent tokens exist. Returns (admin_token, agent_token)."""
    import secrets

    data_dir.mkdir(parents=True, exist_ok=True)

    # Admin token: persist across restarts
    admin_token_file = data_dir / "admin_token"
    if admin_token_file.exists():
        admin_token = admin_token_file.read_text().strip()
    else:
        admin_token = secrets.token_urlsafe(32)
        admin_token_file.write_text(admin_token)
        admin_token_file.chmod(0o600)

    # Agent token: persist across restarts. In the Docker era this was
    # a bind-mount so regeneration was transparent (container saw the
    # new file immediately). In the microVM era the token is copied at
    # staging time — regenerating it breaks running sandboxes (401 on
    # agent API). The token's threat model doesn't benefit from rotation
    # anyway: the agent always holds the current value via /app/agent_token.
    agent_token_file = data_dir / "agent_token"
    if agent_token_file.exists():
        agent_token = agent_token_file.read_text().strip()
    else:
        agent_token = secrets.token_hex(32)
        agent_token_file.write_text(agent_token)
        agent_token_file.chmod(0o600)

    return admin_token, agent_token


# ---------------------------------------------------------------------------
# SAFEYOLO_IGNORE_CIDRS — pass a CIDR (or comma-separated list of CIDRs) as
# an env var to add mitmproxy --ignore-hosts exemptions for those IP ranges.
# CIDR-only by design: no regex surface for the user to misuse, validated at
# startup, and /0–/7 is refused so you can't accidentally exempt half the
# internet.
# ---------------------------------------------------------------------------

# Refuse prefixes wider than this — user-facing footgun guard.
_IGNORE_CIDR_MIN_PREFIX = 8


def _octet_range_regex(lo: int, hi: int) -> str:
    """Regex fragment matching any integer in [lo, hi]. 0 ≤ lo ≤ hi ≤ 255."""
    if lo == 0 and hi == 255:
        return r"\d+"
    # Alternation is fine here: the widest CIDRs we accept (/8) give at most
    # 256 values in the partial octet, which regex engines compile happily.
    return "(?:" + "|".join(str(n) for n in range(lo, hi + 1)) + ")"


def _cidr_to_ignore_regex(cidr: str) -> str:
    """Convert an IPv4 CIDR to a mitmproxy --ignore-hosts regex.

    Output matches `<ip>` or `<ip>:<port>` where <ip> is any IPv4 address in
    the CIDR. Rejects IPv6 (the host:port regex shape doesn't map cleanly)
    and prefixes < /8 (accidental-over-exemption guard).
    """
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as e:
        raise ValueError(f"Invalid CIDR {cidr!r}: {e}") from e

    if isinstance(net, ipaddress.IPv6Network):
        raise ValueError(f"IPv6 CIDR not supported: {cidr!r}")

    if net.prefixlen < _IGNORE_CIDR_MIN_PREFIX:
        raise ValueError(
            f"CIDR {cidr!r} is too wide (prefix /{net.prefixlen} < "
            f"/{_IGNORE_CIDR_MIN_PREFIX}); refusing to exempt that large a range"
        )

    octets = net.network_address.packed  # 4 bytes
    full = net.prefixlen // 8        # number of fully-fixed leading octets
    partial = net.prefixlen % 8      # bits constraining the next octet, if any

    parts: list[str] = [str(octets[i]) for i in range(full)]

    if full < 4:
        if partial == 0:
            # Whole remaining octets are wildcards
            parts.extend([r"\d+"] * (4 - full))
        else:
            lo = octets[full]
            hi = lo + (1 << (8 - partial)) - 1
            parts.append(_octet_range_regex(lo, hi))
            parts.extend([r"\d+"] * (4 - full - 1))

    return r"^" + r"\.".join(parts) + r"(?::\d+)?$"


def _parse_ignore_cidrs_env() -> list[str]:
    """Parse SAFEYOLO_IGNORE_CIDRS into a list of --ignore-hosts regexes.

    Fails fast on any invalid entry so a typo can't silently drop a passthrough.
    """
    raw = os.environ.get("SAFEYOLO_IGNORE_CIDRS", "").strip()
    if not raw:
        return []
    regexes: list[str] = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        regexes.append(_cidr_to_ignore_regex(entry))
    return regexes


def _build_command(
    addons_dir: Path,
    cert_dir: Path,
    config_dir: Path,
    data_dir: Path,
    logs_dir: Path,
    admin_token: str,
    proxy_port: int = 8080,
    admin_port: int = 9090,
    test_config: dict | None = None,
) -> list[str]:
    """Build the mitmdump command line."""
    # Find mitmdump matching the running Python interpreter FIRST.
    # SafeYolo addons import PyYAML, mitmproxy2swagger, etc. which live in
    # the project's .venv; Homebrew's mitmdump bottle ships its own sealed
    # Python env that does NOT have those deps and crashes on startup with
    # "ModuleNotFoundError: No module named 'yaml'". PATH lookup can find
    # the wrong one (depends on PATH ordering vs /opt/homebrew/bin). Prefer
    # the sibling of sys.executable (the interpreter that's running us) so
    # the addon deps are always resolvable.
    python_dir = Path(sys.executable).parent
    candidate = python_dir / "mitmdump"
    if candidate.exists():
        mitmdump = str(candidate)
    else:
        mitmdump = shutil.which("mitmdump") or "mitmdump"

    # Bind to all interfaces so VMs on the bridge can reach the proxy
    cmd = [mitmdump, "--listen-host", "0.0.0.0", "-p", str(proxy_port)]

    # Load addons
    for addon_file in ADDON_CHAIN:
        addon_path = addons_dir / addon_file
        if addon_path.exists():
            cmd.extend(["-s", str(addon_path)])

    # Core options
    cmd.extend(["--set", f"confdir={cert_dir}"])
    cmd.extend(["--set", "block_global=false"])
    cmd.extend(["--set", "stream_large_bodies=10m"])
    cmd.extend(["--set", f"admin_port={admin_port}"])
    # Pass token via file path, NOT on the command line. The cmdline is
    # visible to any local user via /proc/PID/cmdline or `ps aux` — putting
    # the admin token there leaks it to every process on the host.
    admin_token_file = data_dir / "admin_token"
    cmd.extend(["--set", f"admin_api_token_file={admin_token_file}"])

    # TLS passthrough for frpc — frp protocol doesn't work through MITM
    cmd.extend(["--ignore-hosts", r"^api\.asterfold\.ai:7000$"])

    # User-supplied IPv4 CIDR passthroughs (comma-separated in
    # SAFEYOLO_IGNORE_CIDRS). Useful for e.g. Tailscale CGNAT (100.64.0.0/10)
    # or RFC1918 admin networks. Validation failures raise here so the proxy
    # refuses to start with a mis-typed CIDR rather than silently dropping it.
    for regex in _parse_ignore_cidrs_env():
        cmd.extend(["--ignore-hosts", regex])

    # -------------------------------------------------------------------------
    # Blocking mode configuration
    # Each addon has its own default. SAFEYOLO_BLOCK=true overrides all to block.
    # Individual env vars provide fine-grained control.
    # NOTE: Runtime mode changes via admin API are in-memory only.
    # On restart, SafeYolo returns to these startup defaults.
    # -------------------------------------------------------------------------
    force_block = os.environ.get("SAFEYOLO_BLOCK") == "true"

    # network-guard: defaults to BLOCK
    ng_block = force_block or os.environ.get("NETWORK_GUARD_BLOCK", "true").lower() == "true"
    cmd.extend(["--set", f"network_guard_block={'true' if ng_block else 'false'}"])

    # credential-guard: defaults to BLOCK
    cg_block = force_block or os.environ.get("CREDGUARD_BLOCK", "true").lower() == "true"
    cmd.extend(["--set", f"credguard_block={'true' if cg_block else 'false'}"])

    # pattern-scanner: defaults to WARN-ONLY
    ps_block = force_block or os.environ.get("PATTERN_BLOCK", "false").lower() == "true"
    if ps_block:
        cmd.extend(["--set", "pattern_block_input=true"])
        cmd.extend(["--set", "pattern_block_output=true"])

    # test-context: defaults to BLOCK (428 soft-reject for missing context).
    # In test mode (blackbox harness), disable blocking so host-side proxy
    # tests that don't include X-Test-Context aren't 428'd. The isolation
    # tests explicitly include the header on probes they want recorded.
    if test_config:
        tc_block = False
    else:
        tc_block = force_block or os.environ.get("TEST_CONTEXT_BLOCK", "true").lower() == "true"
    cmd.extend(["--set", f"test_context_block={'true' if tc_block else 'false'}"])

    # Override container-default paths for host execution
    data_dir = config_dir / "data"
    cmd.extend(["--set", f"circuit_state_file={data_dir / 'circuit_breaker_state.json'}"])
    cmd.extend(["--set", f"flow_store_db_path={logs_dir / 'flows.sqlite3'}"])

    # Policy file
    policy_toml = config_dir / "policy.toml"
    policy_yaml = config_dir / "policy.yaml"
    if policy_toml.exists():
        cmd.extend(["--set", f"policy_file={policy_toml}"])
    elif policy_yaml.exists():
        cmd.extend(["--set", f"policy_file={policy_yaml}"])
    else:
        raise RuntimeError(
            f"No policy file found in {config_dir}. "
            f"Run 'safeyolo init' to create a default configuration."
        )

    # Rate limit config (optional)
    ratelimit_config = config_dir / "rate_limits.json"
    if ratelimit_config.exists():
        cmd.extend(["--set", f"ratelimit_config={ratelimit_config}"])

    # Service gateway — auto-enable when vault exists
    vault_key = config_dir / "data" / "vault.key"
    vault_enc = config_dir / "data" / "vault.yaml.enc"
    if vault_key.exists() and vault_enc.exists():
        cmd.extend(["--set", "gateway_enabled=true"])
        cmd.extend(["--set", f"gateway_services_dir={config_dir / 'services'}"])
        cmd.extend(["--set", f"gateway_vault_path={vault_enc}"])
        cmd.extend(["--set", f"gateway_vault_key={vault_key}"])

    # Agent map file for service discovery (microVM mode)
    agent_map = config_dir / "data" / "agent_map.json"
    cmd.extend(["--set", f"agent_map_file={agent_map}"])

    # Custom upstream CA trust
    # Sources: test config (test.ca_cert) > env var (SAFEYOLO_CA_CERT)
    # Used for: blackbox tests (test CA), corporate environments (internal CA)
    #
    # Creates a combined CA bundle (certifi CAs + custom CA) and passes it
    # to mitmproxy via ssl_verify_upstream_trusted_ca. This is deterministic
    # — no mutating the certifi package, survives uv sync/pip install.
    ca_cert = None
    if test_config and test_config.get("ca_cert"):
        ca_cert = test_config["ca_cert"]
    elif os.environ.get("SAFEYOLO_CA_CERT"):
        ca_cert = os.environ["SAFEYOLO_CA_CERT"]
    if ca_cert:
        ca_path = Path(ca_cert)
        if not ca_path.exists():
            raise RuntimeError(f"CA cert not found: {ca_cert}")
        combined_bundle = _build_combined_ca_bundle(ca_path, data_dir)
        cmd.extend(["--set", f"ssl_verify_upstream_trusted_ca={combined_bundle}"])
        log.info("Trusting upstream CA: %s (combined bundle at %s)", ca_cert, combined_bundle)

    # Blackbox test sinkhole routing
    # Sources: test config (test.sinkhole_router) > env var (SAFEYOLO_SINKHOLE_ROUTER)
    # Loads LAST so upstream connections are redirected after security addons run.
    sinkhole_router = None
    if test_config and test_config.get("sinkhole_router"):
        sinkhole_router = test_config["sinkhole_router"]
    elif os.environ.get("SAFEYOLO_SINKHOLE_ROUTER"):
        sinkhole_router = os.environ["SAFEYOLO_SINKHOLE_ROUTER"]
    if sinkhole_router:
        router_path = Path(sinkhole_router)
        if not router_path.exists():
            raise RuntimeError(f"Sinkhole router addon not found: {sinkhole_router}")
        log.info("Loading sinkhole router addon: %s", sinkhole_router)
        cmd.extend(["-s", str(router_path)])
        # Defer upstream connect until AFTER the request hook runs so
        # the sinkhole router can rewrite flow.request.host to the
        # local sinkhole BEFORE mitmproxy resolves DNS. Without this,
        # blackbox test hostnames that don't resolve (e.g. *.test)
        # fail at CONNECT with [Errno 8] nodename nor servname. Real
        # upstreams aren't affected because the router no-ops for them.
        cmd.extend(["--set", "connection_strategy=lazy"])

    return cmd


def _merge_system_cas_into_certifi() -> None:
    """Merge system CA bundle into certifi so mitmproxy trusts all roots.

    Cross-signed chains (e.g. Cloudflare → SSL.com → Comodo "AAA Certificate
    Services") may chain to roots present in only one bundle.  Merging both
    prevents upstream TLS failures when either bundle drops a root the other
    still carries.  This mirrors the Dockerfile RUN step that was lost in the
    Docker-to-host migration.
    """
    try:
        import certifi

        certifi_bundle = Path(certifi.where())
    except (ImportError, Exception) as exc:
        log.warning("Cannot locate certifi bundle, skipping CA merge: %s", exc)
        return

    # Collect candidate system CA bundle paths (Linux + macOS)
    system_bundles = [
        Path("/etc/ssl/certs/ca-certificates.crt"),   # Debian/Ubuntu
        Path("/etc/pki/tls/certs/ca-bundle.crt"),      # RHEL/Fedora
        Path("/etc/ssl/cert.pem"),                      # macOS / Alpine
    ]
    system_bundle = next((p for p in system_bundles if p.exists()), None)
    if not system_bundle:
        log.debug("No system CA bundle found, skipping merge")
        return

    # Read both bundles and check if merge is needed
    system_pems = system_bundle.read_text()
    certifi_pems = certifi_bundle.read_text()

    # Simple dedup: only append certs not already present
    new_certs = []
    for block in system_pems.split("-----END CERTIFICATE-----"):
        block = block.strip()
        if block and block not in certifi_pems:
            new_certs.append(block + "\n-----END CERTIFICATE-----\n")

    if not new_certs:
        log.debug("System CAs already present in certifi bundle")
        return

    with certifi_bundle.open("a") as f:
        f.write("\n")
        f.writelines(new_certs)
    log.info("Merged %d system CA certs into certifi bundle", len(new_certs))


def _build_combined_ca_bundle(custom_ca: Path, data_dir: Path) -> Path:
    """Create a CA bundle combining certifi CAs + a custom CA.

    Returns the path to the combined bundle. The bundle is written to
    data_dir/combined-ca-bundle.pem and recreated each time to ensure
    it always reflects the current certifi bundle + custom CA.
    """
    import certifi
    certifi_bundle = Path(certifi.where())

    combined = data_dir / "combined-ca-bundle.pem"
    combined.write_text(
        certifi_bundle.read_text() + "\n" + custom_ca.read_text()
    )
    return combined


def start_proxy(proxy_port: int = 8080, admin_port: int = 9090) -> None:
    """Start mitmproxy as a host background process."""
    if is_proxy_running():
        log.info("Proxy already running")
        return

    config_dir = get_config_dir()
    data_dir = get_data_dir()
    logs_dir = get_logs_dir()
    cert_dir = config_dir / "certs"

    addons_dir = _find_addons_dir()
    if not addons_dir:
        raise RuntimeError(
            "Cannot find addons directory. "
            "Run from the SafeYolo repo or ensure addons are installed."
        )

    pdp_dir = _find_pdp_dir()

    # Ensure certs, tokens, log dirs
    _ensure_certs(cert_dir)
    admin_token, _agent_token = _ensure_tokens(data_dir)
    logs_dir.mkdir(parents=True, exist_ok=True)

    # Merge system CAs into certifi so mitmproxy can verify all upstream chains
    _merge_system_cas_into_certifi()

    # Load test config if enabled
    full_config = load_config()
    test_config = full_config.get("test", {})
    if not test_config.get("enabled"):
        test_config = None
    else:
        log.info("Test mode enabled via config.yaml")

    # Build command
    cmd = _build_command(
        addons_dir=addons_dir,
        cert_dir=cert_dir,
        config_dir=config_dir,
        data_dir=data_dir,
        logs_dir=logs_dir,
        admin_token=admin_token,
        proxy_port=proxy_port,
        admin_port=admin_port,
        test_config=test_config,
    )

    # Environment: set PYTHONPATH so addons can import pdp, models, etc.
    env = os.environ.copy()
    python_paths = [str(addons_dir)]
    if pdp_dir:
        python_paths.append(str(pdp_dir.parent))  # Parent so `from pdp import ...` works
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = ":".join(python_paths) + (":" + existing if existing else "")

    # Map container paths to host paths.
    # Addons hardcode /safeyolo (config bind-mount) and /app/logs (log dir)
    # from the Docker container layout. These env vars override the defaults.
    env["CONFIG_DIR"] = str(config_dir)
    env["LOG_DIR"] = str(logs_dir)
    env["SAFEYOLO_LOG_PATH"] = str(logs_dir / "safeyolo.jsonl")
    env["MITMPROXY_LOG_PATH"] = str(logs_dir / "mitmproxy.log")
    env["SAFEYOLO_DATA_DIR"] = str(config_dir / "data")
    env["SAFEYOLO_SERVICES_DIR"] = str(config_dir / "services")
    # Where addons/pid_writer.py will drop the pid when mitmproxy reaches
    # `running` (= listener bound, all addons loaded). We poll for this
    # file below rather than sleeping -- the absence of the file during
    # the poll window tells us mitmdump crashed.
    env["SAFEYOLO_PROXY_PID_FILE"] = str(_pid_file())

    # Pass test sinkhole config to child process (read by sinkhole_router addon)
    if test_config:
        env["SAFEYOLO_SINKHOLE_HOST"] = str(test_config.get("sinkhole_host", "127.0.0.1"))
        env["SAFEYOLO_SINKHOLE_HTTP_PORT"] = str(test_config.get("sinkhole_http_port", 18080))
        env["SAFEYOLO_SINKHOLE_HTTPS_PORT"] = str(test_config.get("sinkhole_https_port", 18443))

    # Clear any stale pid file from a previous crashed run so the poll
    # below doesn't mistake it for "ready". addons/pid_writer.py will
    # recreate it on `running`.
    pid_file = _pid_file()
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    pid_file.unlink(missing_ok=True)

    # Start as background process
    log_file = logs_dir / "mitmproxy.log"
    with open(log_file, "a") as lf:
        proc = subprocess.Popen(
            cmd,
            stdout=lf,
            stderr=lf,
            env=env,
            start_new_session=True,  # Detach from terminal
        )

    # Wait for addons/pid_writer.py to signal ready, OR for mitmdump to
    # die (whichever first). No fixed sleep: the pid file usually appears
    # in 150-300ms; poll interval 50ms = sub-tick on success. On failure
    # proc.poll() surfaces the exit code immediately.
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if pid_file.exists():
            break
        if proc.poll() is not None:
            tail = _read_log_tail(log_file, lines=15)
            raise RuntimeError(
                f"mitmdump exited during startup (rc={proc.returncode}).\n"
                f"Last {15} log lines:\n{tail}"
            )
        time.sleep(0.05)
    else:
        # Ran past the deadline with mitmdump still alive but no pid
        # file -- bound but `running` never fired? Unusual. Surface log
        # tail so whatever hung shows up.
        tail = _read_log_tail(log_file, lines=15)
        raise RuntimeError(
            f"Proxy did not signal ready within 10s (pid={proc.pid}).\n"
            f"Last {15} log lines:\n{tail}"
        )

    log.info("Proxy started (PID %d) on port %d", proc.pid, proxy_port)

    # Start the UDS -> TCP bridge for Linux agents that reach mitmproxy
    # via a bind-mounted socket instead of IP networking. macOS agents
    # use the vsock relay inside safeyolo-vm and ignore this socket.
    # Best-effort: a failed bridge start shouldn't prevent the proxy
    # from coming up.
    try:
        from .proxy_bridge import start_proxy_bridge
        start_proxy_bridge(proxy_port=proxy_port)
    except Exception as exc:
        log.warning("proxy bridge failed to start: %s: %s",
                    type(exc).__name__, exc)


def stop_proxy() -> None:
    """Stop the host mitmproxy process.

    Does NOT stop the proxy_bridge. The bridge owns /safeyolo/proxy.sock,
    which gVisor's gofer binds once at container start; unlinking the
    socket invalidates the container-side inode handle even after a
    fresh bind at the same path. Keeping the bridge alive across
    mitmproxy restarts preserves the UDS inode — clients inside running
    agents just see transient "connection refused" to 127.0.0.1:8080
    during the gap and recover automatically when mitmproxy is back.

    `safeyolo stop --all` is the right command when the bridge should
    also go (it tears down agents first, so no one is holding handles).
    """
    pid_file = _pid_file()
    if not pid_file.exists():
        return

    pid = int(pid_file.read_text().strip())

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pid_file.unlink(missing_ok=True)
        return

    # Wait up to 5 seconds for clean exit
    for _ in range(50):
        try:
            os.kill(pid, 0)  # Check if alive
            time.sleep(0.1)
        except ProcessLookupError:
            break
    else:
        # Still alive after 5s — force kill
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            # Process died during the SIGTERM wait loop — fine.
            pass

    pid_file.unlink(missing_ok=True)
    log.info("Proxy stopped")


def is_proxy_running() -> bool:
    """Check if the mitmproxy process is alive."""
    pid_file = _pid_file()
    if not pid_file.exists():
        return False

    pid = int(pid_file.read_text().strip())
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        pid_file.unlink(missing_ok=True)
        return False


def wait_for_healthy(timeout: int = 30, admin_port: int = 9090) -> bool:
    """Wait for mitmproxy admin API to become healthy."""
    import urllib.error
    import urllib.request

    data_dir = get_data_dir()
    admin_token_file = data_dir / "admin_token"
    token = admin_token_file.read_text().strip() if admin_token_file.exists() else ""

    for _ in range(timeout):
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{admin_port}/health",
                headers={"Authorization": f"Bearer {token}"},
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, ConnectionError, OSError):
            # Proxy not up yet this tick — sleep and retry until timeout.
            pass
        time.sleep(1)

    return False


def get_ca_cert_path() -> Path | None:
    """Return path to the public CA cert, or None if not generated yet."""
    cert = get_config_dir() / "certs" / "mitmproxy-ca-cert.pem"
    return cert if cert.exists() else None
