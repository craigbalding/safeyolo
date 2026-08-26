"""Host-side mitmproxy process management for SafeYolo."""

import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from .config import get_config_dir, get_data_dir, get_logs_dir, load_config
from .ignore_hosts import (
    build_ignore_patterns,
    normalize_ignore_hosts,
)
from .tailnet import TAILSCALE_OPERATION_TIMEOUT_SECONDS, validate_tailnet_port
from .timing import child_environment as _profile_child_environment
from .timing import enter as _profile_enter
from .traffic_session import (
    session_process_alive,
    start_session,
    stop_session,
)

log = logging.getLogger("safeyolo.proxy")

DEFAULT_FLOW_CACHE = 5_000

# Addon load order — mirrors scripts/start-safeyolo.sh exactly
ADDON_CHAIN = [
    # UDS ingress is imported by traffic_master before mitmproxy parses its
    # options. Initial modes are supplied by the custom entry point, so no
    # bootstrap addon or transient TCP listener is needed here.
    # Layer 0: Infrastructure
    "pid_writer.py",     # writes SAFEYOLO_PROXY_PID_FILE on `running`
    "file_logging.py",
    "memory_monitor.py",
    "admin_shield.py",
    "agent_api.py",
    "loop_guard.py",
    "request_id.py",
    "operator_provenance.py",
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
    "ignored_host_logger.py",
    "metrics.py",
    "traffic_scope.py",
    "flow_pruner.py",
    "admin_api.py",
    # Layer 4: Reserved diagnostic destinations (issue #213 PR B).
    # probe_sink is the normal terminator (early marker in requestheaders,
    # local 200 in request). transport_guard is the correlated late
    # request-hook failsafe (client-correlatable) + the structural
    # server_connect no-egress backstop (audit-only for catastrophic
    # chain failures). Load order matters: transport_guard's request
    # hook must run AFTER probe_sink so a normally-terminated probe
    # bypasses the failsafe entirely.
    "probe_sink.py",
    "transport_guard.py",
]


def _pid_file() -> Path:
    return get_data_dir() / "proxy.pid"


def web_tailnet_status_file() -> Path:
    """Return the traffic master's durable WebMITM Tailnet state path."""
    return get_data_dir() / "web-tailnet-status.json"


def _read_startup_failure(path: Path, offset: int) -> str | None:
    """Read this launch attempt's structured failure event, if present."""
    try:
        with path.open(encoding="utf-8") as event_file:
            event_file.seek(offset)
            candidates = []
            for line in event_file:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("event") == "ops.proxy_start_failed":
                    candidates.append(event)
    except OSError:
        return None
    if not candidates:
        return None
    event = candidates[-1]
    return str(event.get("summary") or event.get("details", {}).get("error") or "Proxy startup failed")


def resolve_flow_cache(cli_value: int | None, environ: dict[str, str] | None = None) -> int:
    """Resolve CLI > environment > default flow-cache configuration."""
    environment = os.environ if environ is None else environ
    raw_value: int | str = (
        cli_value
        if cli_value is not None
        else environment.get("SAFEYOLO_FLOW_CACHE", DEFAULT_FLOW_CACHE)
    )
    try:
        value = int(raw_value)
    except (TypeError, ValueError) as exc:
        raise ValueError("SAFEYOLO_FLOW_CACHE must be a positive integer") from exc
    if value <= 0:
        source = "--flow-cache" if cli_value is not None else "SAFEYOLO_FLOW_CACHE"
        raise ValueError(f"{source} must be a positive integer")
    return value


def _find_addons_dir() -> Path | None:
    """Find the mitmproxy addons directory.

    Post-refactor (#200 phase 5), addons live next to this module in
    the installed package: `safeyolo/mitm_addons/`. The sibling lookup
    works for both editable (`uv tool install --editable .`) and
    non-editable installs, since the package layout itself is
    consistent. `SAFEYOLO_ADDONS_DIR` still overrides for testing or
    custom deployments.
    """
    env_override = os.environ.get("SAFEYOLO_ADDONS_DIR")
    if env_override:
        p = Path(env_override)
        if p.is_dir() and (p / "request_id.py").exists():
            return p
        return None

    sibling = Path(__file__).resolve().parent / "mitm_addons"
    if sibling.is_dir() and (sibling / "request_id.py").exists():
        return sibling
    return None


def _find_pdp_dir() -> Path | None:
    """Find the pdp directory for PYTHONPATH.

    Repo layout works for editable installs. Non-editable installs need
    SAFEYOLO_PDP_DIR set because pdp/ is still outside the Python package.
    """
    env_override = os.environ.get("SAFEYOLO_PDP_DIR")
    if env_override:
        p = Path(env_override)
        if p.is_dir() and (p / "__init__.py").exists():
            return p
        return None

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
                f"Timed out waiting 60s for mitmdump to generate {ca_cert}. "
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
        admin_token_file.chmod(0o600)  # DOC: docs/security-verification.md, SECURITY.md

    # Agent token: persist across restarts. The token is copied into the
    # guest at staging time, so regenerating it here would break any
    # running sandbox (401 on agent API) until it restarts. The threat
    # model does not benefit from rotation — the guest always holds the
    # current value via /app/agent_token.
    agent_token_file = data_dir / "agent_token"
    if agent_token_file.exists():
        agent_token = agent_token_file.read_text().strip()
    else:
        agent_token = secrets.token_hex(32)
        agent_token_file.write_text(agent_token)
        agent_token_file.chmod(0o600)

    return admin_token, agent_token


def _initial_mode_specs(data_dir: Path) -> list[str]:
    """Build the startup `mode` list from agent_map.json.

    Each known agent becomes a `unix:<path>` entry. The CLI mutates this
    list at runtime via admin API `PUT /admin/proxy/mode` as agents are
    added/removed. Empty list is valid — mitmproxy starts with no
    listeners until the first agent is added.
    """
    from .sockets import path_for

    map_path = data_dir / "agent_map.json"
    if not map_path.exists():
        return []
    try:
        data = json.loads(map_path.read_text())
    except (json.JSONDecodeError, OSError):
        return []

    specs: list[str] = []
    for name, entry in data.items():
        ip = entry.get("ip")
        if not ip:
            continue
        try:
            p = path_for(name, ip)
        except ValueError as exc:
            log.warning("skipping agent %r: %s", name, exc)
            continue
        specs.append(f"unix:{p}")
    return specs


def sync_proxy_modes(admin_port: int = 9090, timeout: float = 5.0) -> bool:
    """Push the current agent_map-derived mode list to a running mitmproxy.

    Called by `safeyolo agent add`/`remove` so new UnixInstance listeners
    appear (and old ones stop) without a mitmproxy restart. Mitmproxy's
    `Proxyserver.configure()` hot-reloads on `options.mode` change.

    Returns True on success, False if the admin API call failed (e.g.,
    mitmproxy not running). Callers treat failure as best-effort — the
    socket will be created on next start via `_initial_mode_specs`.
    """
    import httpx

    data_dir = get_data_dir()
    specs = _initial_mode_specs(data_dir)

    token_path = data_dir / "admin_token"
    if not token_path.exists():
        log.warning("admin_token not found; skipping proxy mode sync")
        return False
    token = token_path.read_text().strip()

    url = f"http://127.0.0.1:{admin_port}/admin/proxy/mode"
    try:
        resp = httpx.put(
            url,
            json={"modes": specs},
            headers={"Authorization": f"Bearer {token}"},
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        log.warning("proxy mode sync failed: %s: %s", type(exc).__name__, exc)
        return False

    if resp.status_code != 200:
        log.warning("proxy mode sync returned %d: %s", resp.status_code, resp.text[:200])
        return False
    log.info("proxy mode sync ok (%d listeners)", len(specs))
    return True


def sync_proxy_ignore_hosts(
    hosts: list[str] | None = None,
    admin_port: int | None = None,
    timeout: float = 5.0,
) -> bool:
    """Push configured exact passthrough hosts to a running mitmproxy."""
    import httpx

    config = load_config()
    if hosts is None:
        hosts = normalize_ignore_hosts(config.get("proxy", {}).get("ignore_hosts", []))
    else:
        hosts = normalize_ignore_hosts(hosts)
    if admin_port is None:
        admin_port = int(config.get("proxy", {}).get("admin_port", 9090))

    token_path = get_data_dir() / "admin_token"
    if not token_path.exists():
        log.warning("admin_token not found; skipping proxy ignore-host sync")
        return False

    url = f"http://127.0.0.1:{admin_port}/admin/proxy/ignore-hosts"
    try:
        response = httpx.put(
            url,
            json={"hosts": hosts},
            headers={"Authorization": f"Bearer {token_path.read_text().strip()}"},
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        log.warning("proxy ignore-host sync failed: %s: %s", type(exc).__name__, exc)
        return False

    if response.status_code != 200:
        log.warning(
            "proxy ignore-host sync returned %d: %s",
            response.status_code,
            response.text[:200],
        )
        return False
    log.info("proxy ignore-host sync ok (%d operator entries)", len(hosts))
    return True


def sync_web_tailnet(
    enabled: bool,
    port: int,
    *,
    admin_port: int | None = None,
    timeout: float = TAILSCALE_OPERATION_TIMEOUT_SECONDS + 2.0,
) -> tuple[bool, dict]:
    """Ask the running traffic master to reconcile its Serve child."""
    import httpx

    config = load_config()
    if admin_port is None:
        admin_port = int(config.get("proxy", {}).get("admin_port", 9090))
    token_path = get_data_dir() / "admin_token"
    if not token_path.exists():
        return False, {"error": "admin token is unavailable"}

    try:
        response = httpx.put(
            f"http://127.0.0.1:{admin_port}/admin/proxy/web-tailnet",
            json={"enabled": enabled, "port": port},
            headers={"Authorization": f"Bearer {token_path.read_text().strip()}"},
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        return False, {"error": f"{type(exc).__name__}: {exc}"}

    try:
        payload = response.json()
    except ValueError:
        payload = {"error": response.text[:200] or "invalid admin API response"}
    if not isinstance(payload, dict):
        payload = {"error": "unexpected admin API response"}
    if response.status_code != 200:
        log.warning(
            "WebMITM Tailnet reconcile returned %d: %s",
            response.status_code,
            response.text[:200],
        )
        return False, payload
    return True, payload


def _build_command(
    addons_dir: Path,
    cert_dir: Path,
    config_dir: Path,
    data_dir: Path,
    logs_dir: Path,
    admin_token: str,
    proxy_port: int = 8080,
    admin_port: int = 9090,
    flow_cache: int = DEFAULT_FLOW_CACHE,
    test_config: dict | None = None,
    proxy_config: dict | None = None,
) -> list[str]:
    """Build the mitmdump command line."""
    # The SafeYolo entrypoint composes ConsoleMaster and mitmweb around one
    # canonical View/Proxyserver. It must run inside the private tmux PTY.
    cmd = [sys.executable, "-m", "safeyolo.traffic_master"]

    # UnixMode is registered directly by safeyolo.traffic_master before
    # mitmproxy parses options. The remaining script addons provide policy,
    # observability, and administrative behavior.
    for addon_file in ADDON_CHAIN:
        addon_path = addons_dir / addon_file
        if addon_path.exists():
            cmd.extend(["-s", str(addon_path)])

    # Core options
    cmd.extend(["--set", f"confdir={cert_dir}"])
    cmd.extend(["--set", "block_global=false"])
    cmd.extend(["--set", "stream_large_bodies=10m"])
    cmd.extend(["--set", f"flow_pruner_max={flow_cache}"])
    cmd.extend(["--set", "web_open_browser=false"])
    cmd.extend(["--set", f"web_host={(proxy_config or {}).get('web_host', '127.0.0.1')}"])  # DOC: docs/security-verification.md
    cmd.extend(["--set", f"web_port={(proxy_config or {}).get('web_port', 8081)}"])
    cmd.extend(["--set", f"admin_port={admin_port}"])
    # Pass token via file path, NOT on the command line. The cmdline is
    # visible to any local user via /proc/PID/cmdline or `ps aux` — putting
    # the admin token there leaks it to every process on the host.
    admin_token_file = data_dir / "admin_token"
    cmd.extend(["--set", f"admin_api_token_file={admin_token_file}"])

    # Complete TLS passthrough list: built-ins, constrained CIDR environment
    # entries, and exact operator-managed hosts from config.yaml. Validation
    # failures abort startup instead of silently losing an exemption.
    configured_hosts = (proxy_config or {}).get("ignore_hosts", [])
    for pattern in build_ignore_patterns(configured_hosts):
        cmd.extend(["--ignore-hosts", pattern])

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
    # tests that don't include X-SafeYolo-Test-Context aren't 428'd. The isolation
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
    # Sources: test config > environment override > persistent proxy config.
    # Used for: blackbox tests (test CA), corporate environments (internal CA)
    #
    # Creates a combined CA bundle (certifi CAs + custom CA) and passes it
    # to mitmproxy via ssl_verify_upstream_trusted_ca. This is deterministic
    # — no mutating the certifi package, survives uv sync/pip install.
    ca_path, ca_source = resolve_upstream_ca_cert(test_config, proxy_config)
    if ca_path is not None:
        combined_bundle = _build_combined_ca_bundle(ca_path, data_dir)
        cmd.extend(["--set", f"ssl_verify_upstream_trusted_ca={combined_bundle}"])
        log.info(
            "Trusting upstream CA from %s: %s (combined bundle at %s)",
            ca_source,
            ca_path,
            combined_bundle,
        )

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
    still carries.
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


def resolve_upstream_ca_cert(
    test_config: dict | None,
    proxy_config: dict | None,
) -> tuple[Path | None, str | None]:
    """Resolve additional upstream trust with explicit override precedence."""
    candidates = (
        ("test.ca_cert", (test_config or {}).get("ca_cert")),
        ("SAFEYOLO_CA_CERT", os.environ.get("SAFEYOLO_CA_CERT")),
        ("proxy.upstream_ca_cert", (proxy_config or {}).get("upstream_ca_cert")),
    )
    for source, value in candidates:
        if value in (None, ""):
            continue
        if not isinstance(value, str):
            raise RuntimeError(f"{source} must be a filesystem path")
        path = Path(value).expanduser()
        if not path.is_file():
            raise RuntimeError(f"CA cert not found: {path}")
        return path, source
    return None, None


def start_proxy(
    proxy_port: int = 8080,
    admin_port: int = 9090,
    flow_cache: int | None = None,
) -> None:
    """Start mitmproxy as a host background process."""
    if is_proxy_running():
        log.info("Proxy already running")
        return

    _profile_enter("proxy: resolve runtime paths and addons")
    config_dir = get_config_dir()
    data_dir = get_data_dir()
    logs_dir = get_logs_dir()
    cert_dir = config_dir / "certs"

    addons_dir = _find_addons_dir()
    if not addons_dir:
        raise RuntimeError(
            "Cannot find the SafeYolo addons directory.\n"
            "\n"
            "Looked in the repo layout relative to this package and at "
            "$SAFEYOLO_ADDONS_DIR (unset or invalid).\n"
            "\n"
            "Fixes:\n"
            "  1. Install editable from the repo:\n"
            "       uv tool install --editable .\n"
            "  2. Or point SafeYolo at an existing checkout:\n"
            "       export SAFEYOLO_ADDONS_DIR=/path/to/safeyolo/cli/src/safeyolo/mitm_addons\n"
            "       export SAFEYOLO_PDP_DIR=/path/to/safeyolo/pdp\n"
        )

    pdp_dir = _find_pdp_dir()

    # Ensure certs, tokens, log dirs
    _profile_enter("proxy: ensure certificates, tokens, and logs")
    _ensure_certs(cert_dir)
    admin_token, _agent_token = _ensure_tokens(data_dir)
    logs_dir.mkdir(parents=True, exist_ok=True)

    # Merge system CAs into certifi so mitmproxy can verify all upstream chains
    _profile_enter("proxy: merge host CA trust")
    _merge_system_cas_into_certifi()

    # Load test config if enabled
    _profile_enter("proxy: load configuration and build child command")
    full_config = load_config()
    test_config = full_config.get("test", {})
    if not test_config.get("enabled"):
        test_config = None
    else:
        log.info("Test mode enabled via config.yaml")

    resolved_flow_cache = resolve_flow_cache(flow_cache)

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
        flow_cache=resolved_flow_cache,
        test_config=test_config,
        proxy_config=full_config.get("proxy", {}),
    )

    # Environment: set PYTHONPATH so addons can import pdp, models, etc.
    _profile_enter("proxy: construct child environment")
    env = os.environ.copy()
    env.update(_profile_child_environment("traffic-master"))
    python_paths = [str(addons_dir)]
    if pdp_dir:
        python_paths.append(str(pdp_dir.parent))  # Parent so `from pdp import ...` works
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = ":".join(python_paths) + (":" + existing if existing else "")

    # Addons hardcode /safeyolo and /app/logs as defaults for the guest
    # layout. When running the mitmproxy master on the host these env vars
    # redirect writes to the operator's config + logs directories.
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
    env["SAFEYOLO_DEFER_PROXY_READY"] = "1"
    # The custom traffic-master entry point applies these modes after parsing
    # command/config options but before Master.run() binds listeners. This
    # avoids a temporary TCP listener and the old fixed bootstrap delay.
    env["SAFEYOLO_INITIAL_MODES"] = json.dumps(_initial_mode_specs(data_dir))
    env["SAFEYOLO_WEB_PASSWORD_FILE"] = str(data_dir / "admin_token")
    web_tailnet = full_config.get("proxy", {}).get("web_tailnet", {})
    if not isinstance(web_tailnet, dict):
        raise ValueError("proxy.web_tailnet must be a mapping")
    web_tailnet_enabled = web_tailnet.get("enabled", False)
    if type(web_tailnet_enabled) is not bool:
        raise ValueError("proxy.web_tailnet.enabled must be true or false")
    web_tailnet_port = web_tailnet.get("port", 443)
    validate_tailnet_port(web_tailnet_port)
    if web_tailnet_enabled and full_config.get("proxy", {}).get("web_host", "127.0.0.1") != "127.0.0.1":
        raise ValueError("WebMITM Tailnet sharing requires proxy.web_host to remain 127.0.0.1")
    env["SAFEYOLO_WEB_TAILNET_ENABLED"] = "1" if web_tailnet_enabled else "0"
    env["SAFEYOLO_WEB_TAILNET_PORT"] = str(web_tailnet_port)
    env["SAFEYOLO_WEB_TAILNET_STATUS_FILE"] = str(web_tailnet_status_file())

    # Pass test sinkhole config to child process (read by sinkhole_router addon)
    if test_config:
        env["SAFEYOLO_SINKHOLE_HOST"] = str(test_config.get("sinkhole_host", "127.0.0.1"))
        env["SAFEYOLO_SINKHOLE_HTTP_PORT"] = str(test_config.get("sinkhole_http_port", 18080))
        env["SAFEYOLO_SINKHOLE_HTTPS_PORT"] = str(test_config.get("sinkhole_https_port", 18443))

    _profile_enter("proxy: remove stale readiness and socket state")
    # Clear any stale pid file from a previous crashed run so the poll
    # below doesn't mistake it for "ready". addons/pid_writer.py will
    # recreate it on `running`.
    pid_file = _pid_file()
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    pid_file.unlink(missing_ok=True)

    # A crash can leave filesystem socket inodes behind. No proxy is alive at
    # this point, so none can be a functioning listener.
    from .sockets import remove_stale_sockets
    remove_stale_sockets()

    # Start inside SafeYolo's private terminal server. ConsoleMaster receives
    # a real PTY even when no operator is attached; mitmweb and proxy traffic
    # remain alive across console attach/detach.
    event_log = logs_dir / "safeyolo.jsonl"
    try:
        event_offset = event_log.stat().st_size
    except OSError:
        event_offset = 0
    try:
        _profile_enter("proxy: create private traffic session")
        start_session(cmd, env=env)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(f"failed to start private traffic session: {exc}") from exc

    # Wait for addons/pid_writer.py to signal ready, OR for mitmdump to
    # die (whichever first). No fixed sleep: the pid file usually appears
    # in 150-300ms; poll interval 50ms = sub-tick on success. On failure
    # proc.poll() surfaces the exit code immediately.
    try:
        _profile_enter("proxy: wait for traffic-master readiness")
        startup_timeout = TAILSCALE_OPERATION_TIMEOUT_SECONDS if web_tailnet_enabled else 10.0
        deadline = time.monotonic() + startup_timeout
        while time.monotonic() < deadline:
            if pid_file.exists():
                break
            if not session_process_alive():
                failure = _read_startup_failure(event_log, event_offset) or (
                    "Traffic master exited before recording a structured startup failure."
                )
                raise RuntimeError(
                    "shared traffic master exited during startup.\n"
                    f"{failure}"
                )
            time.sleep(0.05)
        else:
            failure = _read_startup_failure(event_log, event_offset) or (
                "Traffic master remained alive but did not finish startup before the readiness deadline."
            )
            raise RuntimeError(
                f"Proxy did not signal ready within {startup_timeout:g}s.\n"
                f"{failure}"
            )
    except Exception:
        pid_file.unlink(missing_ok=True)
        stop_session()
        raise

    try:
        pid = int(pid_file.read_text().strip())
    except (OSError, ValueError):
        pid_file.unlink(missing_ok=True)
        stop_session()
        raise RuntimeError("Proxy published an invalid readiness marker") from None
    log.info("Proxy started (PID %d) on port %d", pid, proxy_port)


def stop_proxy() -> None:
    """Stop the host mitmproxy process.

    Per-agent UDS listeners are owned by mitmproxy directly (one
    `UnixInstance` per agent). Stopping the process tears them down
    along with their socket files. Guest-side socat retries connects
    while mitmproxy is offline (see `guest-proxy-forwarder.sh`), so a
    brief restart window is absorbed without the agent seeing an
    HTTP-layer failure — provided mitmproxy recovers within the retry
    window.
    """
    _profile_enter("proxy: resolve traffic-master state")
    pid_file = _pid_file()
    if not pid_file.exists():
        stop_session()
        return

    pid = int(pid_file.read_text().strip())

    _profile_enter("proxy: send graceful termination")
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pid_file.unlink(missing_ok=True)
        stop_session()
        return

    # Wait up to 5 seconds for clean exit
    _profile_enter("proxy: wait for graceful traffic-master exit")
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

    _profile_enter("proxy: clean private traffic session")
    pid_file.unlink(missing_ok=True)
    stop_session()
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
        # start_proxy has already published its final readiness marker. If
        # that process disappears, no amount of HTTP retrying can recover it.
        if not is_proxy_running():
            return False
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
