"""Host-side mitmproxy process management for SafeYolo.

Replaces the Docker-based proxy container with a direct host process.
The addon stack, options, and behavior are identical — only the
execution environment changes (host process vs. container).
"""

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

log = logging.getLogger("safeyolo.proxy")

# Addon load order — mirrors scripts/start-safeyolo.sh exactly
ADDON_CHAIN = [
    # Layer 0: Infrastructure
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
    """Generate mitmproxy CA cert if not present. Returns path to public cert."""
    cert_dir.mkdir(parents=True, exist_ok=True)
    ca_cert = cert_dir / "mitmproxy-ca-cert.pem"

    if not ca_cert.exists():
        log.info("Generating mitmproxy CA certificate...")
        try:
            subprocess.run(
                ["mitmdump", "--set", f"confdir={cert_dir}", "-p", "0"],
                timeout=5,
                capture_output=True,
            )
        except subprocess.TimeoutExpired:
            pass  # Expected — mitmdump exits after generating certs

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

    # Agent token: regenerated every start
    agent_token = secrets.token_hex(32)
    agent_token_file = data_dir / "agent_token"
    agent_token_file.write_text(agent_token)
    agent_token_file.chmod(0o600)

    return admin_token, agent_token


def _build_command(
    addons_dir: Path,
    cert_dir: Path,
    config_dir: Path,
    logs_dir: Path,
    admin_token: str,
    proxy_port: int = 8080,
    admin_port: int = 9090,
    test_config: dict | None = None,
) -> list[str]:
    """Build the mitmdump command line."""
    # Find mitmdump in the same venv/prefix as this Python process
    mitmdump = shutil.which("mitmdump")
    if not mitmdump:
        # Check sibling of the running Python interpreter
        python_dir = Path(sys.executable).parent
        candidate = python_dir / "mitmdump"
        if candidate.exists():
            mitmdump = str(candidate)
        else:
            mitmdump = "mitmdump"  # Fall back to PATH

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
    cmd.extend(["--set", f"admin_api_token={admin_token}"])

    # TLS passthrough for frpc — frp protocol doesn't work through MITM
    cmd.extend(["--ignore-hosts", r"^api\.asterfold\.ai:7000$"])

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

    # test-context: defaults to BLOCK (428 soft-reject for missing context)
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
        raise RuntimeError(f"No policy file found in {config_dir}")

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
    # Merged into certifi bundle so mitmproxy trusts BOTH the custom CA
    # and real CAs (ssl_verify_upstream_trusted_ca would replace the bundle).
    ca_cert = None
    if test_config and test_config.get("ca_cert"):
        ca_cert = test_config["ca_cert"]
    elif os.environ.get("SAFEYOLO_CA_CERT"):
        ca_cert = os.environ["SAFEYOLO_CA_CERT"]
    if ca_cert:
        ca_path = Path(ca_cert)
        if not ca_path.exists():
            raise RuntimeError(f"CA cert not found: {ca_cert}")
        log.info("Trusting upstream CA: %s (merged into certifi)", ca_cert)

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


def _merge_ca_into_certifi(ca_path: Path) -> None:
    """Append a CA certificate to certifi's bundle."""
    try:
        import certifi
        certifi_bundle = Path(certifi.where())
    except (ImportError, Exception) as exc:
        log.warning("Cannot locate certifi bundle, skipping CA merge: %s", exc)
        return

    ca_pem = ca_path.read_text().strip()
    existing = certifi_bundle.read_text()
    if ca_pem in existing:
        log.debug("CA already in certifi bundle: %s", ca_path)
        return

    with certifi_bundle.open("a") as f:
        f.write("\n" + ca_pem + "\n")
    log.info("Merged CA into certifi bundle: %s", ca_path)


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
    from .config import load_config
    full_config = load_config()
    test_config = full_config.get("test", {})
    if not test_config.get("enabled"):
        test_config = None
    else:
        log.info("Test mode enabled via config.yaml")
        # Merge test CA into certifi so mitmproxy trusts both the test
        # sinkhole certs AND real upstream certs (e.g., python.org for mise)
        test_ca = test_config.get("ca_cert")
        if test_ca:
            _merge_ca_into_certifi(Path(test_ca))

    # Build command
    cmd = _build_command(
        addons_dir=addons_dir,
        cert_dir=cert_dir,
        config_dir=config_dir,
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

    # Pass test sinkhole config to child process (read by sinkhole_router addon)
    if test_config:
        env["SAFEYOLO_SINKHOLE_HOST"] = str(test_config.get("sinkhole_host", "127.0.0.1"))
        env["SAFEYOLO_SINKHOLE_HTTP_PORT"] = str(test_config.get("sinkhole_http_port", 18080))
        env["SAFEYOLO_SINKHOLE_HTTPS_PORT"] = str(test_config.get("sinkhole_https_port", 18443))

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

    # Write PID file
    pid_file = _pid_file()
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    pid_file.write_text(str(proc.pid))

    log.info("Proxy started (PID %d) on port %d", proc.pid, proxy_port)


def stop_proxy() -> None:
    """Stop the host mitmproxy process."""
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
    import urllib.request
    import urllib.error

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
            pass
        time.sleep(1)

    return False


def get_ca_cert_path() -> Path | None:
    """Return path to the public CA cert, or None if not generated yet."""
    cert = get_config_dir() / "certs" / "mitmproxy-ca-cert.pem"
    return cert if cert.exists() else None
