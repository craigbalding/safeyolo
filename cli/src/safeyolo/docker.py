"""Docker container management for SafeYolo."""

import logging
import os
import subprocess
import time
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .config import (
    CA_VOLUME_NAME,
    INTERNAL_NETWORK_NAME,
    PRIVATE_CERTS_VOLUME_NAME,
    PROXY_CONTAINER_NAME,
    get_certs_dir,
    get_config_dir,
    get_data_dir,
    get_logs_dir,
    get_policies_dir,
    get_rules_path,
    load_config,
)

log = logging.getLogger("safeyolo.docker")

# Template directory for compose files
COMPOSE_TEMPLATES_DIR = Path(__file__).parent / "templates" / "compose"

# Subprocess timeout constants (seconds)
DOCKER_BUILD_TIMEOUT_SECONDS = 300  # 5 minutes - fresh builds can be slow
DOCKER_INSPECT_TIMEOUT_SECONDS = 5  # Network/container inspect is fast
DOCKER_COMPOSE_TIMEOUT_SECONDS = 30  # Up/down/pull operations


class DockerError(Exception):
    """Docker operation failed."""

    pass


class BuildError(Exception):
    """Image build failed."""

    pass


def _run(
    args: list[str],
    check: bool = True,
    capture: bool = True,
    timeout: int = DOCKER_COMPOSE_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess:
    """Run a command and return result.

    Args:
        args: Command and arguments
        check: Raise on non-zero exit
        capture: Capture stdout/stderr
        timeout: Max seconds to wait (default: DOCKER_COMPOSE_TIMEOUT_SECONDS)
    """
    try:
        result = subprocess.run(
            args,
            check=check,
            capture_output=capture,
            text=True,
            timeout=timeout,
        )
        return result
    except subprocess.TimeoutExpired:
        raise DockerError(f"Command timed out after {timeout}s: {' '.join(args)}")
    except subprocess.CalledProcessError as err:
        raise DockerError(f"Command failed: {' '.join(args)}\n{err.stderr}")
    except FileNotFoundError:
        raise DockerError(f"Command not found: {args[0]}")


def check_docker() -> bool:
    """Check if Docker is available."""
    try:
        result = _run(["docker", "version"], check=False, timeout=DOCKER_INSPECT_TIMEOUT_SECONDS)
        return result.returncode == 0
    except DockerError:
        return False


def get_repo_root() -> Path | None:
    """Find safeyolo repo root by locating Dockerfile.

    Walks up from CLI package location to find Dockerfile.
    Returns None if not found (e.g., pip installed from PyPI).
    """
    # Start from this file's location: cli/src/safeyolo/docker.py
    current = Path(__file__).resolve().parent

    # Walk up looking for Dockerfile (max 5 levels)
    for _ in range(5):
        dockerfile = current / "Dockerfile"
        if dockerfile.exists():
            return current
        current = current.parent

    return None


def image_exists(image_name: str) -> bool:
    """Check if a Docker image exists locally."""
    result = _run(
        ["docker", "images", "-q", image_name],
        check=False,
        timeout=DOCKER_INSPECT_TIMEOUT_SECONDS,
    )
    return bool(result.stdout.strip())


def build_image(tag: str = "safeyolo:latest", quiet: bool = False) -> None:
    """Build the safeyolo Docker image from repo source.

    Args:
        tag: Image tag to build
        quiet: Suppress build output

    Raises:
        BuildError: If repo not found or build fails

    Note:
        Output is not captured so user sees build progress in terminal.
        Errors show exit code only (stderr goes to terminal).
    """
    repo_root = get_repo_root()
    if not repo_root:
        raise BuildError(
            "Cannot find safeyolo repo root (no Dockerfile found).\n"
            "If installed from PyPI, pull the image instead:\n"
            "  docker pull safeyolo:latest"
        )

    args = ["docker", "build", "-t", tag, str(repo_root)]
    if quiet:
        args.insert(2, "-q")

    try:
        # Don't capture output so user sees build progress
        subprocess.run(args, check=True, timeout=DOCKER_BUILD_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        raise BuildError(
            f"Docker build timed out after {DOCKER_BUILD_TIMEOUT_SECONDS}s.\n"
            "Check network connectivity or try: docker build --no-cache"
        )
    except subprocess.CalledProcessError as err:
        raise BuildError(f"Docker build failed (exit code {err.returncode})")


def get_container_name() -> str:
    """Get container name from config."""
    config = load_config()
    return config["proxy"].get("container_name", "safeyolo")


def is_running() -> bool:
    """Check if SafeYolo container is running."""
    name = get_container_name()
    result = _run(
        ["docker", "ps", "-q", "-f", f"name={name}"],
        check=False,
        timeout=DOCKER_INSPECT_TIMEOUT_SECONDS,
    )
    return bool(result.stdout.strip())


def get_container_status() -> dict | None:
    """Get container status details."""
    name = get_container_name()
    result = _run(
        [
            "docker", "inspect",
            "-f", "{{.State.Status}}|{{.State.Health.Status}}|{{.State.StartedAt}}",
            name,
        ],
        check=False,
        timeout=DOCKER_INSPECT_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        return None

    parts = result.stdout.strip().split("|")
    if len(parts) >= 3:
        return {
            "status": parts[0],
            "health": parts[1] if parts[1] else "none",
            "started_at": parts[2],
        }
    return None


def generate_compose(sandbox: bool = True) -> str:
    """Generate docker-compose.yml content from config using Jinja2 template.

    Args:
        sandbox: If True (default), generate Sandbox Mode with network isolation.
                 If False, generate Try Mode for evaluation.

    Both modes:
    - Use localhost-only port bindings (127.0.0.1)
    - Run as non-root (host UID/GID)
    - Use Docker volume for private key (never exposed to host)

    Sandbox Mode additionally:
    - Creates internal network for agent isolation
    - Uses Docker volume for public CA (agents mount it)
    - Includes certs-init service for volume permissions

    Try Mode:
    - Host-mounts public CA cert directory (user reads it directly)
    - No internal network (agent runs on host)
    """
    config = load_config()
    proxy = config["proxy"]
    config_dir = get_config_dir()

    # Resolve paths
    rules_path = get_rules_path()
    policy_path = config_dir / "policy.yaml"

    # Template variables
    variables = {
        "sandbox": sandbox,
        # Proxy config
        "image": proxy.get("image", "safeyolo:latest"),
        "container_name": proxy.get("container_name", "safeyolo"),
        "proxy_port": proxy.get("port", 8080),
        "admin_port": proxy.get("admin_port", 9090),
        # User (non-root execution)
        "uid": os.getuid(),
        "gid": os.getgid(),
        # Paths
        "logs_dir": get_logs_dir(),
        "certs_dir": get_certs_dir(),
        "policies_dir": get_policies_dir(),
        "data_dir": get_data_dir(),
        "rules_path": str(rules_path) if rules_path.exists() else None,
        "policy_path": str(policy_path) if policy_path.exists() else None,
        # Network constants (for sandbox mode)
        "internal_network": INTERNAL_NETWORK_NAME,
        "proxy_hostname": PROXY_CONTAINER_NAME,  # Docker DNS name for proxy
        # Volume names
        "private_certs_volume": PRIVATE_CERTS_VOLUME_NAME,
        "public_certs_volume": CA_VOLUME_NAME,
    }

    # Render template
    env = Environment(
        loader=FileSystemLoader(str(COMPOSE_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        keep_trailing_newline=True,
    )
    template = env.get_template("safeyolo.yml.j2")
    return template.render(**variables)


def write_compose_file(sandbox: bool = True) -> Path:
    """Write docker-compose.yml to config directory.

    Args:
        sandbox: If True (default), generate Sandbox Mode with network isolation.
                 If False, generate Try Mode for evaluation.
    """
    config_dir = get_config_dir(create=True)
    compose_path = config_dir / "docker-compose.yml"
    compose_path.write_text(generate_compose(sandbox=sandbox))
    return compose_path


def start(detach: bool = True, pull: bool = False, auto_build: bool = True) -> bool:
    """Start SafeYolo container.

    Args:
        detach: Run in background
        pull: Pull latest image first
        auto_build: Build image if missing (default True)

    Returns:
        True if image was built, False if it already existed
    """
    if not check_docker():
        raise DockerError("Docker is not available - please install Docker")

    config = load_config()
    image_name = config["proxy"].get("image", "safeyolo:latest")
    built = False

    # Auto-build if image doesn't exist
    if auto_build and not pull and not image_exists(image_name):
        build_image(tag=image_name)
        built = True

    sandbox = config.get("sandbox", False)
    compose_path = write_compose_file(sandbox=sandbox)

    if pull:
        _run(["docker", "compose", "-f", str(compose_path), "pull"])

    args = ["docker", "compose", "-f", str(compose_path), "up"]
    if detach:
        args.append("-d")

    _run(args)
    return built


def stop() -> None:
    """Stop SafeYolo container."""
    config_dir = get_config_dir()
    compose_path = config_dir / "docker-compose.yml"

    if not compose_path.exists():
        # Try direct docker stop
        name = get_container_name()
        _run(["docker", "stop", name], check=False)
        return

    _run(["docker", "compose", "-f", str(compose_path), "down"])


def restart() -> None:
    """Restart SafeYolo container."""
    config_dir = get_config_dir()
    compose_path = config_dir / "docker-compose.yml"

    if compose_path.exists():
        _run(["docker", "compose", "-f", str(compose_path), "restart"])
    else:
        stop()
        start()


def logs(follow: bool = False, tail: int | None = None) -> subprocess.Popen | str:
    """Get container logs.

    Args:
        follow: Stream logs continuously
        tail: Number of lines from end

    Returns:
        Popen if follow=True, else log string
    """
    name = get_container_name()
    args = ["docker", "logs"]

    if follow:
        args.append("-f")
    if tail:
        args.extend(["--tail", str(tail)])

    args.append(name)

    if follow:
        # Return process for streaming
        return subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    else:
        result = _run(args)
        return result.stdout


def wait_for_healthy(timeout: int = 30) -> bool:
    """Wait for container to become healthy.

    Args:
        timeout: Max seconds to wait

    Returns:
        True if healthy, False if timeout
    """
    start_time = time.time()
    while time.time() - start_time < timeout:
        status = get_container_status()
        if status and status.get("health") == "healthy":
            return True
        if status and status.get("status") != "running":
            return False
        time.sleep(1)
    return False


def copy_ca_cert_to_host() -> Path | None:
    """Copy CA certificate from container to host certs directory.

    In Sandbox Mode, the CA cert lives in a Docker volume. This copies it
    to the host for diagnostic use (inspecting cert, testing proxy from host).

    Returns:
        Path to copied cert, or None if copy failed.
    """
    name = get_container_name()
    certs_dir = get_certs_dir()
    certs_dir.mkdir(parents=True, exist_ok=True)

    ca_cert_path = certs_dir / "mitmproxy-ca-cert.pem"
    container_cert_path = "/certs-public/mitmproxy-ca-cert.pem"

    try:
        result = _run(
            ["docker", "cp", f"{name}:{container_cert_path}", str(ca_cert_path)],
            check=False,
            timeout=DOCKER_INSPECT_TIMEOUT_SECONDS,
        )
        if result.returncode == 0 and ca_cert_path.exists():
            return ca_cert_path
    except DockerError as exc:
        log.debug("Failed to copy CA cert from container: %s", exc)

    return None
