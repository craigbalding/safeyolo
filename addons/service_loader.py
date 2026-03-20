"""
service_loader.py - Service definition loader for Service Gateway

Loads service definitions from YAML files, provides a registry for
looking up services by name.

Service definitions describe external APIs: their authentication
methods and route whitelists per role (access profile).

Usage:
    from service_loader import init_service_registry, get_service_registry

    init_service_registry(Path("/safeyolo/services"))
    registry = get_service_registry()
    service = registry.get_service("gmail")
"""

import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from utils import sanitize_for_log

log = logging.getLogger("safeyolo.service-loader")


@dataclass
class RouteRule:
    """A route rule within a role."""

    effect: str  # "allow" or "deny"
    methods: list[str] = field(default_factory=lambda: ["*"])
    path: str = "/*"

    @classmethod
    def from_dict(cls, d: dict) -> "RouteRule":
        methods = d.get("methods", ["*"])
        if isinstance(methods, str):
            methods = [methods]
        return cls(
            effect=d["effect"],
            methods=[m.upper() for m in methods],
            path=d.get("path", "/*"),
        )


@dataclass
class AuthConfig:
    """Authentication configuration for a service role."""

    type: str  # "bearer", "api_key"
    header: str = "Authorization"
    scheme: str = "Bearer"
    refresh_on_401: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> "AuthConfig":
        return cls(
            type=d["type"],
            header=d.get("header", "Authorization"),
            scheme=d.get("scheme", "Bearer"),
            refresh_on_401=d.get("refresh_on_401", False),
        )


@dataclass
class ServiceRole:
    """A named access profile within a service."""

    name: str
    auth: AuthConfig
    routes: list[RouteRule] = field(default_factory=list)
    require_approval: bool = False

    @classmethod
    def from_dict(cls, name: str, d: dict) -> "ServiceRole":
        auth = AuthConfig.from_dict(d["auth"])
        routes = [RouteRule.from_dict(r) for r in d.get("routes", [])]
        return cls(
            name=name,
            auth=auth,
            routes=routes,
            require_approval=d.get("require_approval", False),
        )


@dataclass
class ServiceDefinition:
    """A complete service definition (one per YAML file)."""

    name: str
    roles: dict[str, ServiceRole] = field(default_factory=dict)
    description: str = ""
    default_host: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "ServiceDefinition":
        roles = {}
        for role_name, role_config in d.get("roles", {}).items():
            roles[role_name] = ServiceRole.from_dict(role_name, role_config)
        return cls(
            name=d["name"],
            roles=roles,
            description=d.get("description", ""),
            default_host=d.get("default_host", ""),
        )


class ServiceRegistry:
    """Registry of service definitions loaded from YAML files."""

    def __init__(self, user_dir: Path, builtin_dir: Path | None = None):
        self._user_dir = user_dir
        self._builtin_dir = builtin_dir or Path("/app/services")
        self._lock = threading.RLock()
        self._services: dict[str, ServiceDefinition] = {}
        self._last_mtimes: dict[str, float] = {}
        self._watcher_thread: threading.Thread | None = None
        self._watcher_stop = threading.Event()

    def load(self) -> None:
        """Load all service definitions from user and builtin directories."""
        with self._lock:
            self._services.clear()
            self._last_mtimes.clear()

            # Load builtin first, then user (user overrides builtin)
            for directory in [self._builtin_dir, self._user_dir]:
                if not directory.exists():
                    continue
                for yaml_file in sorted(directory.glob("*.yaml")):
                    try:
                        raw = yaml.safe_load(yaml_file.read_text())
                        if not raw or not isinstance(raw, dict):
                            continue
                        service = ServiceDefinition.from_dict(raw)
                        self._services[service.name] = service
                        self._last_mtimes[str(yaml_file)] = yaml_file.stat().st_mtime
                        log.info("Loaded service: %s", sanitize_for_log(service.name))
                    except (OSError, yaml.YAMLError, KeyError, TypeError, ValueError) as e:
                        log.warning("Skipping %s: %s", yaml_file.name, sanitize_for_log(str(e)))

            log.info(f"Service registry: {len(self._services)} services loaded")

    def _has_changes(self) -> bool:
        """Check if any service file has been added, removed, or modified."""
        current_files: dict[str, float] = {}
        for directory in [self._builtin_dir, self._user_dir]:
            if not directory.exists():
                continue
            for yaml_file in directory.glob("*.yaml"):
                current_files[str(yaml_file)] = yaml_file.stat().st_mtime

        return current_files != self._last_mtimes

    def start_watcher(self) -> None:
        """Start background file watcher for service definitions."""
        if self._watcher_thread is not None:
            return

        def watch_loop():
            while not self._watcher_stop.is_set():
                try:
                    if self._has_changes():
                        log.info("Service definitions changed, reloading...")
                        self.load()
                except (OSError, yaml.YAMLError) as e:
                    log.warning("Service watcher error: %s", sanitize_for_log(str(e)))
                self._watcher_stop.wait(timeout=2.0)

        self._watcher_thread = threading.Thread(target=watch_loop, daemon=True, name="service-watcher")
        self._watcher_thread.start()
        log.info("Started service file watcher")

    def stop_watcher(self) -> None:
        """Stop file watcher."""
        if self._watcher_thread:
            self._watcher_stop.set()
            self._watcher_thread.join(timeout=2.0)
            self._watcher_thread = None
            self._watcher_stop.clear()

    def get_service(self, name: str) -> ServiceDefinition | None:
        """Get service by name."""
        with self._lock:
            return self._services.get(name)

    def list_services(self) -> list[ServiceDefinition]:
        """List all loaded services."""
        with self._lock:
            return list(self._services.values())


# Module singleton
_registry: ServiceRegistry | None = None
_registry_lock = threading.Lock()


def init_service_registry(
    user_dir: Path,
    builtin_dir: Path | None = None,
) -> ServiceRegistry:
    """Initialize and load the module-level service registry singleton."""
    global _registry
    with _registry_lock:
        _registry = ServiceRegistry(user_dir, builtin_dir)
        _registry.load()
        return _registry


def get_service_registry() -> ServiceRegistry | None:
    """Get the module-level service registry singleton."""
    return _registry
