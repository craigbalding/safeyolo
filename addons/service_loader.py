"""
service_loader.py - Service definition loader for Service Gateway v2

Loads service definitions from YAML files, provides a registry for
looking up services by name.

Service definitions describe external APIs: their authentication
methods, capabilities (named route sets), and risky routes (factual
security signals for PDP evaluation).

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
class AuthConfig:
    """Authentication configuration for a service."""

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
class CapabilityRoute:
    """A route within a capability (positive-list only, no effect field)."""

    methods: list[str]
    path: str

    @classmethod
    def from_dict(cls, d: dict) -> "CapabilityRoute":
        methods = d["methods"]
        if isinstance(methods, str):
            methods = [methods]
        return cls(
            methods=[m.upper() for m in methods],
            path=d["path"],
        )


@dataclass
class Capability:
    """A named set of allowed routes within a service."""

    name: str
    description: str = ""
    routes: list[CapabilityRoute] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, name: str, d: dict) -> "Capability":
        routes = [CapabilityRoute.from_dict(r) for r in d.get("routes", [])]
        return cls(
            name=name,
            description=d.get("description", ""),
            routes=routes,
            scopes=d.get("scopes", []),
        )


@dataclass
class RiskyRoute:
    """A single risky route with factual ATT&CK signals."""

    path: str
    methods: list[str] = field(default_factory=lambda: ["*"])
    description: str = ""
    tactics: list[str] = field(default_factory=list)
    enables: list[str] = field(default_factory=list)
    irreversible: bool = False
    group: str | None = None

    @classmethod
    def from_dict(cls, d: dict, group_defaults: dict | None = None) -> "RiskyRoute":
        gd = group_defaults or {}

        methods = d.get("methods", ["*"])
        if isinstance(methods, str):
            methods = [methods]

        # Merge tactics: union of group + route
        route_tactics = d.get("tactics", [])
        group_tactics = gd.get("tactics", [])
        tactics = list(dict.fromkeys(group_tactics + route_tactics))  # union, order preserved

        # Merge enables: union of group + route
        route_enables = d.get("enables", [])
        group_enables = gd.get("enables", [])
        enables = list(dict.fromkeys(group_enables + route_enables))

        # irreversible: route overrides group if explicitly set
        if "irreversible" in d:
            irreversible = d["irreversible"]
        else:
            irreversible = gd.get("irreversible", False)

        # description: route overrides group if present
        description = d.get("description", gd.get("description", ""))

        return cls(
            path=d["path"],
            methods=[m.upper() for m in methods],
            description=description,
            tactics=tactics,
            enables=enables,
            irreversible=irreversible,
            group=gd.get("group"),
        )


@dataclass
class RiskyRouteGroup:
    """A group of related risky routes (for watch UX)."""

    group: str
    description: str = ""
    tactics: list[str] = field(default_factory=list)
    enables: list[str] = field(default_factory=list)
    irreversible: bool = False
    routes: list[RiskyRoute] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "RiskyRouteGroup":
        group_defaults = {
            "group": d["group"],
            "description": d.get("description", ""),
            "tactics": d.get("tactics", []),
            "enables": d.get("enables", []),
            "irreversible": d.get("irreversible", False),
        }
        routes = [RiskyRoute.from_dict(r, group_defaults) for r in d.get("routes", [])]
        return cls(
            group=d["group"],
            description=d.get("description", ""),
            tactics=d.get("tactics", []),
            enables=d.get("enables", []),
            irreversible=d.get("irreversible", False),
            routes=routes,
        )


def _parse_risky_routes(raw_list: list[dict]) -> tuple[list[RiskyRoute], list[RiskyRouteGroup]]:
    """Parse risky_routes list into flat routes and groups."""
    flat_routes: list[RiskyRoute] = []
    groups: list[RiskyRouteGroup] = []

    for entry in raw_list:
        if "group" in entry:
            grp = RiskyRouteGroup.from_dict(entry)
            groups.append(grp)
            flat_routes.extend(grp.routes)
        else:
            # Ungrouped route
            flat_routes.append(RiskyRoute.from_dict(entry))

    return flat_routes, groups


@dataclass
class ServiceDefinition:
    """A complete service definition (one per YAML file, v2 schema)."""

    name: str
    schema_version: int = 1
    description: str = ""
    default_host: str = ""
    auth: AuthConfig | None = None
    capabilities: dict[str, Capability] = field(default_factory=dict)
    risky_routes: list[RiskyRoute] = field(default_factory=list)
    risky_route_groups: list[RiskyRouteGroup] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "ServiceDefinition":
        schema_version = d.get("schema_version")
        if schema_version != 1:
            raise ValueError(
                f"Unsupported schema_version: {schema_version} (expected 1)"
            )

        auth = AuthConfig.from_dict(d["auth"]) if "auth" in d else None

        capabilities = {}
        for cap_name, cap_config in d.get("capabilities", {}).items():
            capabilities[cap_name] = Capability.from_dict(cap_name, cap_config)

        risky_routes, risky_route_groups = _parse_risky_routes(
            d.get("risky_routes", [])
        )

        return cls(
            name=d["name"],
            schema_version=1,
            description=d.get("description", ""),
            default_host=d.get("default_host", ""),
            auth=auth,
            capabilities=capabilities,
            risky_routes=risky_routes,
            risky_route_groups=risky_route_groups,
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
