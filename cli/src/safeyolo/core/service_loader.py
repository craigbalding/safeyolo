"""
service_loader.py - Service definition loader for Service Gateway v2

Loads service definitions from YAML files, provides a registry for
looking up services by name.

Service definitions describe external APIs: their authentication
methods, capabilities (named route sets), and risky routes (factual
security signals for PDP evaluation).

Usage:
    from safeyolo.core.service_loader import init_service_registry, get_service_registry

    init_service_registry(Path("/safeyolo/services"))
    registry = get_service_registry()
    service = registry.get_service("gmail")
"""

import copy
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from safeyolo.core.utils import sanitize_for_log

log = logging.getLogger("safeyolo.service-loader")


@dataclass(frozen=True)
class ServiceLoadProblem:
    """One deterministic service-definition load failure."""

    path: Path
    error_type: str
    message: str


class ServiceRegistryError(RuntimeError):
    """One or more service files could not be loaded consistently."""

    def __init__(self, problems: list[ServiceLoadProblem]):
        self.problems = tuple(problems)
        detail = "; ".join(
            f"{problem.path}: {problem.error_type}: {problem.message}"
            for problem in problems
        )
        super().__init__(f"service definitions are invalid: {detail}")


@dataclass
class AuthConfig:
    """Authentication configuration for a service."""

    type: str  # "bearer", "api_key"
    header: str = "Authorization"
    scheme: str = "Bearer"
    refresh_on_401: bool = False
    # Operator opt-in: allow sgw_ credential injection over plain HTTP.
    # Only set true when the transport is trusted end-to-end by another layer
    # (tailnet / WireGuard / private VLAN / same-host loopback). Default denies
    # HTTP injection to prevent sgw_ token leakage on untrusted networks.
    allow_http: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> "AuthConfig":
        return cls(
            type=d["type"],
            header=d.get("header", "Authorization"),
            scheme=d.get("scheme", "Bearer"),
            refresh_on_401=d.get("refresh_on_401", False),
            allow_http=d.get("allow_http", False),
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


_VALID_BINDING_TYPES = {"string", "enum", "integer", "boolean", "string_list"}
_VALID_ENFORCEMENT_VALUES = {"enforced", "declared"}
_ENFORCEMENT_TIERS = [
    "request_shape",
    "transport_hygiene",
    "state_capture",
    "state_enforcement",
    "response_validators",
]


@dataclass
class ContractBinding:
    """A named variable the agent proposes and the operator approves."""

    name: str
    source: str = "agent"
    type: str = "string"
    options: list[str] = field(default_factory=list)
    pattern: str = ""
    visible_to_operator: bool = True
    required_if: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, name: str, d: dict) -> "ContractBinding":
        binding_type = d.get("type", "string")
        if binding_type not in _VALID_BINDING_TYPES:
            raise ValueError(
                f"Invalid binding type '{binding_type}' for '{name}'. "
                f"Must be one of: {', '.join(sorted(_VALID_BINDING_TYPES))}"
            )
        options = d.get("options", [])
        if binding_type == "enum" and not options:
            raise ValueError(
                f"Enum binding '{name}' must have non-empty 'options'"
            )
        return cls(
            name=name,
            source=d.get("source", "agent"),
            type=binding_type,
            options=options,
            pattern=d.get("pattern", ""),
            visible_to_operator=d.get("visible_to_operator", True),
            required_if=d.get("required_if", {}),
        )


@dataclass
class TransportConstraint:
    """HTTP transport-level constraints for an operation."""

    require_no_body: bool = False
    allow_headers: list[str] = field(default_factory=list)
    deny_ambiguous_encoding: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> "TransportConstraint":
        return cls(
            require_no_body=d.get("require_no_body", False),
            allow_headers=d.get("allow_headers", []),
            deny_ambiguous_encoding=d.get("deny_ambiguous_encoding", False),
        )


@dataclass
class QueryConstraint:
    """Constraint on a single query parameter."""

    equals_var: str = ""
    integer_range: list[int] = field(default_factory=list)
    type: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "QueryConstraint":
        return cls(
            equals_var=d.get("equals_var", ""),
            integer_range=d.get("integer_range", []),
            type=d.get("type", ""),
        )


@dataclass
class BodyConstraint:
    """Constraint on a single body field."""

    type: str = "string"
    equals_var: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "BodyConstraint":
        return cls(
            type=d.get("type", "string"),
            equals_var=d.get("equals_var", ""),
        )


@dataclass
class PathParamConstraint:
    """Constraint on a path parameter."""

    in_state_set: str = ""
    equals_var: str = ""
    type: str = "string"

    @classmethod
    def from_dict(cls, d: dict) -> "PathParamConstraint":
        return cls(
            in_state_set=d.get("in_state_set", ""),
            equals_var=d.get("equals_var", ""),
            type=d.get("type", "string"),
        )


@dataclass
class ContractOperation:
    """An allowed request shape within a contract."""

    name: str
    method: str = "GET"
    path: str = ""
    transport: TransportConstraint | None = None
    query_allow: dict[str, QueryConstraint] = field(default_factory=dict)
    query_deny_unknown: bool = True
    body_allow: dict[str, BodyConstraint] = field(default_factory=dict)
    body_deny_unknown: bool = True
    path_params: dict[str, PathParamConstraint] = field(default_factory=dict)
    requires_enforcement: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "ContractOperation":
        req = d.get("request", {})
        transport = None
        if "transport" in req:
            transport = TransportConstraint.from_dict(req["transport"])

        query_allow = {}
        query_section = req.get("query", {})
        for param_name, constraint in query_section.get("allow", {}).items():
            query_allow[param_name] = QueryConstraint.from_dict(constraint)
        query_deny_unknown = query_section.get("deny_unknown", True)

        body_allow = {}
        body_section = req.get("body", {})
        for field_name, constraint in body_section.get("allow", {}).items():
            body_allow[field_name] = BodyConstraint.from_dict(constraint)
        body_deny_unknown = body_section.get("deny_unknown", True)

        path_params = {}
        for param_name, constraint in req.get("path_params", {}).items():
            path_params[param_name] = PathParamConstraint.from_dict(constraint)

        requires_enforcement = d.get("requires_enforcement", "")
        if requires_enforcement and requires_enforcement not in _ENFORCEMENT_TIERS:
            raise ValueError(
                f"requires_enforcement '{requires_enforcement}' is not a valid tier. "
                f"Must be one of: {', '.join(_ENFORCEMENT_TIERS)}"
            )

        return cls(
            name=d["name"],
            method=req.get("method", "GET"),
            path=req.get("path", ""),
            transport=transport,
            query_allow=query_allow,
            query_deny_unknown=query_deny_unknown,
            body_allow=body_allow,
            body_deny_unknown=body_deny_unknown,
            path_params=path_params,
            requires_enforcement=requires_enforcement,
        )


@dataclass
class EnforcementStatus:
    """Enforcement status for each tier."""

    request_shape: str = "declared"
    transport_hygiene: str = "declared"
    state_capture: str = "declared"
    state_enforcement: str = "declared"
    response_validators: str = "declared"

    @classmethod
    def from_dict(cls, d: dict) -> "EnforcementStatus":
        for key in _ENFORCEMENT_TIERS:
            val = d.get(key, "declared")
            if val not in _VALID_ENFORCEMENT_VALUES:
                raise ValueError(
                    f"Enforcement value '{val}' for '{key}' must be 'enforced' or 'declared'"
                )
        return cls(
            request_shape=d.get("request_shape", "declared"),
            transport_hygiene=d.get("transport_hygiene", "declared"),
            state_capture=d.get("state_capture", "declared"),
            state_enforcement=d.get("state_enforcement", "declared"),
            response_validators=d.get("response_validators", "declared"),
        )

    def get_tier_status(self, tier: str) -> str:
        return getattr(self, tier, "declared")


@dataclass
class ContractTemplate:
    """Full contract template attached to a capability."""

    template: str
    bindings: dict[str, ContractBinding] = field(default_factory=dict)
    operations: list[ContractOperation] = field(default_factory=list)
    enforcement: EnforcementStatus = field(default_factory=EnforcementStatus)
    state: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "ContractTemplate":
        bindings = {}
        for name, bdef in d.get("bindings", {}).items():
            bindings[name] = ContractBinding.from_dict(name, bdef)

        operations = [ContractOperation.from_dict(op) for op in d.get("operations", [])]

        enforcement = EnforcementStatus.from_dict(d.get("enforcement", {}))

        return cls(
            template=d.get("template", ""),
            bindings=bindings,
            operations=operations,
            enforcement=enforcement,
            state=d.get("state", {}),
        )

    def grantable_operations(self) -> list[ContractOperation]:
        """Operations whose requires_enforcement tier is enforced (or absent → request_shape)."""
        result = []
        for op in self.operations:
            tier = op.requires_enforcement or "request_shape"
            if self.enforcement.get_tier_status(tier) == "enforced":
                result.append(op)
        return result

    @property
    def is_grantable(self) -> bool:
        return len(self.grantable_operations()) > 0

    def ungrantable_tiers(self) -> list[str]:
        """Tier names blocking grantability for excluded operations."""
        tiers: list[str] = []
        seen: set[str] = set()
        for op in self.operations:
            tier = op.requires_enforcement or "request_shape"
            if self.enforcement.get_tier_status(tier) != "enforced" and tier not in seen:
                tiers.append(tier)
                seen.add(tier)
        return tiers

    def match_operation(self, method: str, path: str) -> ContractOperation | None:
        """Match request against grantable operations. Exact path > parameterized > glob."""
        grantable = self.grantable_operations()
        best: ContractOperation | None = None
        best_specificity = -1

        for op in grantable:
            if op.method.upper() != method.upper():
                continue
            specificity = _path_match_specificity(path, op.path)
            if specificity > best_specificity:
                best = op
                best_specificity = specificity

        return best


def _path_match_specificity(actual: str, template: str) -> int:
    """Match actual path against template. Returns specificity score or -1 for no match.

    Scores: 2 = exact match, 1 = parameterized match, 0 = glob match, -1 = no match.
    """
    actual_parts = [p for p in actual.strip("/").split("/") if p]
    template_parts = [p for p in template.strip("/").split("/") if p]

    if not template_parts and not actual_parts:
        return 2

    # Check segment by segment
    has_param = False
    for i, t_seg in enumerate(template_parts):
        if t_seg == "*" or t_seg == "**":
            # Glob: matches rest
            return 0
        if i >= len(actual_parts):
            return -1
        if t_seg.startswith("{") and t_seg.endswith("}"):
            has_param = True
            continue
        if t_seg != actual_parts[i]:
            return -1

    if len(actual_parts) != len(template_parts):
        return -1

    return 1 if has_param else 2


@dataclass
class Capability:
    """A named set of allowed routes within a service."""

    name: str
    description: str = ""
    routes: list[CapabilityRoute] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    contract: ContractTemplate | None = None

    @classmethod
    def from_dict(cls, name: str, d: dict) -> "Capability":
        routes = [CapabilityRoute.from_dict(r) for r in d.get("routes", [])]
        contract = None
        if "contract" in d:
            contract = ContractTemplate.from_dict(d["contract"])
        return cls(
            name=name,
            description=d.get("description", ""),
            routes=routes,
            scopes=d.get("scopes", []),
            contract=contract,
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
    raw: dict = field(default_factory=dict, repr=False, compare=False)

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
            raw=copy.deepcopy(d),
        )

    def to_dict(self) -> dict:
        """Return the schema document validated to create this definition."""
        return copy.deepcopy(self.raw)


class ServiceRegistry:
    """Registry of service definitions loaded from YAML files."""

    def __init__(
        self,
        user_dir: Path,
        builtin_dir: Path | None = None,
        *,
        require_builtin: bool = False,
    ):
        from safeyolo.core.service_paths import resolve_service_directories

        directories = resolve_service_directories(user_dir, builtin_dir)
        self._user_dir = directories.user
        self._builtin_dir = directories.builtin
        self._require_builtin = require_builtin
        self._lock = threading.RLock()
        self._services: dict[str, ServiceDefinition] = {}
        self._last_file_state: dict[str, tuple[int, int]] = {}
        self._last_errors: tuple[ServiceLoadProblem, ...] = ()
        self._reload_callbacks: list[Callable[[], None]] = []
        self._watcher_thread: threading.Thread | None = None
        self._watcher_stop = threading.Event()

    @property
    def directories(self) -> tuple[Path, Path]:
        """Return builtin and user directories in effective precedence order."""
        return (self._builtin_dir, self._user_dir)

    @property
    def last_errors(self) -> tuple[ServiceLoadProblem, ...]:
        """Return errors from the most recent attempted load."""
        with self._lock:
            return self._last_errors

    def _audit_problem(self, problem: ServiceLoadProblem) -> None:
        try:
            from safeyolo.core.audit_schema import EventKind, Severity
            from safeyolo.core.utils import write_event

            write_event(
                "ops.config_error",
                kind=EventKind.OPS,
                severity=Severity.MEDIUM,
                summary=f"Service definition {problem.path.name} failed to load",
                addon="service-loader",
                details={
                    "file": problem.path.name,
                    "error_type": problem.error_type,
                    "error": sanitize_for_log(problem.message),
                },
            )
        except Exception as audit_error:
            # Audit failure must not hide the original configuration problem.
            log.debug(
                "Config-error audit event failed (%s)",
                type(audit_error).__name__,
            )

    def _scan_file_state(self) -> dict[str, tuple[int, int]]:
        state: dict[str, tuple[int, int]] = {}
        for directory in self.directories:
            if not directory.is_dir():
                continue
            for yaml_file in sorted(directory.glob("*.yaml")):
                try:
                    stat = yaml_file.stat()
                except OSError:
                    continue
                state[str(yaml_file)] = (stat.st_mtime_ns, stat.st_size)
        return state

    def load(self, *, strict: bool = False) -> None:
        """Atomically load builtin then user definitions.

        In strict mode any malformed or duplicate definition rejects the whole
        candidate set. The previous live registry remains intact, so the policy
        compiler and request path can never observe a half-reloaded schema.
        """
        services: dict[str, ServiceDefinition] = {}
        problems: list[ServiceLoadProblem] = []
        file_state = self._scan_file_state()

        if self._require_builtin and not self._builtin_dir.is_dir():
            problems.append(
                ServiceLoadProblem(
                    self._builtin_dir,
                    "FileNotFoundError",
                    "packaged builtin service directory is missing",
                )
            )

        for directory in self.directories:
            if directory.exists() and not directory.is_dir():
                problems.append(
                    ServiceLoadProblem(
                        directory,
                        "NotADirectoryError",
                        "service source is not a directory",
                    )
                )
                continue

            names_in_source: dict[str, Path] = {}
            if not directory.is_dir():
                continue
            for yaml_file in sorted(directory.glob("*.yaml")):
                try:
                    raw = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
                    if raw is None:
                        raise ValueError("service definition is empty")
                    if not isinstance(raw, dict):
                        raise TypeError("service definition must be a YAML mapping")
                    service = ServiceDefinition.from_dict(raw)
                    previous = names_in_source.get(service.name)
                    if previous is not None:
                        raise ValueError(
                            f"duplicate service name {service.name!r} in "
                            f"{previous.name} and {yaml_file.name}"
                        )
                    names_in_source[service.name] = yaml_file
                    services[service.name] = service
                    log.info("Loaded service: %s", sanitize_for_log(service.name))
                except (
                    OSError,
                    yaml.YAMLError,
                    AttributeError,
                    KeyError,
                    TypeError,
                    ValueError,
                ) as error:
                    problem = ServiceLoadProblem(
                        yaml_file,
                        type(error).__name__,
                        str(error),
                    )
                    problems.append(problem)
                    log.error(
                        "Service definition failed: %s: %s",
                        yaml_file,
                        sanitize_for_log(str(error)),
                    )
                    self._audit_problem(problem)

        with self._lock:
            self._last_file_state = file_state
            self._last_errors = tuple(problems)
            if strict and problems:
                raise ServiceRegistryError(problems)
            self._services = services

        log.info("Service registry: %d services loaded", len(services))

    def _has_changes(self) -> bool:
        """Check if any service file has been added, removed, or modified."""
        return self._scan_file_state() != self._last_file_state

    def add_reload_callback(self, callback: Callable[[], None]) -> None:
        """Run ``callback`` only after a complete strict reload succeeds."""
        self._reload_callbacks.append(callback)

    def reload_if_changed(self) -> bool:
        """Atomically reload definitions and their policy consumer if changed."""
        if not self._has_changes():
            return False

        with self._lock:
            previous_services = self._services
            # Keep registry readers behind this re-entrant lock until every
            # consumer has committed the same candidate. Compiler callbacks
            # can still resolve services from this thread through the RLock.
            self.load(strict=True)
            callbacks = tuple(self._reload_callbacks)
            try:
                for callback in callbacks:
                    callback()
            except Exception:
                # Registry and compiled policy are one transaction. Restore
                # the previous definitions, then recompile against them before
                # the failed candidate is reported.
                self._services = previous_services
                for callback in callbacks:
                    callback()
                raise
        return True

    def start_watcher(self) -> None:
        """Start background file watcher for service definitions."""
        if self._watcher_thread is not None:
            return

        def watch_loop():
            while not self._watcher_stop.is_set():
                try:
                    if self._has_changes():
                        log.info("Service definitions changed, reloading...")
                        self.reload_if_changed()
                except (OSError, yaml.YAMLError, ServiceRegistryError) as e:
                    log.error("Service watcher reload failed: %s", sanitize_for_log(str(e)))
                except Exception as e:
                    log.error(
                        "Service watcher policy synchronization failed: %s",
                        sanitize_for_log(str(e)),
                    )
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


def _swap_service_registry(
    candidate: ServiceRegistry | None,
    *,
    stop_previous: bool,
) -> ServiceRegistry | None:
    """Install ``candidate`` and return the prior process registry."""
    global _registry
    with _registry_lock:
        previous = _registry
        _registry = candidate
    if stop_previous and previous is not None and previous is not candidate:
        previous.stop_watcher()
    return previous


def init_service_registry(
    user_dir: Path,
    builtin_dir: Path | None = None,
    *,
    strict: bool = True,
    require_builtin: bool = False,
) -> ServiceRegistry:
    """Initialize and load the module-level service registry singleton."""
    candidate = ServiceRegistry(
        user_dir,
        builtin_dir,
        require_builtin=require_builtin,
    )
    candidate.load(strict=strict)
    _swap_service_registry(candidate, stop_previous=True)
    return candidate


def get_service_registry() -> ServiceRegistry | None:
    """Get the module-level service registry singleton."""
    return _registry
