"""
policy_compiler.py - Compile host-centric policy YAML to IAM permission rules.


Converts the user-friendly host-centric format:

    hosts:
      api.openai.com: { credentials: [openai:*], rate_limit: 3000 }

Into the IAM-style permissions the PolicyEngine evaluates:

    permissions:
      - action: credential:use
        resource: "api.openai.com/*"
        effect: allow
        condition: { credential: ["openai:*"] }
      - action: network:request
        resource: "api.openai.com/*"
        effect: budget
        budget: 3000

The host-centric format is the user-facing serialization.
The IAM format is the internal evaluation model.
"""

import logging
import secrets
from pathlib import Path
from typing import Any

from utils import sanitize_for_log

log = logging.getLogger("safeyolo.policy-compiler")


def is_host_centric(raw: dict) -> bool:
    """Check if a raw policy dict uses the host-centric format."""
    return "hosts" in raw


def compile_policy(raw: dict) -> dict:
    """Compile host-centric policy YAML into IAM-format dict.

    Takes the user-friendly format and produces a dict that
    UnifiedPolicy.model_validate() can consume directly.

    Args:
        raw: Parsed YAML dict with host-centric format

    Returns:
        Dict in IAM format ready for UnifiedPolicy validation
    """
    result: dict[str, Any] = {}

    # Pass through metadata
    if "metadata" in raw:
        result["metadata"] = raw["metadata"]

    permissions: list[dict] = []
    domains: dict[str, Any] = {}
    host_map: dict[str, str] = {}

    # --- Compile hosts → permissions + domains ---
    hosts = raw.get("hosts", {})
    for host_pattern, config in hosts.items():
        if config is None:
            config = {}

        # Scalar shorthand: { rate_limit: 3000 } or full dict
        if not isinstance(config, dict):
            log.warning("Skipping host %s: config is not a dict", sanitize_for_log(host_pattern))
            continue

        # Wildcard host gets special handling
        if host_pattern == "*":
            _compile_wildcard(config, permissions)
            continue

        resource = f"{host_pattern}/*"

        # Credential routing
        if "credentials" in config:
            creds = config["credentials"]
            if isinstance(creds, str):
                creds = [creds]
            permissions.append(
                {
                    "action": "credential:use",
                    "resource": resource,
                    "effect": "allow",
                    "tier": "explicit",
                    "condition": {"credential": creds},
                }
            )

        # Egress control (per-host deny/prompt)
        egress = config.get("egress")
        if egress == "deny":
            permissions.append(
                {
                    "action": "network:request",
                    "resource": resource,
                    "effect": "deny",
                    "tier": "explicit",
                }
            )

        # Rate limiting
        if "rate_limit" in config:
            permissions.append(
                {
                    "action": "network:request",
                    "resource": resource,
                    "effect": "budget",
                    "budget": config["rate_limit"],
                    "tier": "explicit",
                }
            )

        # Domain bypass
        if "bypass" in config:
            domains[host_pattern] = {"bypass": config["bypass"]}

        # Domain addon overrides
        if "addons" in config:
            domains.setdefault(host_pattern, {})["addons"] = config["addons"]

        # Service binding (host → service name for gateway)
        if "service" in config:
            host_map[host_pattern] = config["service"]

        # Raw IAM rules passthrough (escape hatch)
        if "rules" in config:
            for rule in config["rules"]:
                permissions.append(rule)

    result["permissions"] = permissions

    if domains:
        # Merge with any explicit domains section
        explicit_domains = raw.get("domains", {})
        merged = {**explicit_domains, **domains}
        result["domains"] = merged
    elif "domains" in raw:
        result["domains"] = raw["domains"]

    # --- Global budget ---
    if "global_budget" in raw:
        result["budgets"] = {"network:request": raw["global_budget"]}
    elif "budgets" in raw:
        result["budgets"] = raw["budgets"]

    # --- Credential detection rules ---
    if "credentials" in raw:
        result["credential_rules"] = _compile_credentials(raw["credentials"], hosts)
    elif "credential_rules" in raw:
        result["credential_rules"] = raw["credential_rules"]

    # --- Pass through remaining sections ---
    for key in ("required", "scan_patterns", "addons", "clients"):
        if key in raw:
            result[key] = raw[key]

    # Risk appetite → gateway:risky_route permissions
    gateway_section = raw.get("gateway", {})
    if isinstance(gateway_section, dict) and "risk_appetite" in gateway_section:
        _compile_risk_appetite(gateway_section["risk_appetite"], permissions)

    # Per-agent hosts → permissions with agent condition
    _compile_agent_hosts(raw.get("agents", {}), permissions, domains)

    # Services + agents section → gateway token map + capability route permissions
    if "services" in raw or "agents" in raw:
        gateway = compile_gateway(raw, host_map=host_map, permissions=permissions)
        result["gateway"] = gateway
    elif host_map:
        # host_map exists but no agents — still store it for gateway
        result["gateway"] = {"token_map": {}, "agent_env": {}, "host_map": host_map}

    # Pass through grant_ttl_seconds from gateway section
    if isinstance(gateway_section, dict) and "grant_ttl_seconds" in gateway_section:
        result.setdefault("gateway", {})["grant_ttl_seconds"] = gateway_section["grant_ttl_seconds"]

    log.info(f"Compiled host-centric policy: {len(hosts)} hosts → {len(permissions)} permissions")
    return result


def _compile_wildcard(config: dict, permissions: list[dict]) -> None:
    """Compile the wildcard host entry into default permissions."""
    # Unknown credentials handling
    unknown_creds = config.get("unknown_credentials", config.get("credentials"))
    if unknown_creds == "prompt":
        permissions.append(
            {
                "action": "credential:use",
                "resource": "*",
                "effect": "prompt",
                "tier": "explicit",
            }
        )
    elif unknown_creds == "deny":
        permissions.append(
            {
                "action": "credential:use",
                "resource": "*",
                "effect": "deny",
                "tier": "explicit",
            }
        )

    # Egress posture (network-level access control for unlisted hosts)
    egress = config.get("egress")
    if egress == "prompt":
        permissions.append(
            {
                "action": "network:request",
                "resource": "*",
                "effect": "prompt",
                "tier": "explicit",
            }
        )
    elif egress == "deny":
        permissions.append(
            {
                "action": "network:request",
                "resource": "*",
                "effect": "deny",
                "tier": "explicit",
            }
        )
    # egress = "allow" or absent → default-allow behaviour, no permission needed

    # Default rate limit
    if "rate_limit" in config:
        permissions.append(
            {
                "action": "network:request",
                "resource": "*",
                "effect": "budget",
                "budget": config["rate_limit"],
                "tier": "explicit",
            }
        )

    # Raw rules passthrough
    if "rules" in config:
        for rule in config["rules"]:
            permissions.append(rule)


def _compile_agent_hosts(
    agents: dict[str, Any],
    permissions: list[dict],
    domains: dict[str, Any],
) -> None:
    """Compile per-agent host entries into permissions with agent conditions.

    Each agents.<name>.hosts entry compiles identically to a proxy-wide host
    entry, but with an additional condition.agent = name.
    """
    for agent_name, agent_config in agents.items():
        if not isinstance(agent_config, dict):
            continue

        # Agent-level default egress posture (catch-all for this agent)
        agent_egress = agent_config.get("egress")
        if agent_egress in ("deny", "prompt"):
            permissions.append(
                {
                    "action": "network:request",
                    "resource": "*",
                    "effect": agent_egress,
                    "tier": "explicit",
                    "condition": {"agent": agent_name},
                }
            )

        agent_hosts = agent_config.get("hosts", {})
        for host_pattern, config in agent_hosts.items():
            if config is None:
                config = {}
            if not isinstance(config, dict):
                continue

            resource = f"{host_pattern}/*"

            # Egress control (per-host deny/prompt for this agent)
            egress = config.get("egress")
            if egress in ("deny", "prompt"):
                permissions.append(
                    {
                        "action": "network:request",
                        "resource": resource,
                        "effect": egress,
                        "tier": "explicit",
                        "condition": {"agent": agent_name},
                    }
                )

            # Rate limiting
            if "rate_limit" in config:
                permissions.append(
                    {
                        "action": "network:request",
                        "resource": resource,
                        "effect": "budget",
                        "budget": config["rate_limit"],
                        "tier": "explicit",
                        "condition": {"agent": agent_name},
                    }
                )

            # Credential routing
            if "credentials" in config:
                creds = config["credentials"]
                if isinstance(creds, str):
                    creds = [creds]
                permissions.append(
                    {
                        "action": "credential:use",
                        "resource": resource,
                        "effect": "allow",
                        "tier": "explicit",
                        "condition": {"credential": creds, "agent": agent_name},
                    }
                )

            # Domain bypass
            if "bypass" in config:
                domains[host_pattern] = {"bypass": config["bypass"]}


def _compile_credentials(
    credentials: dict[str, Any],
    hosts: dict[str, Any],
) -> list[dict]:
    """Compile credential detection rules.

    Auto-derives allowed_hosts from the hosts section:
    if api.openai.com has credentials: [openai:*], then
    the openai credential rule gets api.openai.com as an allowed host.

    Args:
        credentials: Dict of credential name → config
        hosts: Dict of host patterns → config (for deriving allowed_hosts)

    Returns:
        List of credential rule dicts for UnifiedPolicy
    """
    rules = []
    for name, config in credentials.items():
        if not isinstance(config, dict):
            continue

        rule: dict[str, Any] = {"name": name}

        # Patterns (required)
        if "patterns" in config:
            rule["patterns"] = config["patterns"]
        else:
            log.warning("Credential %s has no patterns, skipping", sanitize_for_log(name))
            continue

        # Headers
        if "headers" in config:
            rule["header_names"] = config["headers"]

        # Allowed hosts: explicit or auto-derived from hosts section
        if "allowed_hosts" in config:
            rule["allowed_hosts"] = config["allowed_hosts"]
        else:
            # Auto-derive from hosts that accept this credential type
            allowed = []
            for host_pattern, hcfg in hosts.items():
                if host_pattern == "*" or not isinstance(hcfg, dict):
                    continue
                host_creds = hcfg.get("credentials", [])
                if isinstance(host_creds, str):
                    host_creds = [host_creds]
                if f"{name}:*" in host_creds or name in host_creds:
                    # Strip trailing /* if present
                    clean_host = host_pattern.rstrip("/*") if "/" in host_pattern else host_pattern
                    allowed.append(clean_host)
            rule["allowed_hosts"] = allowed

        if "suggested_url" in config:
            rule["suggested_url"] = config["suggested_url"]

        rules.append(rule)

    return rules


def _compile_risk_appetite(rules: list[dict], permissions: list[dict]) -> None:
    """Compile gateway.risk_appetite rules into gateway:risky_route permissions.

    Maps: decision: allow → effect: allow, decision: require_approval → effect: prompt,
    decision: deny → effect: deny.
    """
    decision_map = {
        "allow": "allow",
        "require_approval": "prompt",
        "deny": "deny",
    }

    for rule in rules:
        decision = rule.get("decision", "require_approval")
        effect = decision_map.get(decision, "prompt")

        condition: dict[str, Any] = {}
        if "tactics" in rule:
            condition["tactics"] = rule["tactics"]
        if "enables" in rule:
            condition["enables"] = rule["enables"]
        if "irreversible" in rule:
            condition["irreversible"] = rule["irreversible"]
        if "account" in rule:
            condition["account"] = rule["account"]
        if "agent" in rule:
            condition["agent"] = rule["agent"]
        if "service" in rule:
            condition["service"] = rule["service"]

        perm: dict[str, Any] = {
            "action": "gateway:risky_route",
            "resource": "*",
            "effect": effect,
            "tier": "explicit",
        }
        if condition:
            perm["condition"] = condition

        permissions.append(perm)


def mint_gateway_token() -> str:
    """Generate a new gateway token (sgw_ prefix + 64 hex chars)."""
    return f"sgw_{secrets.token_hex(32)}"


def compile_gateway(
    raw: dict,
    services_dir: str | Path | None = None,
    host_map: dict[str, str] | None = None,
    permissions: list[dict] | None = None,
) -> dict:
    """Compile gateway configuration from services/agents sections.

    Reads agents section, resolves service references, mints tokens.
    When permissions list is provided, also compiles capability routes
    into gateway:request permissions.

    Policy format:
        agents:
          agent-name:
            services:
              service-name:
                capability: capability-name
                token: vault-credential-name
                account: agent  # optional persona

    Args:
        raw: Parsed policy YAML dict
        services_dir: Path to service definitions directory
        host_map: Host-to-service binding map
        permissions: If provided, gateway:request permissions are appended here

    Returns:
        Dict with token_map and agent_env:
        {
            "token_map": {sgw_token: {"agent": ..., "service": ..., "capability": ..., "token": ..., "account": ...}},
            "agent_env": {agent_name: {service_name: token}},
        }
    """
    agents = raw.get("agents", {})
    if not agents:
        return {"token_map": {}, "agent_env": {}, "host_map": host_map or {}}

    token_map: dict[str, dict[str, str]] = {}
    agent_env: dict[str, dict[str, str]] = {}

    for agent_name, agent_config in agents.items():
        if not isinstance(agent_config, dict):
            log.warning("Skipping agent %s: config is not a dict", sanitize_for_log(agent_name))
            continue

        agent_services = agent_config.get("services", {})
        if not isinstance(agent_services, dict):
            log.warning("Skipping agent %s: services is not a dict", sanitize_for_log(agent_name))
            continue

        agent_env[agent_name] = {}
        for service_name, service_config in agent_services.items():
            # Accept both dict format and legacy string format
            if isinstance(service_config, str):
                # Legacy: minifuse: reader (no vault token specified)
                capability_name = service_config
                vault_token = ""
                account = "agent"
            elif isinstance(service_config, dict):
                # v2: capability field (preferred), fall back to role for compat
                capability_name = service_config.get("capability", service_config.get("role", ""))
                vault_token = service_config.get("token", "")
                account = service_config.get("account", "agent")
            else:
                log.warning(
                    "Skipping service %s for agent %s: invalid config",
                    sanitize_for_log(service_name),
                    sanitize_for_log(agent_name),
                )
                continue

            if not capability_name:
                log.warning(
                    "Skipping service %s for agent %s: no capability specified",
                    sanitize_for_log(service_name),
                    sanitize_for_log(agent_name),
                )
                continue

            sgw_token = mint_gateway_token()
            token_map[sgw_token] = {
                "agent": agent_name,
                "service": service_name,
                "capability": capability_name,
                "token": vault_token,
                "account": account,
            }
            agent_env[agent_name][service_name] = sgw_token

    # Compile capability routes into gateway:request permissions
    if permissions is not None:
        _compile_capability_routes(token_map, agents, permissions)

    log.info(f"Compiled gateway: {len(agents)} agents, {len(token_map)} tokens minted")
    return {"token_map": token_map, "agent_env": agent_env, "host_map": host_map or {}}


def _get_service_registry():
    """Get the ServiceRegistry for compilation. Returns None if not initialized."""
    from service_loader import get_service_registry

    return get_service_registry()


def _compile_capability_routes(
    token_map: dict[str, dict],
    agents_raw: dict,
    permissions: list[dict],
) -> None:
    """Compile capability routes into gateway:request permissions.

    Uses the ServiceRegistry singleton to look up service definitions.

    For each agent/service/capability grant, resolves routes into permissions:
    - No contract: emit raw capability routes
    - Contract with binding: resolve operations using bound_values
    - Contract without binding: skip (no permissions, PDP denies)

    Args:
        token_map: Compiled token map (agent → service bindings)
        agents_raw: Raw agents section from policy
        permissions: List to append gateway:request permissions to
    """
    registry = _get_service_registry()
    if registry is None:
        return

    # Build set of (agent, service, capability) from token_map
    agent_grants: dict[str, dict[str, str]] = {}  # agent → {service → capability}
    for binding in token_map.values():
        agent = binding["agent"]
        service = binding["service"]
        capability = binding["capability"]
        agent_grants.setdefault(agent, {})[service] = capability

    for agent_name, service_map in agent_grants.items():
        # Get contract bindings for this agent from agents_raw
        agent_data = agents_raw.get(agent_name, {})
        if not isinstance(agent_data, dict):
            continue

        contract_bindings = agent_data.get("contract_bindings", [])

        for service_name, capability_name in service_map.items():
            service_def = registry.get_service(service_name)
            if service_def is None:
                continue

            capability = service_def.capabilities.get(capability_name)
            if capability is None:
                log.warning(
                    "Capability %s not found in service %s during compilation",
                    sanitize_for_log(capability_name),
                    sanitize_for_log(service_name),
                )
                continue

            if capability.contract is None:
                # Case 1: No contract — emit raw routes
                for route in capability.routes:
                    methods = route.methods if route.methods != ["*"] else ["*"]
                    permissions.append(
                        {
                            "action": "gateway:request",
                            "resource": f"{service_name}:{route.path}",
                            "effect": "allow",
                            "tier": "explicit",
                            "condition": {
                                "agent": agent_name,
                                "capability": capability_name,
                                "method": methods,
                            },
                        }
                    )
            else:
                # Case 2/3: Contract — find matching binding
                binding = _find_contract_binding(
                    contract_bindings,
                    service_name,
                    capability_name,
                    capability.contract.template,
                )
                if binding is None:
                    # Case 3: No binding yet → no permissions emitted
                    continue

                # Case 2: Binding found — resolve grantable operations
                bound_values = binding.get("bound_values", {})
                for op_name in binding.get("grantable_operations", []):
                    operation = _find_operation(capability.contract, op_name)
                    if operation is None:
                        continue
                    resolved_path = _resolve_path(operation, bound_values)
                    permissions.append(
                        {
                            "action": "gateway:request",
                            "resource": f"{service_name}:{resolved_path}",
                            "effect": "allow",
                            "tier": "explicit",
                            "condition": {
                                "agent": agent_name,
                                "capability": capability_name,
                                "method": [operation.method.upper()],
                            },
                        }
                    )


def _find_contract_binding(bindings: list[dict], service: str, capability: str, template: str) -> dict | None:
    """Find a matching contract binding for a service/capability/template."""
    for b in bindings:
        if b.get("service") == service and b.get("capability") == capability and b.get("template", "") == template:
            return b
    return None


def _find_operation(contract, op_name: str):
    """Find an operation by name in a contract template."""
    for op in contract.operations:
        if op.name == op_name:
            return op
    return None


def _resolve_path(operation, bound_values: dict) -> str:
    """Resolve path template parameters using bound values.

    For each {param} in the operation path, looks up the param's equals_var
    in path_params, then resolves the var from bound_values.

    Example:
        path: /v1/categories/{id}/feeds
        path_params: {id: {equals_var: approved_category_id}}
        bound_values: {approved_category_id: 137}
        → /v1/categories/137/feeds
    """
    path = operation.path
    if not operation.path_params:
        return path

    for param_name, constraint in operation.path_params.items():
        placeholder = f"{{{param_name}}}"
        if placeholder not in path:
            continue

        var_name = getattr(constraint, "equals_var", None)
        if var_name and var_name in bound_values:
            path = path.replace(placeholder, str(bound_values[var_name]))

    return path


def decompile_approval(destination: str, cred_ids: list[str]) -> dict:
    """Create a host-centric entry for a credential approval.

    Used when saving incremental approvals back to the host-centric file.

    Args:
        destination: Host pattern (e.g., "api.example.com")
        cred_ids: Credential identifiers (e.g., ["hmac:a1b2c3"])

    Returns:
        Dict suitable for inserting into the hosts section
    """
    return {"credentials": cred_ids}
