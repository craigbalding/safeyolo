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
            permissions.append({
                "action": "credential:use",
                "resource": resource,
                "effect": "allow",
                "tier": "explicit",
                "condition": {"credential": creds},
            })

        # Rate limiting
        if "rate_limit" in config:
            permissions.append({
                "action": "network:request",
                "resource": resource,
                "effect": "budget",
                "budget": config["rate_limit"],
                "tier": "explicit",
            })

        # Domain bypass
        if "bypass" in config:
            domains[host_pattern] = {"bypass": config["bypass"]}

        # Domain addon overrides
        if "addons" in config:
            domains.setdefault(host_pattern, {})["addons"] = config["addons"]

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

    # Services section (future: gateway addons) - store for later
    if "services" in raw:
        result.setdefault("metadata", {})
        if isinstance(result["metadata"], dict):
            result["metadata"]["_services"] = raw["services"]

    log.info(
        f"Compiled host-centric policy: {len(hosts)} hosts → "
        f"{len(permissions)} permissions"
    )
    return result


def _compile_wildcard(config: dict, permissions: list[dict]) -> None:
    """Compile the wildcard host entry into default permissions."""
    # Unknown credentials handling
    unknown_creds = config.get("unknown_credentials", config.get("credentials"))
    if unknown_creds == "prompt":
        permissions.append({
            "action": "credential:use",
            "resource": "*",
            "effect": "prompt",
            "tier": "explicit",
        })
    elif unknown_creds == "deny":
        permissions.append({
            "action": "credential:use",
            "resource": "*",
            "effect": "deny",
            "tier": "explicit",
        })

    # Default rate limit
    if "rate_limit" in config:
        permissions.append({
            "action": "network:request",
            "resource": "*",
            "effect": "budget",
            "budget": config["rate_limit"],
            "tier": "explicit",
        })

    # Raw rules passthrough
    if "rules" in config:
        for rule in config["rules"]:
            permissions.append(rule)


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
