"""
toml_normalize.py - Bidirectional field name mapping between TOML and internal formats.

TOML policy uses shorter, idiomatic field names. The internal format (produced by
PyYAML from policy.yaml) uses the names that policy_compiler.py expects.

Two pure dict->dict functions, no I/O:
- normalize(doc)   : TOML field names -> internal field names
- denormalize(doc) : internal field names -> TOML field names
"""

from typing import Any


def normalize(doc: dict) -> dict:
    """Convert TOML field names to internal field names.

    Output looks identical to what PyYAML produces from current policy.yaml,
    so policy_compiler.py works unmodified.

    Key structural reshapes:
    - version/description at top level -> nested under metadata: {}
    - budget -> global_budget
    - credential (singular) -> credentials (plural), .match -> .patterns
    - risk (top-level list) -> gateway: { risk_appetite: [...] }
    - hosts.X.allow -> hosts.X.credentials
    - hosts.X.rate -> hosts.X.rate_limit
    - hosts.X.unknown_creds -> hosts.X.unknown_credentials

    Unknown keys pass through unchanged.
    """
    result: dict[str, Any] = {}

    # metadata: top-level version/description -> metadata dict
    meta: dict[str, Any] = {}
    if "version" in doc:
        meta["version"] = doc["version"]
    if "description" in doc:
        meta["description"] = doc["description"]
    if meta:
        result["metadata"] = meta

    # budget -> global_budget
    if "budget" in doc:
        result["global_budget"] = doc["budget"]

    # hosts: rename per-host fields
    if "hosts" in doc:
        result["hosts"] = _normalize_hosts(doc["hosts"])

    # credential (singular) -> credentials (plural)
    if "credential" in doc:
        result["credentials"] = _normalize_credentials(doc["credential"])

    # risk (top-level list) -> gateway.risk_appetite
    if "risk" in doc:
        gateway = result.get("gateway", {})
        gateway["risk_appetite"] = _normalize_risk(doc["risk"])
        result["gateway"] = gateway

    # Pass through keys that don't need renaming
    for key, value in doc.items():
        if key in ("version", "description", "budget", "credential", "risk", "hosts"):
            continue  # Already handled above
        if key not in result:
            result[key] = value

    # Normalize agents.<name>.hosts fields (same mapping as top-level hosts)
    if "agents" in result:
        agents = result["agents"]
        if isinstance(agents, dict):
            for agent_config in agents.values():
                if isinstance(agent_config, dict) and "hosts" in agent_config:
                    agent_config["hosts"] = _normalize_hosts(agent_config["hosts"])

    return result


def _normalize_hosts(hosts: dict) -> dict:
    """Rename per-host TOML fields to internal names."""
    result: dict[str, Any] = {}
    for host, config in hosts.items():
        if not isinstance(config, dict):
            result[host] = config
            continue
        entry: dict[str, Any] = {}
        for k, v in config.items():
            if k == "allow":
                entry["credentials"] = v
            elif k == "rate":
                entry["rate_limit"] = v
            elif k == "unknown_creds":
                entry["unknown_credentials"] = v
            else:
                entry[k] = v
        result[host] = entry
    return result


def _normalize_credentials(creds: dict) -> dict:
    """Rename per-credential TOML fields to internal names."""
    result: dict[str, Any] = {}
    for name, config in creds.items():
        if not isinstance(config, dict):
            result[name] = config
            continue
        entry: dict[str, Any] = {}
        for k, v in config.items():
            if k == "match":
                entry["patterns"] = v
            else:
                entry[k] = v
        result[name] = entry
    return result


def _normalize_risk(rules: list) -> list:
    """Risk rules pass through unchanged (field names already match internal)."""
    return list(rules)


def denormalize(doc: dict) -> dict:
    """Convert internal field names to TOML field names.

    Reverse of normalize(). Used by migration tool and write paths.
    """
    result: dict[str, Any] = {}

    # metadata -> top-level version/description
    meta = doc.get("metadata", {})
    if isinstance(meta, dict):
        if "version" in meta:
            result["version"] = meta["version"]
        if "description" in meta:
            result["description"] = meta["description"]

    # global_budget -> budget
    if "global_budget" in doc:
        result["budget"] = doc["global_budget"]

    # hosts: rename per-host fields back
    if "hosts" in doc:
        result["hosts"] = _denormalize_hosts(doc["hosts"])

    # credentials (plural) -> credential (singular)
    if "credentials" in doc:
        result["credential"] = _denormalize_credentials(doc["credentials"])

    # gateway.risk_appetite -> risk (top-level list)
    gateway = doc.get("gateway", {})
    if isinstance(gateway, dict) and "risk_appetite" in gateway:
        result["risk"] = list(gateway["risk_appetite"])

    # Pass through remaining keys
    for key, value in doc.items():
        if key in ("metadata", "global_budget", "hosts", "credentials", "gateway"):
            continue  # Already handled
        if key not in result:
            result[key] = value

    # Denormalize agents.<name>.hosts fields (same mapping as top-level hosts)
    if "agents" in result:
        agents = result["agents"]
        if isinstance(agents, dict):
            for agent_config in agents.values():
                if isinstance(agent_config, dict) and "hosts" in agent_config:
                    agent_config["hosts"] = _denormalize_hosts(agent_config["hosts"])

    return result


def _denormalize_hosts(hosts: dict) -> dict:
    """Rename per-host internal fields to TOML names."""
    result: dict[str, Any] = {}
    for host, config in hosts.items():
        if not isinstance(config, dict):
            result[host] = config
            continue
        entry: dict[str, Any] = {}
        for k, v in config.items():
            if k == "credentials":
                entry["allow"] = v
            elif k == "rate_limit":
                entry["rate"] = v
            elif k == "unknown_credentials":
                entry["unknown_creds"] = v
            else:
                entry[k] = v
        result[host] = entry
    return result


def _denormalize_credentials(creds: dict) -> dict:
    """Rename per-credential internal fields to TOML names."""
    result: dict[str, Any] = {}
    for name, config in creds.items():
        if not isinstance(config, dict):
            result[name] = config
            continue
        entry: dict[str, Any] = {}
        for k, v in config.items():
            if k == "patterns":
                entry["match"] = v
            else:
                entry[k] = v
        result[name] = entry
    return result
