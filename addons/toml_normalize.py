"""
toml_normalize.py - Bidirectional field name mapping between TOML and internal formats.

TOML policy uses shorter, idiomatic field names. The internal format (used by
policy_compiler.py) uses more descriptive names.

Two pure dict->dict functions, no I/O:
- normalize(doc)   : TOML field names -> internal field names
- denormalize(doc) : internal field names -> TOML field names

Both functions are input-safe: the caller's dict is never mutated. Both
validate shape at top level and raise ValueError with a clear message on
malformed input (non-dict hosts, duplicate representations of the same
logical field, etc.) rather than silently dropping data or crashing deep
inside a helper.
"""

import copy
from typing import Any

# TOML-side key → internal-side key (for collision detection)
_NORMALIZE_COLLISIONS = {
    "budget": "global_budget",
    "credential": "credentials",
    "risk": "gateway",  # risk becomes gateway.risk_appetite
    "version": "metadata",  # version becomes metadata.version
    "description": "metadata",  # description becomes metadata.description
}

# Internal-side key → TOML-side key (for collision detection)
_DENORMALIZE_COLLISIONS = {
    "global_budget": "budget",
    "credentials": "credential",
    "metadata": "version",  # metadata.version becomes top-level version
}


def _require_dict(value: Any, field: str) -> None:
    """Raise ValueError if value is not a dict. Names the field for the operator."""
    if not isinstance(value, dict):
        raise ValueError(
            f"Expected dict for '{field}', got {type(value).__name__}"
        )


def _check_no_collision(doc: dict, toml_key: str, internal_key: str) -> None:
    """Raise ValueError if both TOML and internal representations of the same
    logical field are present in the same input doc."""
    if toml_key in doc and internal_key in doc:
        raise ValueError(
            f"Input contains both '{toml_key}' and '{internal_key}' — "
            f"these are two representations of the same field. "
            f"Keep only one."
        )


def normalize(doc: dict) -> dict:
    """Convert TOML field names to internal field names.

    Key structural reshapes:
    - version/description at top level -> nested under metadata
    - budget -> global_budget
    - credential (singular) -> credentials (plural), .match -> .patterns
    - risk (top-level list) -> gateway.risk_appetite
    - hosts.X.allow -> hosts.X.credentials
    - hosts.X.rate -> hosts.X.rate_limit
    - hosts.X.unknown_creds -> hosts.X.unknown_credentials
    - agents.<name>.hosts.<host> same renames as top-level hosts

    Unknown top-level keys pass through unchanged.

    Raises:
        ValueError: if the input contains both TOML and internal
            representations of the same logical field, or if a top-level
            section (hosts, credential, agents) is present but not a dict.
    """
    # Collision detection: caller must not pass both forms of the same field
    _check_no_collision(doc, "budget", "global_budget")
    _check_no_collision(doc, "credential", "credentials")
    _check_no_collision(doc, "risk", "gateway")

    # Shape validation at the top level
    if "hosts" in doc:
        _require_dict(doc["hosts"], "hosts")
    if "credential" in doc:
        _require_dict(doc["credential"], "credential")
    if "agents" in doc:
        _require_dict(doc["agents"], "agents")
    if "risk" in doc and not isinstance(doc["risk"], list):
        raise ValueError(
            f"Expected list for 'risk', got {type(doc['risk']).__name__}"
        )

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

    # hosts: rename per-host fields (_normalize_hosts deep-copies)
    if "hosts" in doc:
        result["hosts"] = _normalize_hosts(doc["hosts"])

    # credential (singular) -> credentials (plural)
    if "credential" in doc:
        result["credentials"] = _normalize_credentials(doc["credential"])

    # risk (top-level list) -> gateway.risk_appetite
    if "risk" in doc:
        result["gateway"] = {"risk_appetite": _normalize_risk(doc["risk"])}

    # Pass through keys that don't need renaming.
    # Deep-copy to guarantee output independence from input.
    for key, value in doc.items():
        if key in ("version", "description", "budget", "credential", "risk", "hosts"):
            continue  # Already handled above
        if key not in result:
            result[key] = copy.deepcopy(value)

    # Normalize agents.<name>.hosts fields (same mapping as top-level hosts).
    # We deep-copied `agents` in the pass-through above, so this mutates a
    # fresh copy — the caller's input is untouched.
    if "agents" in result:
        agents = result["agents"]
        if isinstance(agents, dict):
            for agent_config in agents.values():
                if isinstance(agent_config, dict) and "hosts" in agent_config:
                    _require_dict(
                        agent_config["hosts"], "agents.<name>.hosts"
                    )
                    agent_config["hosts"] = _normalize_hosts(agent_config["hosts"])

    return result


def _normalize_hosts(hosts: dict) -> dict:
    """Rename per-host TOML fields to internal names. Deep-copies values so
    the output does not share references with the input."""
    result: dict[str, Any] = {}
    for host, config in hosts.items():
        if not isinstance(config, dict):
            result[host] = copy.deepcopy(config)
            continue
        entry: dict[str, Any] = {}
        for k, v in config.items():
            # Deep-copy value so list/dict leaves are independent of input
            v = copy.deepcopy(v)
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
            result[name] = copy.deepcopy(config)
            continue
        entry: dict[str, Any] = {}
        for k, v in config.items():
            v = copy.deepcopy(v)
            if k == "match":
                entry["patterns"] = v
            else:
                entry[k] = v
        result[name] = entry
    return result


def _normalize_risk(rules: list) -> list:
    """Risk rules pass through unchanged (field names already match internal).
    Deep-copied to guarantee independence from input."""
    return copy.deepcopy(list(rules))


def denormalize(doc: dict) -> dict:
    """Convert internal field names to TOML field names.

    Reverse of normalize(). Used by migration tool and write paths.

    Raises:
        ValueError: if the input contains both internal and TOML
            representations of the same logical field, or if a top-level
            section (hosts, credentials, agents, metadata) is present but
            not a dict.
    """
    # Collision detection
    _check_no_collision(doc, "global_budget", "budget")
    _check_no_collision(doc, "credentials", "credential")

    # Shape validation
    if "metadata" in doc:
        _require_dict(doc["metadata"], "metadata")
    if "hosts" in doc:
        _require_dict(doc["hosts"], "hosts")
    if "credentials" in doc:
        _require_dict(doc["credentials"], "credentials")
    if "agents" in doc:
        _require_dict(doc["agents"], "agents")
    if "gateway" in doc:
        _require_dict(doc["gateway"], "gateway")

    result: dict[str, Any] = {}

    # metadata -> top-level version/description
    meta = doc.get("metadata")
    if isinstance(meta, dict):
        if "version" in meta:
            result["version"] = meta["version"]
        if "description" in meta:
            result["description"] = meta["description"]

    # global_budget -> budget
    if "global_budget" in doc:
        result["budget"] = doc["global_budget"]

    # hosts: rename per-host fields back (deep-copies)
    if "hosts" in doc:
        result["hosts"] = _denormalize_hosts(doc["hosts"])

    # credentials (plural) -> credential (singular)
    if "credentials" in doc:
        result["credential"] = _denormalize_credentials(doc["credentials"])

    # gateway handling:
    # - gateway.risk_appetite -> top-level risk
    # - any other gateway fields are preserved as a gateway table minus risk_appetite
    gateway = doc.get("gateway")
    if isinstance(gateway, dict):
        if "risk_appetite" in gateway:
            result["risk"] = copy.deepcopy(list(gateway["risk_appetite"]))
        remaining = {k: copy.deepcopy(v) for k, v in gateway.items() if k != "risk_appetite"}
        if remaining:
            result["gateway"] = remaining

    # Pass through remaining keys. Deep-copy for independence.
    for key, value in doc.items():
        if key in ("metadata", "global_budget", "hosts", "credentials", "gateway"):
            continue  # Already handled
        if key not in result:
            result[key] = copy.deepcopy(value)

    # Denormalize agents.<name>.hosts fields (same mapping as top-level hosts).
    # `agents` was deep-copied in the pass-through above.
    if "agents" in result:
        agents = result["agents"]
        if isinstance(agents, dict):
            for agent_config in agents.values():
                if isinstance(agent_config, dict) and "hosts" in agent_config:
                    _require_dict(
                        agent_config["hosts"], "agents.<name>.hosts"
                    )
                    agent_config["hosts"] = _denormalize_hosts(agent_config["hosts"])

    return result


def _denormalize_hosts(hosts: dict) -> dict:
    """Rename per-host internal fields to TOML names. Deep-copies values."""
    result: dict[str, Any] = {}
    for host, config in hosts.items():
        if not isinstance(config, dict):
            result[host] = copy.deepcopy(config)
            continue
        entry: dict[str, Any] = {}
        for k, v in config.items():
            v = copy.deepcopy(v)
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
            result[name] = copy.deepcopy(config)
            continue
        entry: dict[str, Any] = {}
        for k, v in config.items():
            v = copy.deepcopy(v)
            if k == "patterns":
                entry["match"] = v
            else:
                entry[k] = v
        result[name] = entry
    return result
