#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["tomlkit==0.14.0"]
# ///
"""Generate a cyber research candidate without changing the selected instance.

TOMLKit is the repository's existing round-trip writer. It preserves unrelated
controls and comments, including inline agent definitions. No provider or
assessed destination is contacted by this helper.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

import tomlkit

THREATS = "cyber_threats"
REGISTERED = "cyber_registered"
SERVICE = "cyber-rdap"
GATE = "cyber-registration"


def read_toml(path: Path):
    """Read the selected document, preserving unavailable versus empty state."""
    return tomlkit.parse(path.read_text())


def private_file(path: Path, content: str) -> None:
    """Create a private artifact in the fresh output directory."""
    with open(path, "x", opener=lambda name, flags: os.open(name, flags, 0o600)) as output:
        output.write(content)


def choices_from(path: Path) -> dict:
    """Load explicit operator choices; missing decisions are not defaults."""
    choices = json.loads(path.read_text())
    required = {
        "agent", "profile", "feed", "feed_max_age_seconds", "registration_endpoint",
        "registration_path", "registration_max_age_seconds", "registration_timeout_ms",
        "threshold_days", "new_domain_action", "unknown_action", "list_action",
        "list_unavailable", "list_priority", "registration_priority", "destinations",
    }
    if set(choices) != required:
        raise ValueError(f"Choices need exactly these fields: {', '.join(sorted(required))}")
    if choices["profile"] not in {"hard", "advisory"}:
        raise ValueError("Choose profile hard or advisory")
    if choices["profile"] == "hard" and choices["list_action"] != "deny":
        raise ValueError("A hard exclusion requires list_action deny")
    actions = {"list_action": {"allow", "deny", "approval", "unresolved"},
               "new_domain_action": {"allow", "deny", "approval", "unresolved"},
               "list_unavailable": {"continue", "deny", "approval", "unresolved"},
               "unknown_action": {"continue", "deny", "approval", "unresolved"}}
    for name, allowed in actions.items():
        if choices[name] not in allowed:
            raise ValueError(f"Unsupported {name}")
    for name in ("feed_max_age_seconds", "registration_max_age_seconds", "registration_timeout_ms", "threshold_days"):
        if type(choices[name]) is not int or choices[name] <= 0:
            raise ValueError(f"{name} must be a positive integer")
    endpoint = urlsplit(choices["registration_endpoint"])
    if endpoint.scheme not in {"https", "http"} or not endpoint.hostname or endpoint.username or endpoint.path not in {"", "/"} or endpoint.query or endpoint.fragment:
        raise ValueError("registration_endpoint must be an HTTP(S) origin without credentials")
    path_template = choices["registration_path"]
    if not path_template.startswith("/") or path_template.count("{subject}") != 1:
        raise ValueError("registration_path needs one {subject} placeholder")
    return choices


def managed_parts(choices: dict) -> dict:
    """Build only the named checks, rules and dependency grant of this recipe."""
    influence = "hard_exclusion" if choices["profile"] == "hard" else "advisory"
    common = {
        "subject": "hostname", "implementation_version": "cyber-recipe-1",
        "configuration_version": hashlib.sha256(json.dumps(choices, sort_keys=True).encode()).hexdigest(),
    }
    checks = {
        THREATS: {
            **common, "source_id": choices["feed"], "meaning": "positive means membership in the adopted threat list; absence is not safety",
            "result_type": "finding", "influences": [influence],
            "max_age_seconds": choices["feed_max_age_seconds"],
            "source": {"kind": "feed", "name": choices["feed"]},
        },
        REGISTERED: {
            **common, "source_id": choices["registration_endpoint"],
            "meaning": "RFC 9083 registration event for the exact hostname; parent, transfer, update and certificate dates are not tenant creation",
            "result_type": "timestamp", "influences": ["advisory"],
            "max_age_seconds": choices["registration_max_age_seconds"],
            "source": {"kind": "service", "operation": {
                "gate_id": GATE, "service": SERVICE, "capability": "lookup",
                "endpoint": choices["registration_endpoint"], "method": "GET",
                "path": choices["registration_path"], "effects": "passive", "mapping": "rdap_registration",
            }, "limits": {
                "timeout_ms": choices["registration_timeout_ms"], "max_input_bytes": 8192,
                "max_output_bytes": 65536, "max_concurrent": 2, "max_pending": 4, "max_cached": 128,
            }},
        },
    }
    rules = [
        {"name": "cyber-threat-list", "host": "*", "agent": choices["agent"], "stage": "connect",
         "required": True, "influence": influence, "priority": choices["list_priority"],
         "when": {"op": "finding", "check": THREATS}, "on_match": choices["list_action"],
         "on_unavailable": choices["list_unavailable"]},
        {"name": "cyber-new-domain", "host": "*", "agent": choices["agent"], "stage": "connect",
         "required": True, "influence": "advisory", "priority": choices["registration_priority"],
         "when": {"op": "age", "check": REGISTERED, "comparison": "lt", "seconds": choices["threshold_days"] * 86400},
         "on_match": choices["new_domain_action"], "on_unavailable": choices["unknown_action"]},
    ]
    provider = urlsplit(choices["registration_endpoint"]).hostname
    return {"checks": checks, "rules": rules, "provider": provider,
            "provider_host": {"egress": "allow", "service": SERVICE},
            "grant": {"capability": "lookup"}}


def replace_owned(table, key: str, value, previous) -> None:
    """Replace only a new key or an unchanged block from saved choices."""
    if key in table and (previous is None or table[key] != previous):
        raise ValueError(f"Existing {key} differs from the saved recipe; reconcile it before generation")
    table[key] = value


def compose(policy, choices: dict, previous: dict | None):
    """Preserve unrelated controls; reject collisions rather than widening them."""
    parts = managed_parts(choices)
    old = managed_parts(previous) if previous else None
    if previous and (choices["agent"] != previous["agent"] or parts["provider"] != old["provider"]):
        raise ValueError("Agent/provider changes need explicit reconciliation of old grants")
    checks = policy.setdefault("checks", {})
    for name, check in parts["checks"].items():
        replace_owned(checks, name, check, old["checks"][name] if old else None)
    rules = policy.setdefault("check_rules", [])
    for rule in parts["rules"]:
        matching = [index for index, current in enumerate(rules) if current["name"] == rule["name"]]
        if matching:
            index = matching[0]
            if len(matching) != 1 or not old or rules[index] != next(item for item in old["rules"] if item["name"] == rule["name"]):
                raise ValueError(f"Existing {rule['name']} differs from the saved recipe")
            rules[index] = rule
        else:
            rules.append(rule)
    # The provider host needs its service binding. It receives no workload
    # credential. Only the named gate receives the capability.
    replace_owned(policy.setdefault("hosts", {}), parts["provider"], parts["provider_host"], old["provider_host"] if old else None)
    agents = policy.setdefault("agents", {})
    services = agents.setdefault(f"gate:{GATE}", {}).setdefault("services", {})
    replace_owned(services, SERVICE, parts["grant"], old["grant"] if old else None)
    # New required destinations are explicit operator choices. Existing entries,
    # including denies, remain authoritative and are reported in the rationale.
    hosts = agents.setdefault(choices["agent"], {}).setdefault("hosts", {})
    for destination in choices["destinations"]:
        hosts.setdefault(destination, {"egress": "allow"})
    return policy


def generate(args) -> None:
    """Save a complete review candidate; feed/config/apply remain explicit."""
    root = args.root.resolve(strict=True)
    config_path = root / "config.toml"
    config = read_toml(config_path)
    policy_path = Path(config.get("policy_file", "policy.toml"))
    if not policy_path.is_absolute():
        policy_path = root / policy_path
    policy_path = policy_path.resolve(strict=True)
    choices = choices_from(args.choices)
    previous = choices_from(args.previous) if args.previous else None
    policy = read_toml(policy_path)
    candidate = compose(policy, choices, previous)
    # Candidate-relative references retain their actual inputs after relocation.
    for name, item in candidate.get("lists", {}).items():
        if isinstance(item, str):
            candidate["lists"][name] = str((policy_path.parent / item).resolve())
    for check in candidate.get("checks", {}).values():
        source = check["source"]
        key = "path" if source["kind"] == "recorded" else "spec" if source["kind"] == "job" else None
        if key:
            source[key] = str((policy_path.parent / source[key]).resolve())
    current_sources = policy_path.parent / "policy-feeds.toml"
    sources = read_toml(current_sources) if current_sources.exists() else tomlkit.document()
    incoming = read_toml(args.sources)
    for name, source in incoming["sources"].items():
        existing = sources.setdefault("sources", {})
        if name in existing and existing[name] != source:
            raise ValueError(f"Source {name} already exists with another definition; preserve or explicitly revise it")
        existing[name] = source
    if choices["feed"] not in sources["sources"]:
        raise ValueError("The selected feed needs an adopted source definition")
    provider = urlsplit(choices["registration_endpoint"]).hostname
    service = {"schema_version": 1, "name": SERVICE, "default_host": provider,
               "capabilities": {"lookup": {"routes": [{"methods": ["GET"], "path": choices["registration_path"].replace("{subject}", "*")}]}}}
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    private_file(args.output / "candidate.toml", tomlkit.dumps(candidate))
    private_file(args.output / "sources.toml", tomlkit.dumps(sources))
    # JSON is valid YAML and avoids a second serialization dependency.
    private_file(args.output / f"{SERVICE}.yaml", json.dumps(service, indent=2) + "\n")
    private_file(args.output / "preferences.json", json.dumps(choices, indent=2) + "\n")
    private_file(args.output / "rationale.md", (
        f"Selected instance: {root}\nSelected saved policy: {policy_path}\nAgent: {choices['agent']}\n\n"
        f"List {choices['feed']}: {choices['profile']} influence, {choices['list_action']} on membership, "
        f"{choices['list_unavailable']} when unavailable; priority {choices['list_priority']}.\n"
        f"Exact registration younger than {choices['threshold_days']} days: {choices['new_domain_action']}; "
        f"unknown/error: {choices['unknown_action']}; priority {choices['registration_priority']}.\n"
        f"Provider: {choices['registration_endpoint']}{choices['registration_path']}; passive lookup discloses hostname and caller IP to provider. "
        "Provider logging/retention is not established. No subject visit or scan is authorized by this lookup.\n"
        f"Registration evidence expires after {choices['registration_max_age_seconds']} seconds from collection. "
        "RDAP supplies no dataset observation time here. Existing destination entries, controls, budgets and grants are retained. "
        "An existing destination deny may still refuse a requested source.\n\n"
        "Preview is recorded/offline: service checks are unavailable. It makes no provider calls, DNS lookups or target visits. "
        "Compile-only validation is not a decision simulation. Fixture results describe synthetic cases only.\n"
        "Saved candidate files grant no access. Configure sources, install the service, check/evaluate and apply through the selected host owner; "
        "read policy show to verify active state. An unavailable read means unknown activation.\n"
    ))
    private_file(args.output / "request.json", json.dumps({"agent": choices["agent"], "host": "example.com", "port": 443,
                                                         "scheme": "https", "method": "GET", "path": "/"}, indent=2) + "\n")
    print(f"Candidate saved at {args.output}; selected instance {root} is unchanged")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--choices", type=Path, required=True)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--previous", type=Path)
    args = parser.parse_args()
    try:
        generate(args)
    except (ValueError, OSError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
