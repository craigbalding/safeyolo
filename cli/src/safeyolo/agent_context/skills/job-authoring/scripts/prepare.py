#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["tomlkit==0.14.0", "pyyaml==6.0.3"]
# ///
"""Prepare the installed GitHub/artifact example without activating authority.

Reuse the policy author's TOMLKit writer and the service catalogue's YAML
parser. Provider credentials are referenced by name and never read or copied.
"""

import argparse
import hashlib
import json
import os
import re
from pathlib import Path

import tomlkit
import yaml

AUTHOR = "example_issue_author"
ARTIFACT = "example_artifact"
CAPABILITY = "read_example_issues"


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def add_example_setting(values, name, value):
    """Preserve existing authority; a conflicting example needs an explicit edit."""
    if name in values and values[name] != value:
        raise ValueError(f"Existing {name} differs; reconcile it before preparing this example")
    values[name] = value


def relocate_policy_inputs(policy, policy_path):
    """Keep existing selected files bound when the candidate lives elsewhere."""
    for name, value in policy.get("lists", {}).items():
        if isinstance(value, str):
            policy["lists"][name] = str((policy_path.parent / value).resolve())
    for check in policy.get("checks", {}).values():
        source = check["source"]
        key = "path" if source["kind"] == "recorded" else "spec" if source["kind"] == "job" else None
        if key:
            source[key] = str((policy_path.parent / source[key]).resolve())


def prepare(args):
    """Write reviewable candidates and runnable inputs in a new private directory."""
    root = args.root.resolve(strict=True)
    bundle = args.bundle.resolve(strict=True) if args.bundle else root / "assets/hyperlight"
    config = tomlkit.parse((root / "config.toml").read_text())
    policy_path = Path(config.get("policy_file", "policy.toml"))
    if not policy_path.is_absolute():
        policy_path = root / policy_path
    policy = tomlkit.parse(policy_path.read_text())
    def service_directory(key, default):
        path = Path(config.get(key, default))
        return path if path.is_absolute() else root / path

    builtin = service_directory("gateway_builtin_services_dir", "builtin-services")
    user = service_directory("gateway_services_dir", "services")
    service_target = user / "github.yaml"
    service_source = service_target if service_target.exists() else builtin / "github.yaml"
    service = yaml.safe_load(service_source.read_text())
    if service["name"] != "github" or service["default_host"] != "api.github.com":
        raise ValueError("The selected instance needs its existing GitHub service definition")
    add_example_setting(service["capabilities"], CAPABILITY, {"description": "Read this example's repository issues",
        "routes": [{"methods": ["GET"], "path": f"/repos/{args.repository}/issues/*"}]})
    # Preserve the existing authoring helper's candidate-relative file semantics.
    relocate_policy_inputs(policy, policy_path)
    for name, purpose, inputs in [
        (AUTHOR, "service", {"repository": args.repository, "expected_author_id": args.author_id}),
        (ARTIFACT, "artifact", {"expected_status": "ready"}),
    ]:
        path = bundle / f"{args.engine}-{purpose}.json"
        spec = json.loads(path.read_bytes())
        selected = spec["engine"]["guest" if args.engine == "hyperlight" else "checker"]
        artifact = path.parent / selected["path"]
        if digest(artifact) != selected["sha256"]:
            raise ValueError(f"Selected checker digest differs: {artifact}")
        definition = {"source_id": name, "meaning": "GitHub recorded issue author" if name == AUTHOR else "JSON artifact status is ready",
            "subject": "value", "result_type": "finding", "influences": ["hard_exclusion"],
            "implementation_version": selected["sha256"], "configuration_version": digest(path),
            "max_age_seconds": 60, "inputs": inputs,
            "source": {"kind": "job", "spec": str(path), "effects": "passive", "limits": {
                "timeout_ms": spec["timeout_seconds"] * 1000 + 5000, "max_input_bytes": spec["max_input_bytes"],
                "max_output_bytes": spec["retain_bytes"], "max_concurrent": 1, "max_pending": 1, "max_cached": 0}}}
        add_example_setting(policy.setdefault("checks", {}), name, definition)
        binding = {"name": name, "room": args.room, "factory": args.factory, "job": name,
            "boundary": "admit_issue" if name == AUTHOR else "verify_output",
            "input": "github_issue" if name == AUTHOR else "published_artifact",
            "on_failure": "hold", "require": {"op": "finding", "check": name}}
        if name == AUTHOR:
            binding["repository"] = args.repository
        bindings = policy.setdefault("work_bindings", [])
        old = next((item for item in bindings if item["name"] == name), None)
        if old is not None and old != binding:
            raise ValueError(f"Existing binding {name} differs; reconcile its authority")
        if old is None:
            bindings.append(binding)
    services = policy.setdefault("agents", {}).setdefault("gate:hyperlight-service-check", {}).setdefault("services", {})
    add_example_setting(services, "github", {"capability": CAPABILITY, "token": args.credential})
    # Preserve any explicit existing host decision. A retained denial still wins.
    policy.setdefault("hosts", {}).setdefault("api.github.com", {"egress": "allow", "service": "github", "allow": ["github:*"]})
    args.output.mkdir(parents=True, mode=0o700, exist_ok=False)
    contents = {"candidate.toml": tomlkit.dumps(policy), "github.yaml": yaml.safe_dump(service, sort_keys=False),
        "author-request.json": json.dumps({"subject": {"kind": "value", "value": args.issue},
            "inputs": {"repository": args.repository, "expected_author_id": args.author_id}}) + "\n",
        "ready.json": '{"status":"ready"}\n', "rejected.json": '{"status":"draft"}\n'}
    for name, value in contents.items():
        with open(args.output / name, "x", opener=lambda path, flags: os.open(path, flags, 0o600)) as stream:
            stream.write(value)
    print(json.dumps({"root": str(root), "saved_policy": str(policy_path), "candidate": str(args.output.resolve()),
        "engine": args.engine, "bundle": str(bundle), "repository": args.repository, "expected_author_id": args.author_id,
        "service_target": str(service_target),
        "grant": {"principal": "gate:hyperlight-service-check", "capability": CAPABILITY, "credential": args.credential},
        "boundaries": ["admit_issue", "verify_output"], "activation": "not applied"}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--bundle", type=Path, help="Proposed job bundle; defaults to the selected instance's assets/hyperlight")
    parser.add_argument("--engine", required=True, choices=["hyperlight", "hyperlight-unikraft"])
    for name in ("repository", "author-id", "issue", "room", "factory", "credential"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
        parser.error("repository must be OWNER/REPOSITORY")
    for name in ("author_id", "issue"):
        value = getattr(args, name)
        if not value.isascii() or not value.isdecimal() or not 0 < int(value) <= 2**64 - 1:
            parser.error(f"{name} must be a positive GitHub integer ID")
    prepare(args)


if __name__ == "__main__":
    main()
