#!/usr/bin/env python3
"""Prepare disposable service and policy inputs for the installed P3 pilot."""

from __future__ import annotations

import argparse
import json
import secrets
import tomllib
from pathlib import Path

import tomlkit

from safeyolo.core.vault import Vault, VaultCredential

BASIC = """\
schema_version: 1
name: p3_basic
default_host: legitimate-api.com
auth:
  type: bearer
  header: Authorization
  scheme: Bearer
  allow_http: true
capabilities:
  reader:
    routes:
      - methods: [GET]
        path: /p3/read
"""

CONTRACT = """\
schema_version: 1
name: p3_contract
default_host: httpbin.org
auth:
  type: bearer
  header: Authorization
  scheme: Bearer
  allow_http: true
risky_routes:
  - path: /p3/write
    methods: [POST]
    tactics: [impact]
capabilities:
  writer:
    routes:
      - methods: [POST]
        path: /p3/write
    contract:
      template: p3.write.v1
      bindings:
        project:
          source: operator
          type: enum
          options: [alpha, beta]
        ticket:
          source: operator
          type: string
      operations:
        - name: write
          request:
            method: POST
            path: /p3/write
            query:
              allow:
                ticket:
                  equals_var: ticket
            body:
              allow:
                project:
                  equals_var: project
      enforcement:
        request_shape: enforced
        transport_hygiene: enforced
        state_capture: declared
        state_enforcement: declared
        response_validators: declared
"""


def prepare(config_dir: Path) -> None:
    policy_path = config_dir / "policy.toml"
    policy = tomlkit.parse(policy_path.read_text())
    hosts = policy["hosts"]
    for host, service in (("legitimate-api.com", "p3_basic"), ("httpbin.org", "p3_contract")):
        entry = tomlkit.inline_table()
        entry["egress"] = "allow"
        entry["service"] = service
        hosts[host] = entry
    allowed = tomlkit.inline_table()
    allowed["egress"] = "allow"
    hosts["failing.test"] = allowed
    denied = tomlkit.inline_table()
    denied["egress"] = "deny"
    hosts["evil.com"] = denied
    risks = policy.get("risk") or tomlkit.aot()
    risk = tomlkit.table()
    risk["account"] = "agent"
    risk["tactics"] = ["impact"]
    risk["decision"] = "require_approval"
    risk["approval_default"] = "once"
    risks.append(risk)
    policy["risk"] = risks
    rendered = tomlkit.dumps(policy)
    # Reject a malformed fixture before the native process starts.
    parsed = tomllib.loads(rendered)
    assert parsed["hosts"]["evil.com"]["egress"] == "deny"
    assert parsed["risk"][-1]["decision"] == "require_approval"
    policy_path.write_text(rendered)

    services = config_dir / "services"
    services.mkdir(exist_ok=True)
    (services / "p3-basic.yaml").write_text(BASIC)
    (services / "p3-contract.yaml").write_text(CONTRACT)

    data = config_dir / "data"
    data.mkdir(exist_ok=True)
    passphrase = secrets.token_urlsafe(32)
    key = data / "vault.key"
    key.write_text(passphrase + "\n")
    key.chmod(0o600)
    credential = "p3-vault-" + secrets.token_hex(20)
    vault = Vault(data / "vault.yaml.enc")
    vault.unlock(passphrase)
    vault.store(VaultCredential(name="p3-owned", type="bearer", value=credential))
    (data / "vault.yaml.enc").chmod(0o600)
    fixture = config_dir / "p3-fixture.json"
    fixture.write_text(json.dumps({"credential_name": "p3-owned", "credential": credential}) + "\n")
    fixture.chmod(0o600)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config_dir", type=Path)
    args = parser.parse_args()
    prepare(args.config_dir.resolve())


if __name__ == "__main__":
    main()
