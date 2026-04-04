#!/usr/bin/env python3
"""Migrate agents.yaml into policy.toml [agents] section.

Run on the host (not inside a container):
    python3 scripts/migrate_agents_yaml.py

What it does:
    1. Reads ~/.safeyolo/agents.yaml
    2. Merges entries into ~/.safeyolo/policy.toml under [agents]
    3. Renames agents.yaml to agents.yaml.bak

Verify with: safeyolo policy show --section agents
"""

import shutil
import sys
from pathlib import Path

import tomlkit
import yaml


def main():
    config_dir = Path.home() / ".safeyolo"
    agents_path = config_dir / "agents.yaml"
    policy_path = config_dir / "policy.toml"

    if not agents_path.exists():
        print(f"No agents.yaml found at {agents_path} — nothing to migrate.")
        return

    if not policy_path.exists():
        print(f"No policy.toml found at {policy_path} — run 'safeyolo init' first.")
        sys.exit(1)

    # Load agents.yaml
    agents = yaml.safe_load(agents_path.read_text())
    if not agents or not isinstance(agents, dict):
        print("agents.yaml is empty or invalid — nothing to migrate.")
        return

    # Load policy.toml (preserving comments)
    doc = tomlkit.parse(policy_path.read_text())

    # Build [agents] section
    tbl = tomlkit.table()
    for name, meta in agents.items():
        if not isinstance(meta, dict):
            continue
        agent = tomlkit.table()
        for k, v in meta.items():
            if k == "services" and isinstance(v, dict):
                svc = tomlkit.table()
                for sn, sc in v.items():
                    e = tomlkit.table()
                    if isinstance(sc, dict):
                        for sk, sv in sc.items():
                            e.add(sk, sv)
                    else:
                        e.add("capability", sc)
                    svc.add(sn, e)
                agent.add("services", svc)
            elif k in ("contract_bindings", "grants") and isinstance(v, list):
                aot = tomlkit.aot()
                for item in v:
                    entry = tomlkit.table()
                    for ik, iv in item.items():
                        if isinstance(iv, dict):
                            sub = tomlkit.table()
                            for dk, dv in iv.items():
                                sub.add(dk, dv)
                            entry.add(ik, sub)
                        else:
                            entry.add(ik, iv)
                    aot.append(entry)
                agent.add(k, aot)
            else:
                agent.add(k, v)
        tbl.add(name, agent)

    # Merge into policy.toml
    if "agents" in doc:
        del doc["agents"]
    doc.add("agents", tbl)

    # Write policy.toml
    policy_path.write_text(tomlkit.dumps(doc))
    print(f"Merged {len(agents)} agent(s) into {policy_path}")

    # Back up agents.yaml
    backup = agents_path.with_suffix(".yaml.bak")
    shutil.move(str(agents_path), str(backup))
    print(f"Renamed {agents_path} -> {backup}")

    print("\nVerify with: safeyolo policy show --section agents")


if __name__ == "__main__":
    main()
