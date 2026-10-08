#!/usr/bin/env python3
"""Temporarily select the owned sinkhole parent in a blackbox test instance."""

from __future__ import annotations

import argparse
import json
import os
import stat
import tempfile
from pathlib import Path


def _replace(path: Path, content: str) -> None:
    mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o600
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as output:
        temporary = Path(output.name)
        output.write(content)
    try:
        temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _config(config_dir: Path):
    import tomlkit
    return tomlkit.parse((config_dir / "config.toml").read_text())


def restore(config_dir: Path) -> None:
    state_path = config_dir / "data/native-parent-original.json"
    if not state_path.exists():
        return
    state = json.loads(state_path.read_text())
    trust = config_dir / "data/native-parent-trust.pem"
    if state["selected_ca"] != str(trust):
        raise ValueError("native test trust path does not belong to this instance")
    config = _config(config_dir)
    for key, selected in (("parent_proxy", state["selected"]), ("upstream_ca_file", str(trust))):
        if config.get(key) == selected:
            if key in state["original"]:
                config[key] = state["original"][key]
            else:
                config.pop(key, None)
    _replace(config_dir / "config.toml", config.as_string())
    state_path.unlink()
    trust.unlink(missing_ok=True)


def select(config_dir: Path, selected: str, test_ca: Path) -> None:
    state_path = config_dir / "data/native-parent-original.json"
    if state_path.exists():
        raise ValueError("a previous native test parent has not been restored")
    config = _config(config_dir)
    trust = config_dir / "data/native-parent-trust.pem"
    original = {key: config[key] for key in ("parent_proxy", "upstream_ca_file") if key in config}
    state = {"selected": selected, "selected_ca": str(trust), "original": original}
    _replace(state_path, json.dumps(state) + "\n")
    try:
        ca = original.get("upstream_ca_file")
        ca_path = config_dir / ca if ca else None
        roots = ca_path.read_text() + "\n" if ca_path else ""
        _replace(trust, roots + test_ca.read_text())
        config["parent_proxy"] = selected
        config["upstream_ca_file"] = str(trust)
        _replace(config_dir / "config.toml", config.as_string())
    except (OSError, ValueError):
        restore(config_dir)
        raise


def current(config_dir: Path) -> str:
    return _config(config_dir).get("parent_proxy") or ""


def current_ca(config_dir: Path) -> str:
    ca = _config(config_dir).get("upstream_ca_file")
    return str((config_dir / ca).resolve()) if ca else ""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("select", "restore", "current", "current-ca"))
    parser.add_argument("config_dir", type=Path)
    parser.add_argument("selected", nargs="?")
    parser.add_argument("--test-ca", type=Path)
    args = parser.parse_args()
    if args.action == "restore":
        restore(args.config_dir)
    elif args.action == "current":
        print(current(args.config_dir))
    elif args.action == "current-ca":
        print(current_ca(args.config_dir))
    else:
        if not args.selected or args.test_ca is None:
            parser.error("select requires the owned parent URL and --test-ca")
        select(args.config_dir, args.selected, args.test_ca)


if __name__ == "__main__":
    main()
