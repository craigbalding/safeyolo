#!/usr/bin/env python3
"""Temporarily select the owned sinkhole parent in a blackbox test instance."""

from __future__ import annotations

import argparse
import json
import os
import stat
import tempfile
from pathlib import Path

import yaml


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


def _yaml(path: Path) -> dict:
    value = yaml.safe_load(path.read_text())
    if not isinstance(value, dict) or not isinstance(value.get("proxy"), dict):
        raise ValueError(f"test instance has no proxy configuration: {path}")
    return value


def _native(path: Path) -> dict | None:
    if not path.exists():
        return None
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"native test configuration is not an object: {path}")
    return value


def restore(config_dir: Path) -> None:
    state_path = config_dir / "data" / "native-parent-original.json"
    if not state_path.exists():
        return
    state = json.loads(state_path.read_text())
    selected_ca = config_dir / "data" / "native-parent-trust.pem"
    if state["selected_ca"] != str(selected_ca):
        raise ValueError("native test trust path does not belong to this instance")
    selected = state["selected"]
    config_path = config_dir / "config.yaml"
    config = _yaml(config_path)
    if config["proxy"].get("upstream_proxy") == selected:
        if state["upstream_parent_present"]:
            config["proxy"]["upstream_proxy"] = state["upstream_proxy"]
        else:
            config["proxy"].pop("upstream_proxy", None)
    if config["proxy"].get("upstream_ca_cert") == state["selected_ca"]:
        if state["upstream_ca_present"]:
            config["proxy"]["upstream_ca_cert"] = state["upstream_ca_cert"]
        else:
            config["proxy"].pop("upstream_ca_cert", None)
    _replace(config_path, yaml.safe_dump(config))
    native_path = config_dir / "data" / "native.json"
    native = _native(native_path)
    if native is not None and native.get("parent_proxy") == selected:
        if state["native_parent_present"]:
            native["parent_proxy"] = state["native_parent"]
        else:
            native.pop("parent_proxy", None)
    if native is not None and native.get("upstream_ca_file") == state["selected_ca"]:
        if state["native_ca_present"]:
            native["upstream_ca_file"] = state["native_ca"]
        else:
            native.pop("upstream_ca_file", None)
    if native is not None:
        _replace(native_path, json.dumps(native, indent=2) + "\n")
    state_path.unlink()
    selected_ca.unlink(missing_ok=True)


def select(config_dir: Path, selected: str, test_ca: Path) -> None:
    state_path = config_dir / "data" / "native-parent-original.json"
    if state_path.exists():
        raise ValueError("a previous native test parent has not been restored")
    config_path = config_dir / "config.yaml"
    config = _yaml(config_path)
    native_path = config_dir / "data" / "native.json"
    native = _native(native_path)
    original_ca = (
        native.get("upstream_ca_file") if native is not None else config["proxy"].get("upstream_ca_cert")
    )
    selected_ca = config_dir / "data" / "native-parent-trust.pem"
    state = {
        "selected": selected,
        "selected_ca": str(selected_ca),
        "upstream_parent_present": "upstream_proxy" in config["proxy"],
        "upstream_proxy": config["proxy"].get("upstream_proxy"),
        "upstream_ca_present": "upstream_ca_cert" in config["proxy"],
        "upstream_ca_cert": config["proxy"].get("upstream_ca_cert"),
        "native_parent_present": native is not None and "parent_proxy" in native,
        "native_parent": native.get("parent_proxy") if native is not None else None,
        "native_ca_present": native is not None and "upstream_ca_file" in native,
        "native_ca": native.get("upstream_ca_file") if native is not None else None,
    }
    _replace(state_path, json.dumps(state) + "\n")
    try:
        roots = Path(original_ca).read_text() + "\n" if original_ca else ""
        _replace(selected_ca, roots + test_ca.read_text())
        config["proxy"]["upstream_proxy"] = selected
        config["proxy"]["upstream_ca_cert"] = str(selected_ca)
        _replace(config_path, yaml.safe_dump(config))
        if native is not None:
            native["parent_proxy"] = selected
            native["upstream_ca_file"] = str(selected_ca)
            _replace(native_path, json.dumps(native, indent=2) + "\n")
    except Exception:
        restore(config_dir)
        raise


def current(config_dir: Path) -> str:
    native = _native(config_dir / "data" / "native.json")
    if native is not None:
        return native.get("parent_proxy") or ""
    return os.environ.get("SAFEYOLO_UPSTREAM_PROXY") or (
        _yaml(config_dir / "config.yaml")["proxy"].get("upstream_proxy") or ""
    )


def current_ca(config_dir: Path) -> str:
    native = _native(config_dir / "data" / "native.json")
    if native is not None:
        return native.get("upstream_ca_file") or ""
    return _yaml(config_dir / "config.yaml")["proxy"].get("upstream_ca_cert") or ""


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
