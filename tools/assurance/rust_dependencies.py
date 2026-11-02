#!/usr/bin/env python3
"""Report the locked proxy's production graph and measured direct-edge knockouts."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path

import tomlkit

ROOT = Path(__file__).resolve().parents[2]
GUARD = ROOT / "scripts/cargo_with_space.sh"


def production_manifest(directory: Path, without: str | None = None) -> dict:
    """Project only production targets; Cargo tree otherwise unifies dev features."""
    manifest = tomlkit.parse((directory / "Cargo.toml").read_text())
    manifest.pop("dev-dependencies", None)
    for target in manifest.get("target", {}).values():
        target.pop("dev-dependencies", None)
    if without is not None:
        del manifest["dependencies"][without]
    package = manifest["package"]
    for kind in ("test", "bench", "example"):
        manifest.pop(kind, None)
        package[f"auto{kind}s"] = False
    if (directory / "build.rs").exists() and package.get("build") is not False:
        package["build"] = str(directory / package.get("build", "build.rs"))
    if (directory / "src/lib.rs").exists():
        manifest.setdefault("lib", {})["path"] = str(directory / "src/lib.rs")
    for binary in manifest.get("bin", []):
        binary["path"] = str(directory / binary["path"])
    scopes = [manifest, *manifest.get("target", {}).values()]
    dependency_tables = [
        scope.get(kind, {}) for scope in scopes
        for kind in ("dependencies", "build-dependencies")
    ]
    dependency_tables.extend(manifest.get("patch", {}).values())
    for dependencies in dependency_tables:
        for dependency in dependencies.values():
            if isinstance(dependency, dict) and "path" in dependency:
                dependency["path"] = str((directory / dependency["path"]).resolve())
    return manifest


def cargo(directory: Path, *arguments: str) -> str:
    result = subprocess.run(
        [str(GUARD), *arguments], cwd=directory, check=True,
        text=True, stdout=subprocess.PIPE,
    )
    return result.stdout


def tree_packages(tree: str) -> tuple[dict, dict]:
    features: dict[str, set[str]] = {}
    edges: dict[str, set[str]] = {}
    parents: list[str] = []
    for line in tree.splitlines():
        package, activated = line.removesuffix(" (*)").split("\t", 1)
        match = re.match(r"(\d+)(\S+) v(\S+)", package)
        if match is None:
            raise ValueError(f"unexpected Cargo tree row: {line!r}")
        depth, name, version = match.groups()
        depth = int(depth)
        key = f"{name}@{version}"
        features.setdefault(key, set()).update(filter(None, activated.split(",")))
        edges.setdefault(key, set())
        if depth:
            edges[parents[depth - 1]].add(key)
        parents[depth:] = [key]
    return features, edges


def resolved_graph(metadata: dict, tree: str) -> dict:
    activated, edges = tree_packages(tree)
    root = metadata["resolve"]["root"]
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    # Metadata includes dev packages of path dependencies. Walk only normal/build
    # edges, even though the production root itself has no dev dependencies.
    active = set()
    pending = [root]
    while pending:
        package_id = pending.pop()
        if package_id in active:
            continue
        active.add(package_id)
        pending.extend(
            dep["pkg"] for dep in nodes[package_id]["deps"]
            if any(kind["kind"] != "dev" for kind in dep["dep_kinds"])
        )
    names = {key: f"{packages[key]['name']}@{packages[key]['version']}" for key in active}
    active = {key for key in active if names[key] in activated}
    names = {key: names[key] for key in active}
    if len(set(names.values())) != len(names):
        raise ValueError("same name/version from multiple sources needs explicit disambiguation")
    graph = {}
    for package_id in active - {root}:
        package, node = packages[package_id], nodes[package_id]
        graph[names[package_id]] = {
            "features": sorted(activated[names[package_id]]),
            "source": package["source"] or "local patch",
            "license": package["license"],
            "build_script": any("custom-build" in target["kind"] for target in package["targets"]),
            "proc_macro": any("proc-macro" in target["kind"] for target in package["targets"]),
            "links": package["links"],
            "dependencies": [
                {"package": names[dep["pkg"]], "kinds": [
                    kind for kind in dep["dep_kinds"] if kind["kind"] != "dev"
                ]}
                for dep in node["deps"] if dep["pkg"] in active
                and names[dep["pkg"]] in edges[names[package_id]]
                and any(kind["kind"] != "dev" for kind in dep["dep_kinds"])
            ],
        }
    aliases = {(dep.get("rename") or dep["name"]).replace("-", "_"): dep.get("rename") or dep["name"]
               for dep in packages[root]["dependencies"] if dep["kind"] != "dev"}
    direct = {aliases[dep["name"]]: names[dep["pkg"]]
              for dep in nodes[root]["deps"] if dep["pkg"] in active
              and any(kind["kind"] != "dev" for kind in dep["dep_kinds"])}
    return {"packages": dict(sorted(graph.items())), "direct": dict(sorted(direct.items()))}


def resolve(directory: Path, target: str, without: str | None = None, *, reasons: bool = False) -> dict:
    with tempfile.TemporaryDirectory(prefix="safeyolo-production-graph-") as temporary:
        projection = Path(temporary)
        (projection / "Cargo.toml").write_text(tomlkit.dumps(production_manifest(directory, without)))
        shutil.copyfile(directory / "Cargo.lock", projection / "Cargo.lock")
        # Only the disposable lock may be pruned. Existing versions stay pinned
        # by the product lock; no network or source compilation is involved.
        metadata = json.loads(cargo(projection, "metadata", "--offline", "--format-version=1",
                                    "--filter-platform", target))
        tree = cargo(projection, "tree", "--offline", "--locked", "--target", target,
                     "--edges", "normal,build", "--prefix", "depth", "--format", "{p}\t{f}")
        graph = resolved_graph(metadata, tree)
        if reasons:
            graph["feature_reasons"] = cargo(
                projection, "tree", "--offline", "--locked", "--target", target,
                "--edges", "normal,build,features", "--charset", "ascii",
            ).replace(str(projection), "<production-manifest>").replace(str(directory), "proxy")
        return graph


def removal_delta(before: dict, after: dict) -> dict:
    return {
        "removed": sorted(before["packages"].keys() - after["packages"].keys()),
        "feature_changes": {
            name: {"before": before["packages"][name]["features"], "after": package["features"]}
            for name, package in after["packages"].items()
            if name in before["packages"] and package["features"] != before["packages"][name]["features"]
        },
    }


def report(directory: Path, target: str, *, knockouts: bool) -> dict:
    graph = resolve(directory, target, reasons=True)
    manifest = tomlkit.parse((directory / "Cargo.toml").read_text())
    libraries = {row["name"]: row for row in tomlkit.parse((ROOT / "docs/assurance-map.toml").read_text())["libraries"]}
    decisions = {}
    for name, package_id in graph["direct"].items():
        dependency = manifest["dependencies"][name]
        selection = {"default-features": True, "features": []}
        if isinstance(dependency, dict):
            selection.update({key: dependency[key] for key in selection if key in dependency})
        mapped = libraries[name]
        if (mapped["version"] != package_id.split("@", 1)[1]
                or mapped["features"] != selection["features"]
                or mapped["default_features"] != selection["default-features"]):
            raise ValueError(f"assurance-map library selection differs from Cargo: {name}")
        decisions[name] = {"package": package_id, "requested": selection, "assurance_map": mapped}
        if knockouts:
            decisions[name]["knockout"] = removal_delta(graph, resolve(directory, target, name))
    duplicates = defaultdict(list)
    for package_id in graph["packages"]:
        duplicates[package_id.split("@", 1)[0]].append(package_id)
    return {
        "duplicates": {name: versions for name, versions in duplicates.items() if len(versions) > 1},
        "target": target, "profile": "release (graph is profile-independent)",
        "root_features": [], "dev_dependencies": dict(manifest.get("dev-dependencies", {})),
        "counts": {"direct": len(graph["direct"]), "resolved": len(graph["packages"]),
                   "transitive_only": len(graph["packages"].keys() - set(graph["direct"].values()))},
        "direct": decisions, "packages": graph["packages"], "feature_reasons": graph["feature_reasons"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="supported production Rust target triple")
    parser.add_argument("--knockouts", action="store_true", help="re-resolve after removing each direct edge")
    args = parser.parse_args()
    # The guard probes the real build filesystem although these commands only
    # resolve graphs. It must not select /tmp as a future compilation target.
    os.environ.setdefault("CARGO_TARGET_DIR", str(ROOT / "proxy/target"))
    print(json.dumps(report(ROOT / "proxy", args.target, knockouts=args.knockouts), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
