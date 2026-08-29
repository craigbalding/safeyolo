#!/usr/bin/env python3
"""Render or verify repository-controlled SafeYolo Dispatch Markdown."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from safeyolo.coord import dispatch


def _existing_topics(manifest: dispatch.DispatchManifest, output_root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for topic in manifest.topic_updates:
        relative = topic.relative_path
        existing = dispatch.read_existing_generated_file(output_root, relative)
        if existing is not None:
            result[relative.as_posix()] = existing
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate deterministic Markdown only; this command does not publish, "
            "deploy, schedule, or mutate SafeYolo policy."
        )
    )
    parser.add_argument("source", type=Path, help="Strict public editorial JSON source")
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("site"),
        help="Repository publication tree (default: site)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail without writing when generated files are missing or stale",
    )
    args = parser.parse_args(argv)
    try:
        manifest = dispatch.load_manifest(args.source)
        files = dispatch.generate_files(
            manifest,
            existing_topics=_existing_topics(manifest, args.output_root),
        )
        changed = dispatch.write_generated_files(args.output_root, files, check=args.check)
    except dispatch.DispatchError as exc:
        print(f"Dispatch generation failed: {exc}", file=sys.stderr)
        return 1
    if not files:
        print("No substantive Dispatch or material topic update; wrote nothing.")
    elif args.check:
        print(f"Dispatch output is current ({len(files)} files).")
    elif changed:
        print("Generated: " + ", ".join(path.as_posix() for path in changed))
    else:
        print("Dispatch output already current; wrote nothing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
