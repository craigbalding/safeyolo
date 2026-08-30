#!/usr/bin/env python3
"""Mechanically validate the repository-controlled Dispatch site."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlsplit

import yaml

from safeyolo.coord import dispatch

_LINK_RE = re.compile(r"(?<!!)\[[^\]\n]+\]\(([^)\n]+)\)")
_PUBLICATION_PATHS = (
    re.compile(r"^site/_sources/dispatch/[^/]+\.json$"),
    re.compile(r"^site/(?:dispatch|snapshots|topics)/[^/]+\.md$"),
)


class SiteValidationError(ValueError):
    pass


@dataclass(frozen=True)
class MarkdownPage:
    path: Path
    front_matter: dict[str, Any]
    content: str


def _front_matter(path: Path, content: str) -> dict[str, Any]:
    lines = content.splitlines()
    if not lines or lines[0] != "---":
        raise SiteValidationError(f"{path}: Markdown page has no YAML front matter")
    try:
        end = lines.index("---", 1)
    except ValueError as exc:
        raise SiteValidationError(f"{path}: YAML front matter is not closed") from exc
    try:
        value = yaml.safe_load("\n".join(lines[1:end]))
    except yaml.YAMLError as exc:
        raise SiteValidationError(f"{path}: invalid YAML front matter") from exc
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise SiteValidationError(f"{path}: YAML front matter must be a mapping")
    return value


def _date_text(value: Any) -> str:
    if hasattr(value, "isoformat"):
        return str(value.isoformat())
    return str(value)


def _validate_generated_front_matter(page: MarkdownPage, relative: Path) -> None:
    front = page.front_matter
    relative_text = relative.as_posix()
    if relative.parts[0] in {"dispatch", "snapshots"}:
        required = {
            "dispatch_schema",
            "editor",
            "end",
            "layout",
            "period",
            "permalink",
            "start",
        }
        if set(front) != required or front.get("dispatch_schema") != "safeyolo.dispatch/v1":
            raise SiteValidationError(f"{page.path}: invalid Dispatch front matter schema")
        expected_permalink = f"/{relative.with_suffix('').as_posix()}/"
        if front.get("permalink") != expected_permalink or front.get("editor") != "Relay":
            raise SiteValidationError(f"{page.path}: invalid Dispatch permalink or editor")
        if relative.parts[0] == "dispatch":
            expected_start = relative.stem
            if front.get("period") != "daily" or _date_text(front.get("start")) != expected_start:
                raise SiteValidationError(f"{page.path}: daily date does not match its path")
            if _date_text(front.get("end")) != expected_start:
                raise SiteValidationError(f"{page.path}: daily period is not one day")
    elif relative.parts[0] == "topics":
        required = {
            "dispatch_schema",
            "editor",
            "layout",
            "permalink",
            "topic",
            "updated_through",
        }
        if set(front) != required or front.get("dispatch_schema") != "safeyolo.dispatch-topic/v1":
            raise SiteValidationError(f"{page.path}: invalid topic front matter schema")
        if front.get("topic") != relative.stem or front.get("editor") != "Relay":
            raise SiteValidationError(f"{page.path}: topic metadata does not match its path")
        if front.get("permalink") != f"/topics/{relative.stem}/":
            raise SiteValidationError(f"{page.path}: invalid topic permalink")
    else:
        raise SiteValidationError(f"site/{relative_text}: unexpected generated Markdown path")


def _expected_generated(site_root: Path) -> dict[Path, str]:
    sources = sorted((site_root / "_sources" / "dispatch").glob("*.json"))
    expected: dict[Path, tuple[tuple, str, Path]] = {}
    periods: set[tuple[str, str, str]] = set()
    for source in sources:
        if source.is_symlink() or not source.is_file():
            raise SiteValidationError(f"{source}: source must be a regular non-symlink file")
        try:
            manifest = dispatch.load_manifest(source)
            generated = dispatch.generate_files(manifest)
        except dispatch.DispatchError as exc:
            raise SiteValidationError(f"{source}: {exc}") from exc
        period = (
            manifest.period.kind.value,
            manifest.period.start.isoformat(),
            manifest.period.end.isoformat(),
        )
        if period in periods:
            raise SiteValidationError(f"{source}: duplicate Dispatch period {period}")
        periods.add(period)
        for item in generated:
            relative = item.relative_path
            rank = (manifest.period.end, manifest.period.start, source.name)
            current = expected.get(relative)
            if current is not None and relative.parts[0] != "topics":
                raise SiteValidationError(f"{source}: duplicate generated path {relative}")
            if current is not None and current[0][:2] == rank[:2]:
                raise SiteValidationError(f"{source}: ambiguous same-period topic {relative}")
            if current is None or rank > current[0]:
                expected[relative] = (rank, item.content, source)
    return {relative: value[1] for relative, value in expected.items()}


def _without_fenced_code(content: str) -> str:
    kept: list[str] = []
    fenced = False
    for line in content.splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if not fenced:
            kept.append(line)
    return "\n".join(kept)


def _validate_links(pages: list[MarkdownPage], site_root: Path) -> None:
    permalinks: dict[str, Path] = {}
    for page in pages:
        permalink = page.front_matter.get("permalink")
        if isinstance(permalink, str):
            if not permalink.startswith("/") or not permalink.endswith("/"):
                raise SiteValidationError(f"{page.path}: permalink must be an absolute directory path")
            if ".." in PurePosixPath(permalink).parts:
                raise SiteValidationError(f"{page.path}: permalink escapes the site")
            if permalink in permalinks:
                raise SiteValidationError(f"{page.path}: duplicate permalink {permalink}")
            permalinks[permalink] = page.path

    for page in pages:
        for raw in _LINK_RE.findall(_without_fenced_code(page.content)):
            destination = raw.strip()
            if destination.startswith("<") and destination.endswith(">"):
                destination = destination[1:-1]
            split = urlsplit(destination)
            if split.scheme:
                try:
                    dispatch.validate_public_url(destination, f"{page.path} link")
                except dispatch.DispatchError as exc:
                    raise SiteValidationError(str(exc)) from exc
                continue
            if split.netloc:
                raise SiteValidationError(f"{page.path}: protocol-relative links are not allowed")
            if destination.startswith("#"):
                continue
            decoded = unquote(split.path)
            if not decoded:
                continue
            if decoded.startswith("/"):
                public_path = decoded
            else:
                origin = page.front_matter.get("permalink", "/")
                origin_path = PurePosixPath(str(origin))
                public_path = "/" + (origin_path / decoded).as_posix().lstrip("/")
            if public_path.endswith("/") and public_path in permalinks:
                continue
            relative = PurePosixPath(public_path.lstrip("/"))
            if ".." in relative.parts:
                raise SiteValidationError(f"{page.path}: link escapes the site: {destination}")
            target = site_root.joinpath(*relative.parts)
            if not target.is_file():
                raise SiteValidationError(f"{page.path}: broken local link {destination}")


def publication_changed_paths(base: str) -> tuple[str, ...]:
    result = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=ACMRTUXBD", f"{base}...HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return tuple(line for line in result.stdout.splitlines() if line)


def validate_publication_scope(paths: tuple[str, ...]) -> None:
    unexpected = [path for path in paths if not any(pattern.fullmatch(path) for pattern in _PUBLICATION_PATHS)]
    if unexpected:
        raise SiteValidationError(
            "publication branch changed paths outside the fixed site content allowlist: "
            + ", ".join(unexpected)
        )


def validate_site(site_root: Path) -> None:
    if site_root.is_symlink() or not site_root.is_dir():
        raise SiteValidationError(f"{site_root}: site root must be a regular directory")
    for path in site_root.rglob("*"):
        if path.is_symlink():
            raise SiteValidationError(f"{path}: symlinks are not allowed in the publication tree")
        if path.is_file():
            relative_text = path.relative_to(site_root).as_posix()
            allowed = (
                relative_text in {"CNAME", "_config.yml", "index.md"}
                or re.fullmatch(r"_sources/dispatch/[^/]+\.json", relative_text)
                or re.fullmatch(r"(?:dispatch|snapshots|topics)/[^/]+\.md", relative_text)
            )
            if not allowed:
                raise SiteValidationError(f"{path}: file is outside the fixed site allowlist")
            try:
                content = path.read_text(encoding="utf-8")
            except UnicodeError as exc:
                raise SiteValidationError(f"{path}: publication files must be UTF-8 text") from exc
            dispatch.validate_publication_text(content, f"site/{relative_text}")

    expected = _expected_generated(site_root)
    generated_roots = (site_root / "dispatch", site_root / "snapshots", site_root / "topics")
    actual_generated = {
        path.relative_to(site_root)
        for root in generated_roots
        if root.exists()
        for path in root.rglob("*.md")
    }
    if actual_generated != set(expected):
        missing = sorted(str(path) for path in set(expected) - actual_generated)
        stale = sorted(str(path) for path in actual_generated - set(expected))
        raise SiteValidationError(f"generated path mismatch; missing={missing}, stale={stale}")

    pages: list[MarkdownPage] = []
    for path in sorted(site_root.rglob("*.md")):
        content = path.read_text(encoding="utf-8")
        page = MarkdownPage(path, _front_matter(path, content), content)
        pages.append(page)
        relative = path.relative_to(site_root)
        if relative in expected:
            if content != expected[relative]:
                raise SiteValidationError(f"{path}: generated content is stale")
            _validate_generated_front_matter(page, relative)
    _validate_links(pages, site_root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site-root", type=Path, default=Path("site"))
    parser.add_argument(
        "--publication-base",
        help="Also require every changed path since this git revision to be publication content.",
    )
    args = parser.parse_args(argv)
    try:
        validate_site(args.site_root)
        if args.publication_base:
            validate_publication_scope(publication_changed_paths(args.publication_base))
    except (OSError, subprocess.SubprocessError, SiteValidationError, dispatch.DispatchError) as exc:
        print(f"Dispatch site validation failed: {exc}", file=sys.stderr)
        return 1
    print("Dispatch site validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
