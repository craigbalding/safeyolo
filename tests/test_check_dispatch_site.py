"""Tests for the mechanical Dispatch publication boundary."""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "check_dispatch_site.py"
SPEC = importlib.util.spec_from_file_location("check_dispatch_site", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
check_dispatch_site = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check_dispatch_site
SPEC.loader.exec_module(check_dispatch_site)


def copy_site(tmp_path: Path) -> Path:
    destination = tmp_path / "site"
    shutil.copytree(REPO_ROOT / "site", destination)
    return destination


def test_committed_site_is_fully_reproducible_and_linked() -> None:
    check_dispatch_site.validate_site(REPO_ROOT / "site")


def test_stale_generated_bytes_fail(tmp_path: Path) -> None:
    site = copy_site(tmp_path)
    page = site / "dispatch" / "2026-08-29.md"
    page.write_text(page.read_text() + "\nchanged\n")
    with pytest.raises(check_dispatch_site.SiteValidationError, match="generated content is stale"):
        check_dispatch_site.validate_site(site)


def test_obvious_secret_and_broken_local_link_fail(tmp_path: Path) -> None:
    site = copy_site(tmp_path)
    index = site / "index.md"
    index.write_text(index.read_text() + "\n`github_pat_abcdefghijklmnop`\n")
    with pytest.raises(Exception, match="credential or secret"):
        check_dispatch_site.validate_site(site)

    site = copy_site(tmp_path / "links")
    index = site / "index.md"
    index.write_text(index.read_text() + "\n[Missing](/not-present/)\n")
    with pytest.raises(check_dispatch_site.SiteValidationError, match="broken local link"):
        check_dispatch_site.validate_site(site)

    site = copy_site(tmp_path / "private-link")
    index = site / "index.md"
    index.write_text(index.read_text() + "\n[Private](https://localhost/status)\n")
    with pytest.raises(check_dispatch_site.SiteValidationError, match="public HTTPS"):
        check_dispatch_site.validate_site(site)


def test_publication_branch_scope_is_fixed_to_content_paths() -> None:
    check_dispatch_site.validate_publication_scope(
        (
            "site/_sources/dispatch/2026-08-30.json",
            "site/dispatch/2026-08-30.md",
            "site/snapshots/2026-W35.md",
            "site/topics/coord.md",
        )
    )
    with pytest.raises(check_dispatch_site.SiteValidationError, match="outside"):
        check_dispatch_site.validate_publication_scope(
            ("site/dispatch/2026-08-30.md", ".github/workflows/pages.yml")
        )


def test_workflows_keep_manual_publication_default_and_deploy_separate() -> None:
    publication = (REPO_ROOT / ".github/workflows/dispatch-publication.yml").read_text()
    pages = (REPO_ROOT / ".github/workflows/pages.yml").read_text()
    assert "pull_request:" in publication
    assert "pull_request_target" not in publication
    assert "contents: write" not in publication
    assert "merge" not in publication.lower()
    assert "startsWith(github.head_ref, 'dispatch/')" in publication
    assert "workflow_dispatch:" in pages
    assert "environment:\n      name: github-pages" in pages
    assert "pull_request:" not in pages
