"""Hatch hook that stamps immutable build identity into wheel package data."""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

_IMMUTABLE_REVISION = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


class CustomBuildHook(BuildHookInterface):
    """Generate build metadata outside the source tree for each wheel."""

    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict) -> None:  # noqa: ARG002
        if self.target_name != "wheel":
            return

        project_root = Path(self.root).resolve()
        revision = os.environ.get("SAFEYOLO_BUILD_REVISION", "").strip()
        if revision:
            revision = revision.lower()
            if not _IMMUTABLE_REVISION.fullmatch(revision):
                raise ValueError(
                    "SAFEYOLO_BUILD_REVISION must be a 40- or 64-character "
                    "Git object ID"
                )
            provenance = "build-environment"
        else:
            try:
                result = subprocess.run(
                    [
                        "git",
                        "-C",
                        self.root,
                        "rev-parse",
                        "--show-toplevel",
                        "--verify",
                        "HEAD",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
            except (OSError, subprocess.SubprocessError):
                result = None
            git_output = (
                result.stdout.splitlines()
                if result is not None and result.returncode == 0
                else []
            )
            if len(git_output) == 2:
                git_top_level, revision = git_output
                try:
                    checkout_matches_project = (
                        Path(git_top_level).resolve(strict=True) == project_root
                    )
                except OSError:
                    checkout_matches_project = False
                if not checkout_matches_project:
                    revision = ""
            else:
                revision = ""
            if revision and not _IMMUTABLE_REVISION.fullmatch(revision):
                revision = ""
            if revision:
                try:
                    status = subprocess.run(
                        [
                            "git",
                            "-C",
                            self.root,
                            "status",
                            "--porcelain=v1",
                            "--untracked-files=all",
                        ],
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                except (OSError, subprocess.SubprocessError):
                    status = None
                if (
                    status is None
                    or status.returncode != 0
                    or status.stdout.strip()
                ):
                    revision = ""
            provenance = "build-checkout" if revision else "unknown"

        build_identifier = os.environ.get("SAFEYOLO_BUILD_ID", "").strip() or None
        document = {
            "schema_version": 1,
            "package_version": str(self.metadata.version),
            "source_revision": revision or None,
            "build_identifier": build_identifier,
            "provenance": provenance,
            "state": "known" if revision else "unknown",
        }
        generated = Path(self.directory) / ".safeyolo-build-identity.json"
        generated.parent.mkdir(parents=True, exist_ok=True)
        generated.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self._generated = generated
        build_data["force_include"][str(generated)] = "safeyolo/_build_identity.json"

        # The installer builds the native proxy before invoking uv. Include
        # that exact release artifact in wheel installs so the native default
        # does not depend on the source checkout or an inherited environment
        # variable. Development checkouts without a release build retain the
        # Python comparator package path, while normal install.sh runs build
        # the release artifact before invoking this hook.
        native_binary = project_root / "proxy" / "target" / "release" / "safeyolo-proxy"
        if native_binary.is_file():
            build_data["force_include"][str(native_binary)] = "safeyolo/bin/safeyolo-proxy"

    def finalize(
        self,
        version: str,
        build_data: dict,
        artifact_path: str,  # noqa: ARG002
    ) -> None:
        generated = getattr(self, "_generated", None)
        if generated is not None:
            generated.unlink(missing_ok=True)
