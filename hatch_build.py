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
                    ["git", "-C", self.root, "rev-parse", "--verify", "HEAD"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
            except (OSError, subprocess.SubprocessError):
                result = None
            revision = result.stdout.strip() if result is not None and result.returncode == 0 else ""
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

    def finalize(
        self,
        version: str,
        build_data: dict,
        artifact_path: str,  # noqa: ARG002
    ) -> None:
        generated = getattr(self, "_generated", None)
        if generated is not None:
            generated.unlink(missing_ok=True)
