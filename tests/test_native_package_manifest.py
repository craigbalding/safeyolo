"""Unit checks for the post-cutover native wheel verifier."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from scripts.verify_native_package import inspect_wheel

REQUIRED = (
    "safeyolo/bin/safeyolo-proxy",
    "safeyolo/proxy.py",
    "safeyolo/rust_proxy.py",
    "safeyolo-0.1.0.dist-info/METADATA",
)


def write_wheel(path: Path, *, omit: str | None = None, extra: str | None = None) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name in REQUIRED:
            if name == omit:
                continue
            info = zipfile.ZipInfo(name)
            if name == "safeyolo/bin/safeyolo-proxy":
                info.external_attr = 0o100755 << 16
                content = b"native executable"
            else:
                content = b"package"
            archive.writestr(info, content)
        if extra:
            archive.writestr(extra, b"obsolete")


def test_manifest_reports_native_binary_without_python_policy_package(tmp_path: Path) -> None:
    wheel = tmp_path / "safeyolo-0.1.0-py3-none-any.whl"
    write_wheel(wheel)

    result = inspect_wheel(wheel)

    assert result["native_binary"] == "safeyolo/bin/safeyolo-proxy"
    assert result["native_binary_size"] == len(b"native executable")
    assert result["native_binary_mode"] == "0755"
    assert "pdp/__init__.py" not in result["required_members"]


def test_manifest_fails_closed_when_native_binary_is_missing(tmp_path: Path) -> None:
    wheel = tmp_path / "safeyolo-0.1.0-py3-none-any.whl"
    write_wheel(wheel, omit="safeyolo/bin/safeyolo-proxy")

    with pytest.raises(ValueError, match="safeyolo/bin/safeyolo-proxy"):
        inspect_wheel(wheel)


@pytest.mark.parametrize("obsolete", ["pdp/__init__.py", "safeyolo/core/plumb_service.py",
                                     "safeyolo/storage/flow_store.py", "safeyolo/coord/mattermost.py",
                                     "safeyolo/coord/mattermost_actions.py"])
def test_manifest_rejects_retired_python_production_code(tmp_path: Path, obsolete: str) -> None:
    wheel = tmp_path / "safeyolo-0.1.0-py3-none-any.whl"
    write_wheel(wheel, extra=obsolete)

    with pytest.raises(ValueError, match="retired Python production code"):
        inspect_wheel(wheel)
