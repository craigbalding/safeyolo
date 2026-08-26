#!/usr/bin/env python3
"""Enforce repository-wide mock contracts and boundary declarations."""

from __future__ import annotations

import ast
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests" / "assurance.toml"
TEST_ROOTS = (ROOT / "tests", ROOT / "cli" / "tests")
EXCLUDED_DIRS = {"__pycache__", "uds-networking"}


def _is_true_keyword(call: ast.Call, name: str) -> bool:
    return any(
        keyword.arg == name and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
        for keyword in call.keywords
    )


def _has_explicit_replacement(call: ast.Call, *, patch_object: bool) -> bool:
    """Return whether patch receives a concrete ``new`` object.

    ``patch.object(target, attribute)`` has two required positional arguments;
    the old checker mistook those for an explicit replacement and silently
    allowed an unspecced mock. ``new_callable`` is intentionally not an escape
    hatch because it still manufactures a mock without a target signature.
    """
    positional_new = len(call.args) >= (3 if patch_object else 2)
    keyword_new = any(keyword.arg == "new" for keyword in call.keywords)
    return positional_new or keyword_new


def _has_boundary_marker(tree: ast.Module) -> bool:
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if (
            isinstance(value, ast.Attribute)
            and value.attr == "assurance_boundary"
            and isinstance(value.value, ast.Attribute)
            and value.value.attr == "mark"
            and isinstance(value.value.value, ast.Name)
            and value.value.value.id == "pytest"
        ):
            return True
    return False


def audit_test_file(
    path: Path,
    subjects: set[str] | None = None,
    *,
    require_boundary_marker: bool = False,
) -> list[str]:
    """Return mock-contract and optional boundary-policy violations."""
    tree = ast.parse(path.read_text(), filename=str(path))
    issues: list[str] = []
    subjects = subjects or set()
    mock_constructors = {"Mock", "MagicMock", "AsyncMock"}
    patch_names = {"patch"}
    autospec_names = {"create_autospec"}
    mock_module_aliases: set[str] = set()

    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "unittest.mock":
            for alias in node.names:
                local_name = alias.asname or alias.name
                if alias.name in {"Mock", "MagicMock", "AsyncMock"}:
                    mock_constructors.add(local_name)
                elif alias.name == "patch":
                    patch_names.add(local_name)
                elif alias.name == "create_autospec":
                    autospec_names.add(local_name)
        elif isinstance(node, ast.ImportFrom) and node.module == "unittest":
            for alias in node.names:
                if alias.name == "mock":
                    mock_module_aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "unittest.mock":
                    mock_module_aliases.add(alias.asname or alias.name)

    if require_boundary_marker and not _has_boundary_marker(tree):
        issues.append("missing module-level pytest.mark.assurance_boundary")

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        line = node.lineno
        func = node.func

        if isinstance(func, ast.Name) and func.id in mock_constructors:
            issues.append(f"line {line}: bare {func.id}() is forbidden")
            continue

        if (
            isinstance(func, ast.Attribute)
            and func.attr in {"Mock", "MagicMock", "AsyncMock"}
            and isinstance(func.value, ast.Name)
            and func.value.id in mock_module_aliases
        ):
            issues.append(f"line {line}: bare {func.attr}() is forbidden")
            continue

        is_patch = isinstance(func, ast.Name) and func.id in patch_names
        is_module_patch = (
            isinstance(func, ast.Attribute)
            and func.attr == "patch"
            and isinstance(func.value, ast.Name)
            and func.value.id in mock_module_aliases
        )
        is_patch_object = (
            isinstance(func, ast.Attribute)
            and func.attr == "object"
            and isinstance(func.value, ast.Name)
            and func.value.id in patch_names
        )
        is_module_patch_object = (
            isinstance(func, ast.Attribute)
            and func.attr == "object"
            and isinstance(func.value, ast.Attribute)
            and func.value.attr == "patch"
            and isinstance(func.value.value, ast.Name)
            and func.value.value.id in mock_module_aliases
        )

        if (is_patch_object or is_module_patch_object) and node.args:
            target = node.args[0]
            if isinstance(target, ast.Name) and target.id in subjects:
                issues.append(f"line {line}: subject {target.id} may not be patched")

        is_any_patch = is_patch or is_module_patch or is_patch_object or is_module_patch_object
        is_object_patch = is_patch_object or is_module_patch_object
        if is_any_patch and not _has_explicit_replacement(node, patch_object=is_object_patch):
            if not _is_true_keyword(node, "autospec"):
                issues.append(f"line {line}: mock-producing patch requires autospec=True")

        is_create_autospec = (
            isinstance(func, ast.Name) and func.id in autospec_names
        ) or (
            isinstance(func, ast.Attribute)
            and func.attr == "create_autospec"
            and isinstance(func.value, ast.Name)
            and func.value.id in mock_module_aliases
        )
        if is_create_autospec and not _is_true_keyword(node, "spec_set"):
            issues.append(f"line {line}: create_autospec requires spec_set=True")

        if (
            isinstance(func, ast.Attribute)
            and func.attr == "setattr"
            and node.args
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id in subjects
        ):
            issues.append(f"line {line}: subject {node.args[0].id} may not be monkeypatched")

    return issues


def audit_boundary_file(path: Path, subjects: set[str]) -> list[str]:
    """Compatibility entry point for one declared assurance boundary."""
    return audit_test_file(path, subjects, require_boundary_marker=True)


def iter_test_files() -> list[Path]:
    """Return Python files pytest may import from the two configured roots."""
    files: list[Path] = []
    for root in TEST_ROOTS:
        files.extend(
            path
            for path in root.rglob("*.py")
            if not EXCLUDED_DIRS.intersection(path.relative_to(root).parts)
        )
    return sorted(set(files))


def audit_repository() -> list[str]:
    """Audit all tests, then apply stronger rules to declared boundaries."""
    config = tomllib.loads(MANIFEST.read_text())
    boundaries = config.get("boundary", {})
    issues: list[str] = []
    seen: set[Path] = set()

    for path in iter_test_files():
        relative = path.relative_to(ROOT).as_posix()
        policy = boundaries.get(relative)
        subjects = set(policy.get("subjects", [])) if policy else set()
        for issue in audit_test_file(
            path,
            subjects,
            require_boundary_marker=policy is not None,
        ):
            issues.append(f"{relative}: {issue}")
        seen.add(path)

    for relative in boundaries:
        path = ROOT / relative
        if path not in seen:
            issues.append(f"{relative}: declared file does not exist")
    return issues


def audit_manifest(manifest: Path = MANIFEST) -> list[str]:
    config = tomllib.loads(manifest.read_text())
    issues: list[str] = []
    for relative_path, policy in config.get("boundary", {}).items():
        path = ROOT / relative_path
        if not path.is_file():
            issues.append(f"{relative_path}: declared file does not exist")
            continue
        for issue in audit_boundary_file(path, set(policy.get("subjects", []))):
            issues.append(f"{relative_path}: {issue}")
    return issues


def main() -> int:
    issues = audit_repository()
    if issues:
        print("Test assurance violations:")
        for issue in issues:
            print(f"  - {issue}")
        return 1
    print("Test assurance checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
