"""Tests for security-sensitive identifier validation."""

import pytest

from safeyolo.core.identifiers import validate_task_id


@pytest.mark.parametrize(
    "task_id",
    [
        "a",
        "task-abc",
        "task_abc.123",
        "550e8400-e29b-41d4-a716-446655440000",
        "a" * 128,
    ],
)
def test_validate_task_id_accepts_documented_identifier_characters(task_id):
    assert validate_task_id(task_id) == task_id


@pytest.mark.parametrize(
    "task_id",
    [
        "",
        ".",
        "..",
        "../health",
        "task/name",
        "task?admin=true",
        "task#fragment",
        "//other-host",
        "http://other-host",
        "task\nINFO forged",
        "task\rINFO forged",
        "task\x1b[31m",
        "täsk",
        "-leading-dash",
        ".leading-dot",
        "a" * 129,
    ],
)
def test_validate_task_id_rejects_values_that_are_not_one_safe_path_segment(task_id):
    with pytest.raises(ValueError, match="Task ID"):
        validate_task_id(task_id)


@pytest.mark.parametrize("task_id", [None, 42, b"task"])
def test_validate_task_id_rejects_non_strings(task_id):
    with pytest.raises(ValueError, match="Task ID"):
        validate_task_id(task_id)
