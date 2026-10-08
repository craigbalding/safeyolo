"""Validation for identifiers that cross process and URL boundaries."""

import re

TASK_ID_MAX_LENGTH = 128
_TASK_ID_RE = re.compile(rf"[A-Za-z0-9][A-Za-z0-9._-]{{0,{TASK_ID_MAX_LENGTH - 1}}}\Z")


def validate_task_id(value: str) -> str:
    """Return a task ID that is safe to use as one URL path segment.

    Task IDs deliberately use a narrow ASCII contract. This keeps their value
    identical across JSON, policy metadata, logs, and HTTP routing without
    relying on repeated decoding or normalization.
    """
    if not isinstance(value, str) or not _TASK_ID_RE.fullmatch(value):
        raise ValueError(
            "Task ID must be 1-128 ASCII letters, digits, dots, underscores, "
            "or hyphens, and must start with a letter or digit"
        )
    return value
