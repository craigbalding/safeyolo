"""Edit native listener configuration without normalizing unrelated JSON."""

from __future__ import annotations

import json

# Only token boundaries are needed here. Keep numeric parsing independent of
# Python's float range and integer conversion limit; original text is retained.
_DECODER = json.JSONDecoder(parse_int=str, parse_float=str)


def _space(source: str, offset: int) -> int:
    while offset < len(source) and source[offset] in " \t\r\n":
        offset += 1
    return offset


def _members(source: str) -> tuple[list[tuple[str, int, int]], int]:
    start = _space(source, 0)
    value, end = _DECODER.raw_decode(source, start)
    if not isinstance(value, dict) or _space(source, end) != len(source):
        raise ValueError("Native configuration must be one JSON object")
    members = []
    offset = _space(source, start + 1)
    while source[offset] != "}":
        name, key_end = _DECODER.raw_decode(source, offset)
        start = _space(source, _space(source, key_end) + 1)
        _, end = _DECODER.raw_decode(source, start)
        members.append((name, start, end))
        offset = _space(source, end)
        if source[offset] == ",":
            offset = _space(source, offset + 1)
    return members, offset


def _items(source: str, start: int, end: int) -> list[str]:
    if source[start] != "[":
        raise ValueError("Native listeners must be a JSON array")
    items = []
    offset = _space(source, start + 1)
    while offset < end - 1:
        _, item_end = _DECODER.raw_decode(source, offset)
        items.append(source[offset:item_end])
        offset = _space(source, item_end)
        if source[offset] == ",":
            offset = _space(source, offset + 1)
    return items


def update_listeners(source: str, original: list, updated: list, reload_id: str | None = None) -> str:
    """Replace the last listener array and, optionally, the last reload ID.

    ``original`` is the listener list parsed from ``source``. Retained custom
    entries in ``updated`` must be the same objects from that list; new entries
    are serialized normally. Untouched members and retained entry text remain
    literal, including duplicate fields for the Rust decoder to interpret.
    """
    members, closing = _members(source)
    listeners = next(((start, end) for name, start, end in reversed(members) if name == "listeners"), None)
    if listeners is None:
        raise ValueError("Native configuration needs listeners")
    start, end = listeners
    items = _items(source, start, end)
    if len(items) != len(original):
        raise ValueError("Original listeners do not match the source array")
    retained = {id(entry): text for entry, text in zip(original, items, strict=True)}
    rendered = [retained[id(entry)] if id(entry) in retained else json.dumps(entry) for entry in updated]
    edits = [(start, end, "[" + ",".join(rendered) + "]")]
    if reload_id is not None:
        reload_span = next(((start, end) for name, start, end in reversed(members) if name == "reload_id"), None)
        encoded = json.dumps(reload_id)
        if reload_span is None:
            edits.append((closing, closing, ',"reload_id":' + encoded))
        else:
            edits.append((*reload_span, encoded))
    for start, end, text in sorted(edits, reverse=True):
        source = source[:start] + text + source[end:]
    return source
