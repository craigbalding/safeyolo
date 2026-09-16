#!/usr/bin/env python3
"""Compare the native HAR replay with the pinned installed-source entries.

The replay test prints complete HAR documents as hexadecimal records.  This
checker deliberately uses only the Python standard library: ``json.loads``
preserves the source fixture's escaped surrogateescape values, while Rust's
JSON value type cannot represent those strings.  ``run`` invokes one fixed,
named Rust test, records its combined output, and then performs the same strict
comparison as ``check``.
"""

import argparse
import copy
import json
import os
import subprocess
import sys
from pathlib import Path

REPLAY_TEST = (
    "traffic_view::export::har_tests::"
    "har_replays_owned_source_input_recipes_for_full_entry_comparison"
)


class ReplayFailure(Exception):
    """A malformed replay or a source/native entry mismatch."""


def first_difference(actual, expected, path="entry"):
    """Return the first complete-entry difference, or ``None``."""
    if numbers_equal(actual, expected):
        return None
    if type(actual) is not type(expected):
        return f"{path}: types {type(actual).__name__} != {type(expected).__name__}"
    if isinstance(actual, dict):
        return mapping_difference(actual, expected, path)
    if isinstance(actual, list):
        return sequence_difference(actual, expected, path)
    if actual != expected:
        return f"{path}: {actual!r} != {expected!r}"
    return None


def numbers_equal(actual, expected):
    return (
        isinstance(actual, (int, float))
        and not isinstance(actual, bool)
        and isinstance(expected, (int, float))
        and not isinstance(expected, bool)
        and actual == expected
    )


def mapping_difference(actual, expected, path):
    if actual.keys() != expected.keys():
        return f"{path}: keys {sorted(actual)} != {sorted(expected)}"
    for key in actual:
        difference = first_difference(actual[key], expected[key], f"{path}.{key}")
        if difference:
            return difference
    return None


def sequence_difference(actual, expected, path):
    if len(actual) != len(expected):
        return f"{path}: lengths {len(actual)} != {len(expected)}"
    for index in range(len(actual)):
        difference = first_difference(actual[index], expected[index], f"{path}[{index}]")
        if difference:
            return difference
    return None


def replay_entry(encoded, name, line_number):
    try:
        document = json.loads(bytes.fromhex(encoded))
    except (ValueError, json.JSONDecodeError) as error:
        raise ReplayFailure(f"line {line_number}: invalid {name} HAR JSON: {error}") from error
    if not isinstance(document, dict) or not isinstance(document.get("log"), dict):
        raise ReplayFailure(f"line {line_number}: {name} is not a HAR document")
    entries = document["log"].get("entries")
    if not isinstance(entries, list) or len(entries) != 1:
        count = len(entries) if isinstance(entries, list) else "non-list"
        raise ReplayFailure(f"line {line_number}: {name} has {count} HAR entries")
    if not isinstance(entries[0], dict):
        raise ReplayFailure(f"line {line_number}: {name} entry is not an object")
    return entries[0]


def parse_replay_lines(lines):
    actual = {}
    skipped = {}
    for line_number, line in enumerate(lines, 1):
        if line.startswith("HAR_REPLAY_OK\t"):
            fields = line.split("\t")
            if len(fields) != 3 or not fields[1] or not fields[2]:
                raise ReplayFailure(f"line {line_number}: malformed HAR_REPLAY_OK record")
            _, name, encoded = fields
            if name in actual or name in skipped:
                raise ReplayFailure(f"line {line_number}: duplicate replay record {name}")
            actual[name] = replay_entry(encoded, name, line_number)
        elif line.startswith("HAR_REPLAY_SKIP\t"):
            fields = line.split("\t")
            if len(fields) != 3 or not fields[1] or not fields[2]:
                raise ReplayFailure(f"line {line_number}: malformed HAR_REPLAY_SKIP record")
            _, name, reason = fields
            if name in actual or name in skipped:
                raise ReplayFailure(f"line {line_number}: duplicate replay record {name}")
            skipped[name] = reason
    if not actual and not skipped:
        raise ReplayFailure("replay output contains no HAR_REPLAY records")
    return actual, skipped


def read_replay_log(path):
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ReplayFailure(f"cannot read replay log {path}: {error}") from error
    return parse_replay_lines(text.splitlines())


def input_kinds(inputs):
    flows = inputs.get("flows")
    if not isinstance(flows, list):
        raise ReplayFailure("input fixture has no flow list")
    kinds = {}
    for flow in flows:
        name = flow.get("name") if isinstance(flow, dict) else None
        kind = flow.get("kind") if isinstance(flow, dict) else None
        if not isinstance(name, str) or not isinstance(kind, str) or not name:
            raise ReplayFailure("input fixture contains an invalid flow identity")
        if name in kinds:
            raise ReplayFailure(f"input fixture repeats flow {name}")
        kinds[name] = kind
    return kinds


def selection_parts(selection, kinds):
    selection_name = selection.get("name") if isinstance(selection, dict) else None
    selected = selection.get("selected") if isinstance(selection, dict) else None
    try:
        entries = selection["har"]["log"]["entries"]
    except (KeyError, TypeError):
        raise ReplayFailure(f"{selection_name}: missing HAR entry list") from None
    if not isinstance(selection_name, str) or not isinstance(selected, list):
        raise ReplayFailure("source fixture contains an invalid selection")
    if not isinstance(entries, list):
        raise ReplayFailure(f"{selection_name}: HAR entries are not a list")
    for name in selected:
        if name not in kinds:
            raise ReplayFailure(f"{selection_name}: unknown selected flow {name}")
    http_selected = [name for name in selected if kinds[name] == "http"]
    if len(http_selected) != len(entries):
        raise ReplayFailure(
            f"{selection_name}: {len(http_selected)} HTTP selections but "
            f"{len(entries)} HAR entries"
        )
    return selection_name, http_selected, entries


def source_entries(source, kinds):
    selections = source.get("selections")
    if not isinstance(selections, list):
        raise ReplayFailure("source fixture has no selection list")
    expected = []
    standalone = None
    for selection in selections:
        selection_name, http_selected, entries = selection_parts(selection, kinds)
        if selection_name == "reused_connection_exported_alone":
            standalone = (http_selected, entries)
        expected.extend(
            (selection_name, http_selected[index], entries[index])
            for index in range(len(http_selected))
        )
    if standalone is None:
        raise ReplayFailure("standalone reused-connection selection is missing")
    selected, entries = standalone
    if selected != ["timed_reused"] or len(entries) != 1:
        raise ReplayFailure("standalone reused-connection selection is not singular")
    return expected, entries[0]


def load_contract(root):
    try:
        source = json.loads(
            (root / "proxy/tests/traffic_har_source.json").read_text(encoding="utf-8")
        )
        inputs = json.loads(
            (root / "proxy/tests/traffic_har_inputs.json").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as error:
        raise ReplayFailure(f"cannot read HAR source contract: {error}") from error
    kinds = input_kinds(inputs)
    expected, standalone = source_entries(source, kinds)
    return kinds, expected, standalone


def compare(root, replay_log):
    kinds, expected, standalone_expected = load_contract(root)
    actual, skipped = read_replay_log(replay_log)
    if skipped:
        raise ReplayFailure(f"unexpected replay skips: {sorted(skipped)}")
    http_names = {name for name, kind in kinds.items() if kind == "http"}
    expected_names = http_names
    if set(actual) != expected_names:
        raise ReplayFailure(
            f"replay names differ: actual={sorted(actual)} "
            f"expected={sorted(expected_names)}"
        )

    compared = 0
    for selection_name, name, expected_entry in expected:
        if name == "timed_reused":
            expected_entry = standalone_expected
        difference = first_difference(actual[name], expected_entry)
        if difference:
            raise ReplayFailure(f"{selection_name} / {name}: {difference}")
        compared += 1
    difference = first_difference(actual["timed_reused"], standalone_expected)
    if difference:
        raise ReplayFailure(
            "reused_connection_exported_alone / timed_reused: " + difference
        )
    print(f"compared {compared} source entries across {len(actual)} HTTP recipes")
    print("checked standalone timed_reused against reused_connection_exported_alone")


def run_replay(root, replay_log):
    command = [
        "cargo",
        "test",
        "--lib",
        "--offline",
        "--locked",
        "-p",
        "safeyolo-proxy",
        REPLAY_TEST,
        "--",
        "--nocapture",
    ]
    environment = os.environ.copy()
    environment.update(
        {
            "CARGO_INCREMENTAL": "0",
            "CARGO_PROFILE_DEV_DEBUG": "0",
        }
    )
    replay_log.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            command,
            cwd=root / "proxy",
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as error:
        raise ReplayFailure(f"could not run the fixed Rust replay: {error}") from error
    replay_log.write_text(result.stdout, encoding="utf-8")
    if result.returncode != 0:
        raise ReplayFailure(
            f"Rust replay exited with {result.returncode}; captured output is {replay_log}"
        )
    compare(root, replay_log)


def self_test():
    expected = {"request": {"url": "http://owned.invalid/"}, "response": {"status": 200}}
    changed = copy.deepcopy(expected)
    changed["response"]["status"] = 201
    difference = first_difference(changed, expected)
    if not difference:
        raise ReplayFailure("intentional changed entry was not detected")
    record = json.dumps({"log": {"entries": [expected]}}, separators=(",", ":"))
    duplicate = f"HAR_REPLAY_OK\tone\t{record.encode().hex()}\nHAR_REPLAY_OK\tone\t{record.encode().hex()}"
    try:
        parse_replay_lines(duplicate.splitlines())
    except ReplayFailure:
        print(f"intentional changed entry detected: {difference}")
        print("duplicate replay record rejected")
    else:
        raise ReplayFailure("duplicate replay record was not rejected")
    misaligned = {
        "name": "mixed",
        "selected": ["http", "tcp"],
        "har": {"log": {"entries": [expected, expected]}},
    }
    try:
        selection_parts(misaligned, {"http": "http", "tcp": "tcp"})
    except ReplayFailure:
        print("HTTP/non-HTTP selection alignment rejected")
    else:
        raise ReplayFailure("HTTP/non-HTTP selection alignment was not rejected")


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("self-test", help="check mismatch and duplicate guards")
    for name in ("check", "run"):
        command = subcommands.add_parser(name)
        command.add_argument("candidate_root", type=Path)
        command.add_argument("replay_log", type=Path)
    return parser.parse_args()


def main():
    options = arguments()
    try:
        if options.command == "self-test":
            self_test()
        elif options.command == "run":
            run_replay(options.candidate_root.resolve(), options.replay_log)
        else:
            compare(options.candidate_root.resolve(), options.replay_log)
    except ReplayFailure as error:
        print(f"HAR replay check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
