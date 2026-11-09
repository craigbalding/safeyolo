"""Check the Swift form's import-to-connect assignments without a macOS UI."""

import json
import re
from pathlib import Path

UI = (
    Path(__file__).resolve().parents[1]
    / "command-centre/macos/Sources/UI.swift"
).read_text()


def imported_form():
    """Apply the actual import assignments to an already selected owner A."""
    form = {"terminalTarget": "operator@owner-a.example.ts.net"}
    handoff = {
        "friendlyName": "Owner B",
        "adminURL": "https://owner-b.example.ts.net:9443",
        "eventsURL": "wss://owner-b.example.ts.net:9444/admin/events",
        "transport": "tailnet",
        "token": "synthetic-owner-b-token",
        "instanceID": "sy-owner-b",
        "ownerRoot": "/opt/safeyolo",
    }
    body = UI.split("private func importConnectionFile() {", 1)[1].split(
        "} catch", 1
    )[0]
    assignments = body.split('selectedConnectionID = ""', 1)[1]
    for line in assignments.strip().splitlines():
        name, value = line.strip().split(" = ", 1)
        # These are the form's Swift assignments, not a second import routine.
        form[name] = (
            handoff[value.removeprefix("file.")]
            if value.startswith("file.")
            else json.loads(value.replace("nil", "null"))
        )
    return form


def connect_input(form):
    """Read the input passed by the actual form to configureRemote."""
    constructor = UI.split("private func connect() {", 1)[1].split(
        "RemoteConnectionInput(", 1
    )[1].split("), replacing:", 1)[0]
    result = {}
    for line in constructor.strip().splitlines():
        name, expression = line.strip().rstrip(",").split(": ", 1)
        match = re.fullmatch(
            r"(\w+)(\.trimmingCharacters\(in: \.whitespacesAndNewlines\))?",
            expression,
        )
        assert match, f"Review changed connection expression: {expression}"
        value = form[match[1]]
        result[name] = value.strip() if match[2] else value
    return result


def test_imported_owner_does_not_inherit_selected_owners_terminal_override():
    connection = connect_input(imported_form())
    assert connection["expectedInstanceID"] == "sy-owner-b"
    assert connection["adminURL"] == "https://owner-b.example.ts.net:9443"
    assert connection["terminalTarget"] == ""


def test_imported_owner_can_have_a_deliberately_entered_terminal_override():
    form = imported_form()
    form["terminalTarget"] = "  operator@owner-b-ssh-alias  "
    assert connect_input(form)["terminalTarget"] == "operator@owner-b-ssh-alias"
