"""Print owned in-memory WebSocket retention observations from the source addon.

Run with the checkout's Python environment containing mitmproxy. This script
starts no proxy or API and writes the fixture JSON to stdout.
"""

import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

from mitmproxy.websocket import WebSocketData, WebSocketMessage

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "cli/src/safeyolo/mitm_addons/flow_pruner.py"
SPEC = importlib.util.spec_from_file_location("owned_flow_pruner", SOURCE)
assert SPEC and SPEC.loader
SOURCE_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SOURCE_MODULE)


class View:
    def __init__(self, flows):
        self.flows = flows

    def resolve(self, spec):
        assert spec == "@all"
        return list(self.flows)

    def remove(self, flows):
        self.flows = [flow for flow in self.flows if flow not in flows]


def message(timestamp, body, dropped=False):
    return {"timestamp": timestamp, "hex": body.hex(), "dropped": dropped}


FOUR = b"abcd"
CASES = [
    {
        "name": "terminal_before_message_trim",
        "max_flows": 10,
        "max_bytes": 16,
        "flows": [
            {
                "id": "open",
                "http_end": 2,
                "ws_end": None,
                "messages": [message(3, b"old-body", True), message(4, b"new-body")],
            },
            {"id": "terminal", "http_end": 6, "response": "7465726d696e616c"},
        ],
    },
    {
        "name": "global_timestamp_id_position",
        "max_flows": 1,
        "max_bytes": 12,
        "flows": [
            {
                "id": "a",
                "http_end": 3,
                "ws_end": None,
                "messages": [message(5, FOUR, True), message(5, FOUR), message(9, FOUR)],
            },
            {
                "id": "b",
                "http_end": 3,
                "ws_end": None,
                "messages": [message(1, FOUR), message(5, FOUR), message(8, FOUR)],
            },
        ],
    },
    {
        "name": "latest_empty_and_old_empty",
        "max_flows": 10,
        "max_bytes": 1,
        "flows": [
            {
                "id": "open",
                "http_end": 2,
                "ws_end": None,
                "messages": [message(3, b""), message(4, b"old-body"), message(5, b"new-body"), message(6, b"")],
            },
        ],
    },
    {
        "name": "latest_oversized_soft_target",
        "max_flows": 10,
        "max_bytes": 1,
        "flows": [
            {"id": "open", "http_end": 2, "ws_end": None, "messages": [message(3, FOUR), message(4, b"large-newest")]},
        ],
    },
    {
        "name": "websocket_close_priority",
        "max_flows": 1,
        "max_bytes": 1000,
        "flows": [
            {"id": "later-ws", "http_end": 2, "ws_end": 30, "messages": [message(4, b"one"), message(5, b"two")]},
            {"id": "earlier-http", "http_end": 20},
        ],
    },
    {
        "name": "count_pressure_does_not_trim_open_messages",
        "max_flows": 1,
        "max_bytes": 1000,
        "flows": [
            {"id": "a", "http_end": 2, "ws_end": None, "messages": [message(3, FOUR), message(4, FOUR)]},
            {"id": "b", "http_end": 2, "ws_end": None, "messages": [message(3, FOUR), message(4, FOUR)]},
        ],
    },
]


def run(recipe):
    flows = []
    identities = {}
    for entry in recipe["flows"]:
        websocket = None
        if "messages" in entry:
            messages = []
            for index, item in enumerate(entry["messages"]):
                value = WebSocketMessage(1, True, bytes.fromhex(item["hex"]), item["timestamp"], item["dropped"])
                identities[id(value)] = index
                messages.append(value)
            websocket = WebSocketData(messages=messages, timestamp_end=entry["ws_end"])
        flows.append(
            SimpleNamespace(
                id=entry["id"],
                live=False,
                intercepted=False,
                websocket=websocket,
                request=SimpleNamespace(timestamp_start=1, raw_content=b""),
                response=SimpleNamespace(
                    timestamp_end=entry["http_end"], raw_content=bytes.fromhex(entry.get("response", ""))
                ),
                timestamp_created=1,
                timestamp_end=None,
                error=None,
            )
        )
    view = View(flows)
    SOURCE_MODULE.ctx = SimpleNamespace(
        master=SimpleNamespace(view=view),
        options=SimpleNamespace(
            flow_pruner_max=recipe["max_flows"],
            flow_pruner_max_body_bytes=recipe["max_bytes"],
        ),
    )
    pruner = SOURCE_MODULE.FlowPruner()
    pruner._prune(view, list(flows), recipe["max_flows"], recipe["max_bytes"])
    return {
        "retained": [flow.id for flow in view.flows],
        "messages": {
            flow.id: [identities[id(message)] for message in flow.websocket.messages]
            for flow in view.flows
            if flow.websocket is not None
        },
        "retained_bytes": SOURCE_MODULE._retained_body_bytes(view.flows),
        "pruned": pruner._total_pruned,
        "trimmed": pruner._total_websocket_messages_trimmed,
    }


def main():
    result = {
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "rows": [{"input": case, "result": run(case)} for case in CASES],
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
