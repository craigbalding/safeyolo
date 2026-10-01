"""Pure source scope/filter observations; no proxy or API process is started."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mitmproxy import exceptions, flowfilter

root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root / "cli/src/safeyolo/mitm_addons"))
from traffic_scope import TrafficScope  # noqa: E402 -- load the checkout's addon


class Options:
    view_filter = ""

    def update(self, **values):
        self.view_filter = values["view_filter"]


class View:
    def __init__(self, metadata):
        self.flows = [SimpleNamespace(metadata=value) for value in metadata]

    def resolve(self, selector):
        assert selector == "@all"
        return self.flows


cases = [
    ("default_case", {"agent": "alice"}, [{"agent": "ALICE"}, {"agent": "alice"}, {"agent": "bob"}]),
    ("unattributed_presence", {"unattributed": [1]}, [{}, {"agent": ""}, {"agent": None}, {"agent": "alice"}]),
    (
        "multiline_metadata",
        {"test_id": "CASE-1"},
        [{"agent": "alice", "note": "first\ntest_id: CASE-1\nlast"}, {"test_id": "CASE-1\nother"}],
    ),
    ("literal_scope", {"agent": 'a.b[0]" x'}, [{"agent": 'a.b[0]" x'}, {"agent": 'aXb0" x'}]),
    ("newline_scope", {"test_id": "a\nb"}, [{"test_id": "a\nb"}, {"test_id": "a\nb\nc"}, {"test_id": "a"}]),
    ("empty_unattributed", {"agent": "alice", "unattributed": []}, [{"agent": "alice"}, {}]),
    (
        "numeric_facets",
        {},
        [
            {"agent": "alice", "test_id": True, "test_role": [1, "x"]},
            {"agent": "bob", "test_id": 17, "test_intent": {"a": None}},
        ],
    ),
    (
        "exact_facet_parent",
        {"agent": "alice", "test_id": "case"},
        [
            {"agent": "ALICE", "test_id": "CASE", "test_role": "caps"},
            {"agent": "alice", "test_id": "case", "test_role": "exact"},
        ],
    ),
]
results = []
for name, scope, metadata in cases:
    addon = TrafficScope()
    view = View(metadata)
    context = SimpleNamespace(options=Options(), master=SimpleNamespace(view=view))
    with patch("traffic_scope.ctx", context):
        try:
            stats = addon.set_scope(**scope)
            expression = flowfilter.parse(stats["effective_filter"]) if stats["effective_filter"] else None
            matches = [True if expression is None else bool(flowfilter.match(expression, flow)) for flow in view.flows]
            result = {
                "name": name,
                "scope": scope,
                "metadata": metadata,
                "stats": stats,
                "matches": matches,
                "facets": addon.facet_values(),
            }
        except (ValueError, TypeError, exceptions.OptionsError) as error:
            result = {
                "name": name,
                "scope": scope,
                "metadata": metadata,
                "error_type": type(error).__name__,
                "error": str(error),
            }
    results.append(result)
print(json.dumps(results, indent=2, ensure_ascii=True))
