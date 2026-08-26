"""Tests for trusted-operator traffic provenance."""

from unittest.mock import patch

import pytest
from mitmproxy import connection, http
from operator_provenance import OperatorProvenance

pytestmark = pytest.mark.assurance_boundary


def make_flow(identifier: str = "source") -> http.HTTPFlow:
    client = connection.Client(peername=("127.0.0.1", 1234), sockname=("127.0.0.1", 8080))
    server = connection.Server(address=("example.com", 443))
    item = http.HTTPFlow(client, server)
    item.id = identifier
    item.request = http.Request.make("GET", "https://example.com/path")
    item.response = http.Response.make(200, b"original")
    item.metadata.update(request_id="req-original", agent="cody", test_context={"run": "r1"})
    return item


def test_duplicate_links_to_original_flow():
    addon = OperatorProvenance()
    original = make_flow()
    addon._remember(original)
    duplicate = original.copy()
    duplicate.id = "duplicate"

    with patch("operator_provenance.write_event", autospec=True) as audit:
        addon._view_add(duplicate)

    assert duplicate.metadata["origin"] == "operator"
    assert duplicate.metadata["operator_action"] == "duplicate"
    assert duplicate.metadata["source_flow_id"] == "source"
    assert audit.call_args.kwargs["details"]["resulting_flow_id"] == "duplicate"


def test_edit_and_revert_are_audited_without_reapplying_metadata_after_revert():
    addon = OperatorProvenance()
    item = make_flow()
    addon._remember(item)
    item.backup()
    item.request.path = "/edited"

    with patch("operator_provenance.write_event", autospec=True) as audit:
        addon._view_update(item)
        assert item.metadata["operator_action"] == "edit"
        item.revert()
        addon._view_update(item)

    assert "origin" not in item.metadata
    assert [call.kwargs["details"]["action"] for call in audit.call_args_list] == ["edit", "revert"]


def test_replay_gets_provenance_then_audits_with_fresh_request_id():
    addon = OperatorProvenance()
    item = make_flow()
    addon._remember(item)
    item.backup()
    item.is_replay = "request"
    item.response = None

    with patch("operator_provenance.write_event", autospec=True) as audit:
        addon._view_update(item)
        assert item.metadata["operator_audit_pending"] is True
        item.metadata["request_id"] = "req-fresh"
        addon.request(item)

    assert item.metadata["origin"] == "operator"
    assert item.metadata["operator_action"] == "replay"
    assert item.metadata["source_flow_id"] == "source"
    assert audit.call_args.kwargs["request_id"] == "req-fresh"


def test_intercepted_resume_and_kill_are_distinct_actions():
    addon = OperatorProvenance()
    resumed = make_flow("resumed")
    resumed.response = None
    resumed.intercept()
    addon._remember(resumed)
    resumed.resume()

    killed = make_flow("killed")
    killed.response = None
    killed.live = True
    killed.intercept()
    addon._remember(killed)
    killed.kill()

    with patch("operator_provenance.write_event", autospec=True) as audit:
        addon._view_update(resumed)
        addon._view_update(killed)

    assert resumed.metadata["operator_action"] == "resume"
    assert killed.metadata["operator_action"] == "kill"
    assert [call.kwargs["details"]["action"] for call in audit.call_args_list] == ["resume", "kill"]
