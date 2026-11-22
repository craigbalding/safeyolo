"""Agent host calls preserve typed preparation and never replay a failed effect."""
from __future__ import annotations

import argparse
import importlib.util
import io
import json
import urllib.error
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "cli/src/safeyolo/agent_context/skills/safeyolo/scripts/host-operation.py"
spec = importlib.util.spec_from_file_location("host_operation_client", SOURCE)
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


class Reply(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


@pytest.fixture
def transport(tmp_path, monkeypatch):
    token = tmp_path / "agent-token"
    token.write_text("fixture-agent")
    monkeypatch.setattr(client, "TOKEN_PATH", token)
    calls = []
    responses = []

    class Opener:
        def open(self, request, timeout):
            calls.append(request)
            assert timeout > 0
            response = responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return Reply(json.dumps(response).encode())

    monkeypatch.setattr(client.urllib.request, "build_opener", lambda *_args: Opener())
    return calls, responses


def test_discovery_pins_and_typed_data_cross_preparation_without_authority_fields(tmp_path, transport):
    calls, responses = transport
    responses.extend([{"discovery": {"operations": [{"operation_id": "selected", "operation_sha256": "op",
                        "implementation_sha256": "implementation", "revisions": {"authority": "observed"}}]}},
                      {"kind": "proposal", "prepared": {"invocation": {"typed": True}, "revisions": {"authority": "observed"}}}])
    arguments = tmp_path / "args.json"
    values = {"value": "quotes '\" $() ; are data", "flag": True, "count": 4, "paths": ["a", "b"]}
    arguments.write_text(json.dumps(values))
    result = client.run(argparse.Namespace(command="propose", binding="case:linux", request_id="proposal-1",
                                          operation="selected", resource="fixed", arguments=str(arguments)))
    prepared = tmp_path / "prepared.json"
    prepared.write_text(json.dumps(result))
    assert calls[-1].full_url.endswith("/gateway/host/case:linux")
    proposal = json.loads(calls[-1].data)
    assert proposal["action"]["invocation"]["arguments"] == values
    assert proposal["expected"] == {"authority": "observed"}
    assert set(proposal) == {"request_id", "expected", "action"}
    responses.append({"kind": "job", "receipt": {"job_id": "original", "request_id": "invoke-1"}})
    result = client.run(argparse.Namespace(command="invoke", binding="case", request_id="invoke-1", prepared=str(prepared)))
    assert result["receipt"]["job_id"] == "original"
    invoke = json.loads(calls[-1].data)
    assert invoke["action"] == {"kind": "invoke", "invocation": {"typed": True}}
    assert invoke["expected"] == {"authority": "observed"}


def test_lost_invocation_reply_is_uncertain_and_is_not_retried(transport):
    calls, responses = transport
    responses.append(TimeoutError("lost reply"))
    with pytest.raises(client.RequestFailed) as caught:
        client.call("case", "original-id", {"kind": "invoke"})
    assert len(calls) == 1
    assert caught.value.value["execution_outcome"] == "uncertain"
    assert caught.value.value["request_id"] == "original-id"


def test_private_refusal_is_preserved_without_escalation_or_resubmit(transport):
    calls, responses = transport
    body = {"challenge_id": "private-finding", "reason": "unavailable required check"}
    responses.append(urllib.error.HTTPError(client.BASE_URL, 403, "refused", {}, Reply(json.dumps(body).encode())))
    with pytest.raises(client.RequestFailed) as caught:
        client.call("case", "original-id", {"kind": "invoke"})
    assert caught.value.value == body
    assert len(calls) == 1


def test_redirect_does_not_create_another_authenticated_request():
    assert client.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://other.invalid") is None
