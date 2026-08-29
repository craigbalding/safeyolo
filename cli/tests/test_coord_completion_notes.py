from __future__ import annotations

import asyncio
import json

import pytest

from safeyolo.coord import api, completion_notes, nats_client
from safeyolo.coord import nats_runtime as nr
from safeyolo.coord.identity import new_operation_id


def envelope(body: str, **overrides) -> dict:
    value = {
        "msg_id": "msg-" + "a" * 32,
        "sent_at": 1_800_000_000_000,
        "sender_kind": "agent",
        "sender_agent_id": "ag-" + "b" * 32,
        "sender_agent_name": "forge",
        "origin_instance_id": "sy-" + "c" * 32,
        "content_type": "text/markdown",
        "body": body,
        "sequence": 17,
    }
    value.update(overrides)
    return value


def dispatch_candidate(**overrides) -> completion_notes.CandidateDraft:
    values = {
        "candidate_type": completion_notes.CandidateType.DISPATCH,
        "attribution": completion_notes.AttributionCategory.FORGE_IMPLEMENTATION_DISCOVERY,
        "summary": "A retry boundary can duplicate a trusted completion.",
    }
    values.update(overrides)
    return completion_notes.CandidateDraft(**values)


def factory_candidate(**overrides) -> completion_notes.CandidateDraft:
    values = {
        "candidate_type": completion_notes.CandidateType.FACTORY,
        "attribution": completion_notes.AttributionCategory.FACTORY_PROCESS_OBSERVATION,
        "summary": "Exact tree evidence should travel with the review handoff.",
    }
    values.update(overrides)
    return completion_notes.CandidateDraft(**values)


@pytest.mark.parametrize(
    "state",
    ["DONE", "READY", "CHANGES_REQUIRED", "BLOCKED", "FAILED"],
)
def test_absent_trailer_keeps_ordinary_completion_byte_for_byte(state: str) -> None:
    body = f"{state} task=backlog-437\n\nordinary free-form result"
    parsed = completion_notes.parse_completion_envelope(envelope(body))
    assert parsed.delivery_state.value == state
    assert parsed.delivery_body == body
    assert parsed.trailer_status == "absent"
    assert parsed.candidates == ()
    assert parsed.error is None


def test_zero_candidates_add_no_bytes() -> None:
    body = "DONE task=backlog-437"
    assert completion_notes.render_completion_trailer([]) == ""
    assert completion_notes.append_completion_notes(body, []) == body


def test_explicit_empty_candidate_document_is_invalid_and_must_be_omitted() -> None:
    body = (
        "DONE task=backlog-437\n\n"
        f"{completion_notes.TRAILER_START}\n"
        '{"candidates":[]}\n'
        f"{completion_notes.TRAILER_END}"
    )
    parsed = completion_notes.parse_completion_envelope(envelope(body))
    assert parsed.delivery_state is completion_notes.DeliveryState.DONE
    assert parsed.delivery_body == body
    assert parsed.trailer_status == "invalid"
    assert parsed.candidates == ()
    assert "must be omitted" in parsed.error


def test_multiple_candidates_and_compact_optional_fields_round_trip() -> None:
    dispatch = dispatch_candidate(
        kind="testing_tactic",
        interest="high",
        why_interesting="The durable gap is safer than duplicate operator authority.",
        evidence=(
            completion_notes.EvidenceRef(completion_notes.EvidenceKind.ISSUE, "#437"),
            completion_notes.EvidenceRef(
                completion_notes.EvidenceKind.TEST,
                "cli/tests/test_coord_completion_notes.py::test_multiple_candidates_and_compact_optional_fields_round_trip",
            ),
            completion_notes.EvidenceRef(completion_notes.EvidenceKind.TREE, "a" * 40),
        ),
        snippet="if outcome_unknown:\n    stop_without_replay()",
        outcome="encoded in the completion contract",
    )
    factory = factory_candidate(
        area="review_handoff",
        problem="reviewers had to rediscover candidate identity",
        impact="ambiguous exact-head review",
        suggestion="carry base, head, and tree in the handoff",
        confidence="high",
    )
    delivery = "READY issue=#437 head=" + "d" * 40
    body = completion_notes.append_completion_notes(delivery, [dispatch, factory])

    parsed = completion_notes.parse_completion_envelope(envelope(body))
    assert parsed.delivery_state is completion_notes.DeliveryState.READY
    assert parsed.delivery_body == delivery
    assert parsed.trailer_status == "valid"
    assert [item.candidate_type for item in parsed.candidates] == [
        completion_notes.CandidateType.DISPATCH,
        completion_notes.CandidateType.FACTORY,
    ]
    assert parsed.candidates[0].snippet == dispatch.snippet
    assert parsed.candidates[0].evidence == dispatch.evidence
    assert parsed.candidates[1].suggestion == factory.suggestion


def test_provenance_is_only_derived_from_canonical_envelope() -> None:
    body = completion_notes.append_completion_notes("DONE task=backlog-437", [dispatch_candidate()])
    canonical = envelope(
        body,
        msg_id="msg-" + "1" * 32,
        sequence=912,
        sent_at=1_900_000_000_123,
        sender_agent_id="ag-" + "2" * 32,
        sender_agent_name="forge-renamed",
        origin_instance_id="sy-" + "3" * 32,
    )
    parsed = completion_notes.parse_completion_envelope(canonical)
    provenance = parsed.candidates[0].provenance
    assert provenance.to_dict() == {
        "msg_id": "msg-" + "1" * 32,
        "coord_sequence": 912,
        "sent_at": 1_900_000_000_123,
        "sender_kind": "agent",
        "sender_agent_id": "ag-" + "2" * 32,
        "sender_agent_name": "forge-renamed",
        "origin_instance_id": "sy-" + "3" * 32,
    }
    assert "provenance" not in dispatch_candidate().to_wire()


@pytest.mark.parametrize(
    "reserved",
    [
        "provenance",
        "msg_id",
        "coord_sequence",
        "sequence",
        "sent_at",
        "sender_kind",
        "sender_agent_id",
        "sender_agent_name",
        "origin_instance_id",
        "discovered_by",
        "author",
    ],
)
def test_authored_reserved_provenance_is_rejected(reserved: str) -> None:
    candidate = dispatch_candidate().to_wire()
    candidate[reserved] = "lens"
    parsed = parse_wire([candidate])
    assert parsed.trailer_status == "invalid"
    assert parsed.candidates == ()
    assert "reserved provenance" in parsed.error


def parse_wire(candidates: list[dict], *, root_extra: dict | None = None):
    document = {"candidates": candidates, **(root_extra or {})}
    payload = json.dumps(document, separators=(",", ":"))
    body = f"DONE task=backlog-437\n\n{completion_notes.TRAILER_START}\n{payload}\n{completion_notes.TRAILER_END}"
    return completion_notes.parse_completion_envelope(envelope(body))


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        ({"unknown": "x"}, "unknown fields"),
        ({"type": "MYSTERY_CANDIDATE"}, "type is unknown"),
        ({"attribution": "whoever"}, "attribution is unknown"),
        ({"summary": ""}, "must be non-empty"),
        ({"kind": "Not A Token"}, "lowercase token"),
        ({"evidence": "#437"}, "must be a list"),
        ({"evidence": None}, "must be a list"),
        ({"evidence": [{"kind": "pr", "ref": "#444", "extra": 1}]}, "exactly"),
        ({"evidence": [{"kind": "rumour", "ref": "x"}]}, "kind is unknown"),
        ({"snippet": ""}, "must be non-empty"),
    ],
)
def test_unknown_or_malformed_candidate_fields_are_never_trusted(mutation: dict, error: str) -> None:
    candidate = dispatch_candidate().to_wire()
    candidate.update(mutation)
    parsed = parse_wire([candidate])
    assert parsed.delivery_state is completion_notes.DeliveryState.DONE
    assert parsed.trailer_status == "invalid"
    assert parsed.candidates == ()
    assert error in parsed.error


def test_unknown_root_field_invalidates_the_whole_trailer() -> None:
    parsed = parse_wire([dispatch_candidate().to_wire()], root_extra={"sequence": 99})
    assert parsed.trailer_status == "invalid"
    assert parsed.candidates == ()
    assert "exactly candidates" in parsed.error


@pytest.mark.parametrize(
    "body",
    [
        f"DONE x\n\n{completion_notes.TRAILER_START}\nnot-json\n{completion_notes.TRAILER_END}",
        f"DONE x\n\n{completion_notes.TRAILER_START}\n{{}}",
        "DONE x\n\n<<<SAFEYOLO_COMPLETION_NOTES_V2>>>",
        "DONE x\n\n<<<END_SAFEYOLO_COMPLETION_NOTES_V2>>>",
        f"DONE x\n\n{completion_notes.TRAILER_END}",
        (
            f"DONE x\n\n{completion_notes.TRAILER_START}\n"
            '{"candidates":[]}\n'
            f"{completion_notes.TRAILER_END}\ntrailing text"
        ),
        (
            f"DONE x\n\n{completion_notes.TRAILER_START}\n"
            '{"candidates":[],"candidates":[]}\n'
            f"{completion_notes.TRAILER_END}"
        ),
    ],
)
def test_malformed_unknown_duplicate_or_nonterminal_trailer_is_invalid(body: str) -> None:
    parsed = completion_notes.parse_completion_envelope(envelope(body))
    assert parsed.delivery_state is completion_notes.DeliveryState.DONE
    assert parsed.delivery_body == body
    assert parsed.trailer_status == "invalid"
    assert parsed.candidates == ()
    assert parsed.error


def test_trailer_cannot_turn_a_nonterminal_message_into_delivery_state() -> None:
    body = completion_notes.append_completion_notes("ACCEPTED task=backlog-437", [dispatch_candidate()])
    parsed = completion_notes.parse_completion_envelope(envelope(body))
    assert parsed.delivery_state is None
    assert parsed.delivery_body == body
    assert parsed.trailer_status == "invalid"
    assert parsed.candidates == ()


def test_first_line_delivery_state_is_not_taken_from_later_body_or_trailer() -> None:
    body = "status follows\nDONE task=fake"
    parsed = completion_notes.parse_completion_envelope(envelope(body))
    assert parsed.delivery_state is None
    assert parsed.trailer_status == "absent"


def test_delivery_state_must_start_at_the_first_byte() -> None:
    parsed = completion_notes.parse_completion_envelope(envelope(" DONE task=not-a-real-transition"))
    assert parsed.delivery_state is None


def test_oversized_authored_trailer_is_rejected_before_candidate_ingestion() -> None:
    payload = json.dumps(
        {
            "candidates": [
                {
                    "type": "DISPATCH_CANDIDATE",
                    "attribution": "forge_implementation_discovery",
                    "summary": "x" * completion_notes.MAX_TRAILER_BYTES,
                }
            ]
        },
        separators=(",", ":"),
    )
    body = f"DONE task=x\n\n{completion_notes.TRAILER_START}\n{payload}\n{completion_notes.TRAILER_END}"
    parsed = completion_notes.parse_completion_envelope(envelope(body))
    assert parsed.trailer_status == "invalid"
    assert parsed.candidates == ()
    assert "32768 UTF-8 bytes" in parsed.error


@pytest.mark.parametrize(
    "payload",
    [
        "[" * 10_000 + "0" + "]" * 10_000,
        '{"candidates":' + "9" * 5_000 + "}",
    ],
)
def test_decoder_resource_failures_produce_a_bounded_invalid_result(
    payload: str,
) -> None:
    body = f"DONE task=x\n\n{completion_notes.TRAILER_START}\n{payload}\n{completion_notes.TRAILER_END}"
    parsed = completion_notes.parse_completion_envelope(envelope(body))
    assert parsed.delivery_state is completion_notes.DeliveryState.DONE
    assert parsed.trailer_status == "invalid"
    assert parsed.candidates == ()
    assert parsed.error == "trailer payload is not valid bounded JSON"


def test_invalid_diagnostics_do_not_reflect_authored_control_characters() -> None:
    candidate = dispatch_candidate().to_wire()
    candidate["erase\x1b[2Jscreen"] = "untrusted"
    parsed = parse_wire([candidate])
    assert parsed.trailer_status == "invalid"
    assert parsed.candidates == ()
    assert parsed.error == "candidates[0] contains unknown fields"
    assert "\x1b" not in parsed.error


@pytest.mark.parametrize(
    "category",
    list(completion_notes.AttributionCategory),
)
def test_all_explicit_attribution_categories_round_trip(category) -> None:
    candidate = dispatch_candidate(attribution=category)
    body = completion_notes.append_completion_notes("DONE task=x", [candidate])
    parsed = completion_notes.parse_completion_envelope(envelope(body))
    assert parsed.candidates[0].attribution is category


def test_size_and_count_boundaries() -> None:
    candidates = [dispatch_candidate(summary=f"candidate {index}") for index in range(8)]
    body = completion_notes.append_completion_notes("DONE task=x", candidates)
    assert len(completion_notes.parse_completion_envelope(envelope(body)).candidates) == 8
    with pytest.raises(ValueError, match="at most 8"):
        completion_notes.render_completion_trailer([*candidates, dispatch_candidate()])
    with pytest.raises(ValueError, match="summary exceeds"):
        completion_notes.render_completion_trailer(
            [dispatch_candidate(summary="x" * (completion_notes.MAX_SUMMARY_BYTES + 1))]
        )
    with pytest.raises(ValueError, match="snippet exceeds"):
        completion_notes.render_completion_trailer(
            [dispatch_candidate(snippet="x" * (completion_notes.MAX_SNIPPET_BYTES + 1))]
        )


@pytest.fixture
def completion_coord(nats_env):
    nr.start_server(ready_timeout=8.0)
    nats_client.reset_for_tests()
    api.bootstrap()
    return nats_env


def run(coro):
    return asyncio.run(coro)


@pytest.mark.timeout(30)
def test_retained_envelope_restart_keeps_stable_derived_provenance(completion_coord) -> None:
    agent_id = "ag-" + "d" * 32
    run(api.create_room("completion-notes"))
    api.grant(
        "completion-notes",
        "agent",
        agent_id,
        operation_id=new_operation_id(),
    )
    api.grant(
        "completion-notes",
        "operator",
        "operator",
        operation_id=new_operation_id(),
    )
    body = completion_notes.append_completion_notes(
        "DONE task=backlog-437",
        [
            dispatch_candidate(
                evidence=(
                    completion_notes.EvidenceRef(completion_notes.EvidenceKind.COORD, "room=backlog sequence=227"),
                )
            )
        ],
    )
    sent = run(
        api.send(
            "completion-notes",
            "agent",
            agent_id,
            body,
            sender_agent_name="forge",
        )
    )

    first = run(api.read_room("completion-notes", "operator", "operator"))["messages"][0]
    first_parsed = completion_notes.parse_completion_envelope(first)
    nr.stop_server()
    nats_client.reset_for_tests()
    nr.start_server(ready_timeout=8.0)
    nats_client.reset_for_tests()
    api.bootstrap()
    second = run(api.read_room("completion-notes", "operator", "operator"))["messages"][0]
    second_parsed = completion_notes.parse_completion_envelope(second)

    assert second == first
    assert first_parsed.candidates[0].provenance == second_parsed.candidates[0].provenance
    assert second_parsed.candidates[0].provenance.msg_id == sent["envelope"]["msg_id"]
    assert second_parsed.candidates[0].provenance.coord_sequence == sent["sequence"]
    assert second_parsed.candidates[0].provenance.sender_agent_id == agent_id
    assert second_parsed.candidates[0].provenance.sender_agent_name == "forge"
