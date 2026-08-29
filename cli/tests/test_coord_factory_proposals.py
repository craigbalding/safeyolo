from __future__ import annotations

import json
import multiprocessing
from pathlib import Path

import pytest

from safeyolo.coord import completion_notes, factory_proposals


def canonical_envelope(
    body: str,
    *,
    sequence: int = 10,
    sender_kind: str = "agent",
    sender_agent_name: str | None = "lens",
    msg_id: str | None = None,
) -> dict:
    return {
        "msg_id": msg_id or f"msg-{sequence:032x}",
        "sent_at": 1_800_000_000_000 + sequence,
        "sender_kind": sender_kind,
        "sender_agent_id": "ag-" + "a" * 32 if sender_kind == "agent" else None,
        "sender_agent_name": sender_agent_name if sender_kind == "agent" else None,
        "origin_instance_id": "sy-" + "b" * 32,
        "content_type": "text/markdown",
        "body": body,
        "sequence": sequence,
    }


def candidate_envelope(
    *,
    sequence: int = 10,
    candidate_type: completion_notes.CandidateType = completion_notes.CandidateType.FACTORY,
) -> dict:
    body = completion_notes.append_completion_notes(
        "READY issue=#438 pr=#500 head=" + "c" * 40,
        [
            completion_notes.CandidateDraft(
                candidate_type=candidate_type,
                attribution=completion_notes.AttributionCategory.FACTORY_PROCESS_OBSERVATION,
                summary="An authored nomination that still requires verification.",
                problem="UNTRUSTED problem text must not become a fact.",
                suggestion="UNTRUSTED recommendation must not be applied.",
            )
        ],
    )
    return canonical_envelope(body, sequence=sequence)


def verified_observation(
    *,
    task_key: str = "issue:#500",
    correlation_key: str = "exact-review-handoff",
    facts: tuple[str, ...] = ("Two exact-candidate reviews lacked a tree identifier.",),
    recommendation: str = "Require base, head, and tree in exact review handoffs.",
    recommendation_key: str = "require-exact-review-identifiers",
    evidence: tuple[factory_proposals.VerifiedEvidence, ...] = (),
    material: bool = False,
) -> factory_proposals.VerifiedFactoryObservation:
    return factory_proposals.VerifiedFactoryObservation(
        correlation_key=correlation_key,
        task_key=task_key,
        facts=facts,
        inference="The repeated omissions create avoidable review ambiguity.",
        recommendation=recommendation,
        recommendation_key=recommendation_key,
        impact="One blocked review round trip per incomplete handoff.",
        confidence="high; exact coord sequences verified",
        evidence=evidence,
        material=material,
    )


def consume(
    ledger: factory_proposals.FactoryProposalLedger,
    envelope: dict,
    observation: factory_proposals.VerifiedFactoryObservation,
    *,
    coverage: factory_proposals.ExistingIssueCoverage | None = None,
) -> factory_proposals.ProposalRecord:
    records = factory_proposals.FactoryProposalWorkflow(ledger).consume_envelope(
        envelope,
        verify=lambda _candidate: observation,
        find_existing_issue=lambda _observation: coverage,
    )
    assert len(records) == 1
    return records[0]


def test_stable_fingerprint_uses_normalized_problem_identity() -> None:
    assert factory_proposals.proposal_fingerprint(" Exact Review_Handoff ") == factory_proposals.proposal_fingerprint(
        "exact-review-handoff"
    )
    assert factory_proposals.proposal_fingerprint("exact-review-handoff") != factory_proposals.proposal_fingerprint(
        "review-evidence-loss"
    )


def test_invalid_or_nonfactory_trailers_do_not_call_trusted_inputs(tmp_path: Path) -> None:
    ledger = factory_proposals.FactoryProposalLedger(tmp_path / "ledger.json")
    calls: list[str] = []
    workflow = factory_proposals.FactoryProposalWorkflow(ledger)
    malformed = canonical_envelope("DONE task=x\n\n<<<SAFEYOLO_COMPLETION_NOTES_V2>>>")
    assert (
        workflow.consume_envelope(
            malformed,
            verify=lambda _candidate: calls.append("verify"),
            find_existing_issue=lambda _observation: calls.append("issue"),
        )
        == ()
    )
    assert (
        workflow.consume_envelope(
            candidate_envelope(candidate_type=completion_notes.CandidateType.DISPATCH),
            verify=lambda _candidate: calls.append("verify"),
            find_existing_issue=lambda _observation: calls.append("issue"),
        )
        == ()
    )
    assert calls == []
    assert not ledger.path.exists()


def test_candidate_fields_remain_untrusted_nominations(tmp_path: Path) -> None:
    ledger = factory_proposals.FactoryProposalLedger(tmp_path / "ledger.json")
    record = consume(
        ledger,
        candidate_envelope(),
        verified_observation(material=True),
    )
    rendered = factory_proposals.render_proposal(record)
    assert "UNTRUSTED" not in rendered.body
    assert "Two exact-candidate reviews" in rendered.body
    assert "Require base, head, and tree" in rendered.body
    coord_source = [item for item in record.evidence if item.kind is completion_notes.EvidenceKind.COORD]
    assert len(coord_source) == 1
    assert "sequence=10" in coord_source[0].ref
    assert "sender_agent_name=lens" in coord_source[0].ref


def test_one_low_value_task_is_observed_and_quiet(tmp_path: Path) -> None:
    ledger = factory_proposals.FactoryProposalLedger(tmp_path / "ledger.json")
    record = consume(ledger, candidate_envelope(), verified_observation())
    assert record.status is factory_proposals.ProposalStatus.OBSERVED
    assert ledger.pending() == ()
    assert ledger.path.stat().st_mode & 0o777 == 0o600


def test_repeated_tasks_correlate_into_one_proposal(tmp_path: Path) -> None:
    ledger = factory_proposals.FactoryProposalLedger(tmp_path / "ledger.json")
    first = consume(
        ledger,
        candidate_envelope(sequence=10),
        verified_observation(task_key="issue:#500"),
    )
    second = consume(
        ledger,
        candidate_envelope(sequence=11),
        verified_observation(
            task_key="issue:#501",
            facts=("A second exact review handoff omitted its tree.",),
        ),
    )
    assert first.fingerprint == second.fingerprint
    assert second.status is factory_proposals.ProposalStatus.PROPOSAL_READY
    assert len(ledger.list()) == 1
    assert second.facts == tuple(sorted(second.facts))
    assert {item.task_key for item in second.evidence} == {
        "issue:#500",
        "issue:#501",
    }


def test_one_material_observation_can_be_proposal_ready(tmp_path: Path) -> None:
    ledger = factory_proposals.FactoryProposalLedger(tmp_path / "ledger.json")
    record = consume(
        ledger,
        candidate_envelope(),
        verified_observation(material=True),
    )
    assert record.status is factory_proposals.ProposalStatus.PROPOSAL_READY
    assert len(ledger.pending()) == 1


def test_verified_evidence_is_deduplicated_and_canonically_ordered(
    tmp_path: Path,
) -> None:
    ledger = factory_proposals.FactoryProposalLedger(tmp_path / "ledger.json")
    repeated = factory_proposals.VerifiedEvidence(
        completion_notes.EvidenceKind.ISSUE,
        "#500",
        "issue:#500",
    )
    evidence = (
        factory_proposals.VerifiedEvidence(
            completion_notes.EvidenceKind.TEST,
            "test_z",
            "issue:#500",
        ),
        repeated,
        repeated,
        factory_proposals.VerifiedEvidence(
            completion_notes.EvidenceKind.PR,
            "#600",
            "issue:#500",
        ),
    )
    record = consume(
        ledger,
        candidate_envelope(),
        verified_observation(evidence=evidence),
    )
    assert record.evidence == tuple(sorted(set(record.evidence)))
    assert sum(item == repeated for item in record.evidence) == 1


def test_large_deduplicated_evidence_set_can_be_replayed(tmp_path: Path) -> None:
    ledger = factory_proposals.FactoryProposalLedger(tmp_path / "ledger.json")
    evidence = tuple(
        factory_proposals.VerifiedEvidence(
            completion_notes.EvidenceKind.TEST,
            f"test_{index}",
            "issue:#500",
        )
        for index in range(40)
    )
    observation = verified_observation(evidence=evidence)
    first = consume(ledger, candidate_envelope(), observation)
    replay = consume(ledger, candidate_envelope(), observation)
    assert replay.evidence == first.evidence
    assert len(replay.evidence) == 41  # 40 verified refs plus canonical coord source


def test_existing_issue_coverage_suppresses_duplicate_proposal(tmp_path: Path) -> None:
    ledger = factory_proposals.FactoryProposalLedger(tmp_path / "ledger.json")
    checked: list[str] = []
    workflow = factory_proposals.FactoryProposalWorkflow(ledger)
    record = workflow.consume_envelope(
        candidate_envelope(),
        verify=lambda _candidate: verified_observation(material=True),
        find_existing_issue=lambda observation: (
            checked.append(observation.correlation_key) or factory_proposals.ExistingIssueCoverage("#426 (open)")
        ),
    )[0]
    assert checked == ["exact-review-handoff"]
    assert record.status is factory_proposals.ProposalStatus.COVERED
    assert record.covered_by == "#426 (open)"
    assert ledger.pending() == ()


def test_proposal_render_separates_facts_inference_and_recommendation(
    tmp_path: Path,
) -> None:
    ledger = factory_proposals.FactoryProposalLedger(tmp_path / "ledger.json")
    record = consume(
        ledger,
        candidate_envelope(),
        verified_observation(material=True),
    )
    rendered = factory_proposals.render_proposal(record)
    assert rendered.body.startswith("Factory improvement proposal\n")
    assert "Observed facts (verified):" in rendered.body
    assert "Authoritative evidence:" in rendered.body
    assert "Relay inference:" in rendered.body
    assert "Relay recommendation:" in rendered.body
    assert "Operator decision required; no change has been applied." in rendered.body
    assert rendered.body.index("Observed facts") < rendered.body.index("Relay inference")
    assert rendered.body.index("Relay inference") < rendered.body.index("Relay recommendation")


def relay_send_envelope(rendered: factory_proposals.RenderedProposal) -> dict:
    return canonical_envelope(
        rendered.body,
        sequence=70,
        sender_agent_name="relay",
    )


def operator_outcome_envelope(
    fingerprint: str,
    outcome: factory_proposals.OperatorOutcome,
) -> dict:
    return canonical_envelope(
        f"FACTORY_PROPOSAL_OUTCOME fingerprint={fingerprint} status={outcome.value}",
        sequence=80,
        sender_kind="operator",
        sender_agent_name=None,
    )


def ready_ledger(
    tmp_path: Path,
) -> tuple[
    factory_proposals.FactoryProposalLedger,
    factory_proposals.RenderedProposal,
]:
    ledger = factory_proposals.FactoryProposalLedger(tmp_path / "ledger.json")
    consume(
        ledger,
        candidate_envelope(),
        verified_observation(material=True),
    )
    return ledger, ledger.pending()[0]


def test_presentation_requires_exact_canonical_relay_send(tmp_path: Path) -> None:
    ledger, rendered = ready_ledger(tmp_path)
    operator = canonical_envelope(
        rendered.body,
        sequence=70,
        sender_kind="operator",
        sender_agent_name=None,
    )
    with pytest.raises(factory_proposals.ProposalTransitionError, match="Relay"):
        ledger.mark_presented(rendered, operator)
    wrong_body = relay_send_envelope(rendered)
    wrong_body["body"] += "\nchanged"
    with pytest.raises(factory_proposals.ProposalTransitionError, match="exact"):
        ledger.mark_presented(rendered, wrong_body)
    presented = ledger.mark_presented(rendered, relay_send_envelope(rendered))
    assert presented.status is factory_proposals.ProposalStatus.PRESENTED
    assert presented.last_presented_revision == rendered.revision


def test_restart_does_not_represent_same_revision(tmp_path: Path) -> None:
    ledger, rendered = ready_ledger(tmp_path)
    ledger.mark_presented(rendered, relay_send_envelope(rendered))
    restarted = factory_proposals.FactoryProposalLedger(ledger.path)
    assert restarted.pending() == ()
    record = restarted.get(rendered.fingerprint)
    assert record is not None
    assert record.last_presented_revision == rendered.revision


def test_repeated_nomination_from_same_task_is_not_a_new_revision(
    tmp_path: Path,
) -> None:
    ledger, rendered = ready_ledger(tmp_path)
    ledger.mark_presented(rendered, relay_send_envelope(rendered))
    duplicate = consume(
        ledger,
        candidate_envelope(sequence=11),
        verified_observation(material=True),
    )
    assert duplicate.status is factory_proposals.ProposalStatus.PRESENTED
    assert duplicate.revision == rendered.revision
    assert ledger.pending() == ()


def test_nonmaterial_rendering_metadata_does_not_reopen_presented_revision(
    tmp_path: Path,
) -> None:
    ledger, rendered = ready_ledger(tmp_path)
    presented = ledger.mark_presented(rendered, relay_send_envelope(rendered))
    changed_confidence = verified_observation(material=True)
    changed_confidence = factory_proposals.VerifiedFactoryObservation(
        **{**changed_confidence.__dict__, "confidence": "high."}
    )
    replay = consume(
        ledger,
        candidate_envelope(sequence=12),
        changed_confidence,
    )
    assert replay.status is factory_proposals.ProposalStatus.PRESENTED
    assert replay.revision == presented.revision
    assert replay.confidence == presented.confidence
    assert ledger.pending() == ()


def test_out_of_order_exact_replay_cannot_regress_recommendation(
    tmp_path: Path,
) -> None:
    ledger, first_rendered = ready_ledger(tmp_path)
    ledger.mark_presented(first_rendered, relay_send_envelope(first_rendered))
    recommendation_b = verified_observation(
        recommendation="Require machine-validated exact review identifiers.",
        recommendation_key="machine-validate-exact-review-identifiers",
        material=True,
    )
    updated = consume(
        ledger,
        candidate_envelope(sequence=12),
        recommendation_b,
    )
    second_rendered = ledger.pending()[0]
    assert updated.recommendation == recommendation_b.recommendation
    ledger.mark_presented(
        second_rendered,
        canonical_envelope(
            second_rendered.body,
            sequence=72,
            sender_agent_name="relay",
        ),
    )

    replay = consume(
        ledger,
        candidate_envelope(sequence=10),
        verified_observation(material=True),
    )
    assert replay.status is factory_proposals.ProposalStatus.PRESENTED
    assert replay.recommendation == recommendation_b.recommendation
    assert replay.recommendation_key == recommendation_b.recommendation_key
    assert ledger.pending() == ()


def test_restart_reconciles_retained_send_before_representing(tmp_path: Path) -> None:
    ledger, rendered = ready_ledger(tmp_path)
    sent = relay_send_envelope(rendered)
    # Simulate process death after coord accepted the send but before the
    # ledger recorded the returned canonical envelope.
    restarted = factory_proposals.FactoryProposalLedger(ledger.path)
    reconciled = restarted.reconcile_presentations([sent])
    assert reconciled[0].status is factory_proposals.ProposalStatus.PRESENTED
    assert restarted.pending() == ()


def test_new_evidence_or_material_recommendation_reopens_presented_record(
    tmp_path: Path,
) -> None:
    ledger, rendered = ready_ledger(tmp_path)
    ledger.mark_presented(rendered, relay_send_envelope(rendered))
    changed = consume(
        ledger,
        candidate_envelope(sequence=12),
        verified_observation(
            task_key="issue:#502",
            recommendation="Require a machine-checked base, head, and tree handoff.",
            recommendation_key="machine-check-exact-review-identifiers",
        ),
    )
    assert changed.fingerprint == rendered.fingerprint
    assert changed.status is factory_proposals.ProposalStatus.PROPOSAL_READY
    assert changed.revision != rendered.revision
    assert ledger.pending()[0].revision == changed.revision


@pytest.mark.parametrize(
    "outcome",
    list(factory_proposals.OperatorOutcome),
)
def test_operator_outcomes_are_narrow_status_only_transitions(
    tmp_path: Path,
    outcome: factory_proposals.OperatorOutcome,
) -> None:
    ledger, rendered = ready_ledger(tmp_path)
    ledger.mark_presented(rendered, relay_send_envelope(rendered))
    record = ledger.record_operator_outcome(
        rendered.fingerprint,
        outcome,
        operator_outcome_envelope(rendered.fingerprint, outcome),
    )
    assert record.status.value == outcome.value
    assert ledger.pending() == ()
    if outcome is factory_proposals.OperatorOutcome.DEFERRED:
        repeated = ledger.record_operator_outcome(
            rendered.fingerprint,
            outcome,
            operator_outcome_envelope(rendered.fingerprint, outcome),
        )
        assert repeated.status is factory_proposals.ProposalStatus.DEFERRED
    else:
        with pytest.raises(factory_proposals.ProposalTransitionError, match="cannot apply"):
            ledger.record_operator_outcome(
                rendered.fingerprint,
                outcome,
                operator_outcome_envelope(rendered.fingerprint, outcome),
            )


def test_deferred_proposal_reopens_only_after_revision_change(tmp_path: Path) -> None:
    ledger, rendered = ready_ledger(tmp_path)
    ledger.mark_presented(rendered, relay_send_envelope(rendered))
    ledger.record_operator_outcome(
        rendered.fingerprint,
        factory_proposals.OperatorOutcome.DEFERRED,
        operator_outcome_envelope(
            rendered.fingerprint,
            factory_proposals.OperatorOutcome.DEFERRED,
        ),
    )
    duplicate = consume(
        ledger,
        candidate_envelope(),
        verified_observation(material=True),
    )
    assert duplicate.status is factory_proposals.ProposalStatus.DEFERRED
    assert ledger.pending() == ()
    revised = consume(
        ledger,
        candidate_envelope(sequence=13),
        verified_observation(
            task_key="issue:#503",
            facts=("A third exact review handoff omitted its tree.",),
            material=True,
        ),
    )
    assert revised.status is factory_proposals.ProposalStatus.PROPOSAL_READY


def test_accepted_and_rejected_outcomes_remain_terminal_on_new_input(
    tmp_path: Path,
) -> None:
    for outcome in (
        factory_proposals.OperatorOutcome.ACCEPTED,
        factory_proposals.OperatorOutcome.REJECTED,
    ):
        subdir = tmp_path / outcome.value
        ledger, rendered = ready_ledger(subdir)
        ledger.mark_presented(rendered, relay_send_envelope(rendered))
        decided = ledger.record_operator_outcome(
            rendered.fingerprint,
            outcome,
            operator_outcome_envelope(rendered.fingerprint, outcome),
        )
        record = consume(
            ledger,
            candidate_envelope(sequence=14),
            verified_observation(
                task_key="issue:#504",
                recommendation="A changed recommendation that cannot override the operator.",
                recommendation_key="changed-recommendation-must-not-override-operator",
                material=True,
            ),
        )
        assert record == decided
        assert ledger.pending() == ()


DOGFOOD_CANDIDATE = {
    "type": "FACTORY_CANDIDATE",
    "attribution": "factory_process_observation",
    "summary": "The #437 review could not start from Forge's first REVIEW_READY because it omitted coordinator-required base and tree identifiers.",
    "area": "review_handoff",
    "problem": "Forge's initial handoff supplied PR and head only while the authoritative preassignment required PR, base, head, and tree.",
    "impact": "one blocked coordination round trip before exact-candidate review",
    "suggestion": "validate required exact-candidate fields before sending REVIEW_READY",
    "confidence": "high",
    "evidence": [
        {"kind": "issue", "ref": "#437"},
        {"kind": "coord", "ref": "backlog sequence=231"},
        {"kind": "coord", "ref": "backlog sequence=232"},
        {"kind": "coord", "ref": "backlog sequence=234"},
    ],
}


def dogfood_envelope(sequence: int) -> dict:
    state = "CHANGES_REQUIRED" if sequence == 236 else "READY"
    candidate = {
        **DOGFOOD_CANDIDATE,
        "evidence": [
            *DOGFOOD_CANDIDATE["evidence"],
            *(
                [
                    {
                        "kind": "head",
                        "ref": "4cb23b6df3895af9ffbcf29b4f763b5f980791ca",
                    },
                    {
                        "kind": "tree",
                        "ref": "da5310e41ca87e6633a00cc6af747e7ac2723eb3",
                    },
                ]
                if sequence == 239
                else []
            ),
        ],
    }
    payload = json.dumps(
        {"candidates": [candidate]},
        separators=(",", ":"),
    )
    body = f"{state} issue=#437 pr=#445\n\n{completion_notes.TRAILER_START}\n{payload}\n{completion_notes.TRAILER_END}"
    return canonical_envelope(
        body,
        sequence=sequence,
        msg_id=("msg-6484630f9bb14e199233be0bd484145e" if sequence == 236 else "msg-ab065937e0c1460fad0167b39af93f89"),
    )


def test_real_437_lens_candidate_is_task_local_and_suppressed(tmp_path: Path) -> None:
    ledger = factory_proposals.FactoryProposalLedger(tmp_path / "ledger.json")
    workflow = factory_proposals.FactoryProposalWorkflow(ledger)

    def verify(candidate: completion_notes.ParsedCandidate):
        assert candidate.summary == DOGFOOD_CANDIDATE["summary"]
        assert candidate.provenance.coord_sequence in {236, 239}
        return verified_observation(
            correlation_key="review-handoff-required-identifiers",
            task_key="issue:#437",
            facts=("One #437 handoff omitted coordinator-required base and tree.",),
            recommendation="Validate exact-candidate handoff identifiers before review.",
            material=False,
        )

    for sequence in (236, 239):
        workflow.consume_envelope(
            dogfood_envelope(sequence),
            verify=verify,
            find_existing_issue=lambda _observation: None,
        )
    records = ledger.list()
    assert len(records) == 1
    assert records[0].status is factory_proposals.ProposalStatus.OBSERVED
    assert {item.task_key for item in records[0].evidence} == {"issue:#437"}
    assert "sequence=236" in records[0].evidence[0].ref
    assert "sequence=239" in records[0].evidence[1].ref
    assert ledger.pending() == ()


def test_corrupt_ledger_fails_closed_without_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "ledger.json"
    original = b'{"version":1,"proposals":BROKEN}\n'
    path.write_bytes(original)
    ledger = factory_proposals.FactoryProposalLedger(path)
    with pytest.raises(factory_proposals.ProposalLedgerCorruptionError):
        consume(
            ledger,
            candidate_envelope(),
            verified_observation(material=True),
        )
    assert path.read_bytes() == original


def test_deeply_nested_corrupt_ledger_is_reported_without_escape(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.json"
    path.write_text("[" * 10_000 + "0" + "]" * 10_000)
    with pytest.raises(factory_proposals.ProposalLedgerCorruptionError):
        factory_proposals.FactoryProposalLedger(path).list()


def test_failed_atomic_replace_preserves_previous_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = factory_proposals.FactoryProposalLedger(tmp_path / "ledger.json")
    consume(ledger, candidate_envelope(), verified_observation())
    original = ledger.path.read_bytes()

    def fail_replace(_source, _target):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(factory_proposals.os, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated"):
        consume(
            ledger,
            candidate_envelope(sequence=11),
            verified_observation(task_key="issue:#501"),
        )
    assert ledger.path.read_bytes() == original
    assert list(tmp_path.glob(".ledger.json.*.tmp")) == []


def _concurrent_observe(path: str, sequence: int) -> None:
    ledger = factory_proposals.FactoryProposalLedger(Path(path))
    consume(
        ledger,
        candidate_envelope(sequence=sequence),
        verified_observation(
            task_key=f"issue:#{500 + sequence}",
            facts=(f"Verified concurrent observation {sequence}.",),
        ),
    )


@pytest.mark.timeout(30)
def test_process_concurrency_preserves_all_evidence_atomically(tmp_path: Path) -> None:
    path = tmp_path / "ledger.json"
    context = multiprocessing.get_context("spawn")
    processes = [context.Process(target=_concurrent_observe, args=(str(path), sequence)) for sequence in range(20, 26)]
    for process in processes:
        process.start()
    for process in processes:
        process.join(15)
        assert process.exitcode == 0
    record = factory_proposals.FactoryProposalLedger(path).list()[0]
    assert record.status is factory_proposals.ProposalStatus.PROPOSAL_READY
    assert {item.task_key for item in record.evidence} == {f"issue:#{500 + sequence}" for sequence in range(20, 26)}
    assert len(record.facts) == 6
