from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from safeyolo.coord import completion_notes, dispatch

REPO_ROOT = Path(__file__).resolve().parents[2]
ISSUE_URL = "https://github.com/craigbalding/safeyolo/issues/437"
PR_URL = "https://github.com/craigbalding/safeyolo/pull/445"
COMMIT = "a75cebcd486961f1877c190b3ed71dabc276c8a3"
TEST_URL = f"https://github.com/craigbalding/safeyolo/blob/{COMMIT}/cli/tests/test_coord_completion_notes.py#L1-L410"


def evidence(*, kind: str = "issue", label: str = "Issue #437", url: str = ISSUE_URL) -> dict[str, str]:
    return {"kind": kind, "label": label, "url": url}


def item(**updates: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "theme": "Evidence boundaries",
        "title": "Structured completion notes",
        "body": "Bounded nominations retain canonical attribution.",
        "attribution": "forge_implementation_discovery",
        "evidence": [evidence()],
    }
    value.update(updates)
    return value


def manifest_data(**updates: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "version": 1,
        "period": {
            "kind": "daily",
            "start": "2026-08-29",
            "end": "2026-08-29",
        },
        "sections": [{"kind": "shipped", "items": [item()]}],
    }
    value.update(updates)
    return value


def parse(value: dict[str, Any]) -> dispatch.DispatchManifest:
    return dispatch.parse_manifest_text(json.dumps(value))


def canonical_envelope(
    candidates: list[completion_notes.CandidateDraft],
    *,
    sequence: int = 17,
    sent_at: int | None = None,
) -> dict[str, Any]:
    body = completion_notes.append_completion_notes("DONE task=public-evidence", candidates)
    return {
        "msg_id": f"msg-{sequence:032x}",
        "sent_at": sent_at if sent_at is not None else 1_800_000_000_000 + sequence,
        "sender_kind": "agent",
        "sender_agent_id": f"ag-{sequence:032x}",
        "sender_agent_name": "forge",
        "origin_instance_id": "sy-" + "a" * 32,
        "content_type": "text/plain",
        "body": body,
        "sequence": sequence,
    }


def dispatch_candidate(
    summary: str = "Untrusted worker wording must never become public copy.",
) -> completion_notes.CandidateDraft:
    return completion_notes.CandidateDraft(
        candidate_type=completion_notes.CandidateType.DISPATCH,
        attribution=completion_notes.AttributionCategory.FORGE_IMPLEMENTATION_DISCOVERY,
        summary=summary,
        interest="high",
        evidence=(
            completion_notes.EvidenceRef(completion_notes.EvidenceKind.ISSUE, "#437"),
            completion_notes.EvidenceRef(completion_notes.EvidenceKind.COORD, "private coordination reference"),
        ),
    )


def verified_evidence() -> tuple[dispatch.PublicEvidence, ...]:
    return (dispatch.PublicEvidence(dispatch.PublicEvidenceKind.ISSUE, "Issue #437", ISSUE_URL),)


def test_real_completion_nomination_is_verified_but_never_copied_publicly() -> None:
    envelope = canonical_envelope([dispatch_candidate()])

    def verifier(
        candidate: completion_notes.ParsedCandidate,
    ) -> dispatch.VerifiedNominationDraft | None:
        assert candidate.summary.startswith("Untrusted worker wording")
        return dispatch.VerifiedNominationDraft(
            key="completion-note-boundary",
            attribution=dispatch.PublicAttribution.FORGE_IMPLEMENTATION_DISCOVERY,
            evidence=verified_evidence(),
        )

    nominations = dispatch.collect_verified_nominations([envelope], verifier)
    assert len(nominations) == 1
    assert nominations[0].provenance.coord_sequence == 17

    source = manifest_data()
    source["sections"][0]["items"][0]["nomination_keys"] = ["completion-note-boundary"]
    rendered = dispatch.generate_files(parse(source), verified_nominations=nominations)[0].content
    assert "Bounded nominations retain canonical attribution" in rendered
    assert "Untrusted worker wording" not in rendered
    assert "private coordination reference" not in rendered
    assert envelope["msg_id"] not in rendered
    assert "coord_sequence" not in rendered
    assert "DISPATCH_CANDIDATE" not in rendered
    assert f"[Issue #437]({ISSUE_URL})" in rendered


def test_unsupported_or_wrong_kind_nominations_are_suppressed() -> None:
    factory = completion_notes.CandidateDraft(
        candidate_type=completion_notes.CandidateType.FACTORY,
        attribution=completion_notes.AttributionCategory.FACTORY_PROCESS_OBSERVATION,
        summary="Not Dispatch material.",
    )
    envelopes = [
        canonical_envelope([dispatch_candidate()]),
        canonical_envelope([factory], sequence=18),
        {**canonical_envelope([dispatch_candidate()], sequence=19), "body": "malformed"},
    ]
    assert dispatch.collect_verified_nominations(envelopes, lambda _candidate: None) == ()

    source = manifest_data()
    source["sections"][0]["items"][0]["nomination_keys"] = ["unsupported"]
    with pytest.raises(dispatch.DispatchError, match="unverified nomination"):
        dispatch.generate_files(parse(source))


def test_qualified_nomination_retains_public_qualification_and_evidence() -> None:
    qualification = "The mechanism is verified; production frequency is not yet known."
    nominations = dispatch.collect_verified_nominations(
        [canonical_envelope([dispatch_candidate()])],
        lambda _candidate: dispatch.VerifiedNominationDraft(
            key="qualified-mechanism",
            attribution=dispatch.PublicAttribution.FORGE_IMPLEMENTATION_DISCOVERY,
            evidence=verified_evidence(),
            disposition=dispatch.NominationDisposition.QUALIFIED,
            qualification=qualification,
        ),
    )
    source = manifest_data()
    source_item = source["sections"][0]["items"][0]
    source_item["nomination_keys"] = ["qualified-mechanism"]
    source_item["qualification"] = qualification
    rendered = dispatch.generate_files(parse(source), verified_nominations=nominations)[0].content
    assert f"**Qualification:** {qualification}" in rendered

    source_item["qualification"] = "Different editorial claim."
    with pytest.raises(dispatch.DispatchError, match="retain Relay"):
        dispatch.generate_files(parse(source), verified_nominations=nominations)


def test_nomination_order_and_multiple_candidates_are_deterministic() -> None:
    first = dispatch_candidate("first")
    second = dispatch_candidate("second")

    def verifier(
        candidate: completion_notes.ParsedCandidate,
    ) -> dispatch.VerifiedNominationDraft:
        return dispatch.VerifiedNominationDraft(
            key=f"candidate-{candidate.summary}",
            attribution=dispatch.PublicAttribution.FORGE_IMPLEMENTATION_DISCOVERY,
            evidence=verified_evidence(),
        )

    later = canonical_envelope([first, second], sequence=30, sent_at=1_800_000_000_030)
    earlier = canonical_envelope([first], sequence=20, sent_at=1_800_000_000_020)
    collected = dispatch.collect_verified_nominations([later, earlier], verifier)
    assert [item.key for item in collected] == ["candidate-first", "candidate-second"]
    assert collected[0].provenance.coord_sequence == 20


def test_conflicting_canonical_message_identity_fails_order_independently() -> None:
    first = canonical_envelope([dispatch_candidate("first")], sequence=20)
    second = canonical_envelope([dispatch_candidate("second")], sequence=21)
    second["msg_id"] = first["msg_id"]

    def verifier(
        candidate: completion_notes.ParsedCandidate,
    ) -> dispatch.VerifiedNominationDraft:
        return dispatch.VerifiedNominationDraft(
            key=f"candidate-{candidate.summary}",
            attribution=dispatch.PublicAttribution.FORGE_IMPLEMENTATION_DISCOVERY,
            evidence=verified_evidence(),
        )

    for envelopes in ([first, second], [second, first]):
        with pytest.raises(dispatch.DispatchError, match="conflicting envelopes"):
            dispatch.collect_verified_nominations(envelopes, verifier)

    assert len(dispatch.collect_verified_nominations([first, dict(first)], verifier)) == 1


def test_conflicting_verified_results_for_one_key_fail_closed() -> None:
    calls = 0

    def verifier(
        _candidate: completion_notes.ParsedCandidate,
    ) -> dispatch.VerifiedNominationDraft:
        nonlocal calls
        calls += 1
        return dispatch.VerifiedNominationDraft(
            key="same-key",
            attribution=dispatch.PublicAttribution.FORGE_IMPLEMENTATION_DISCOVERY,
            evidence=(
                dispatch.PublicEvidence(
                    dispatch.PublicEvidenceKind.ISSUE,
                    f"Issue #{436 + calls}",
                    f"https://github.com/craigbalding/safeyolo/issues/{436 + calls}",
                ),
            ),
        )

    with pytest.raises(dispatch.DispatchError, match="conflicting"):
        dispatch.collect_verified_nominations(
            [
                canonical_envelope([dispatch_candidate()], sequence=20),
                canonical_envelope([dispatch_candidate()], sequence=21),
            ],
            verifier,
        )


def test_nomination_retains_relay_verified_attribution() -> None:
    nominations = dispatch.collect_verified_nominations(
        [canonical_envelope([dispatch_candidate()])],
        lambda _candidate: dispatch.VerifiedNominationDraft(
            key="verified-attribution",
            attribution=dispatch.PublicAttribution.PREEXISTING_BUG_EXPOSED_BY_TESTING,
            evidence=verified_evidence(),
        ),
    )
    source = manifest_data()
    source_item = source["sections"][0]["items"][0]
    source_item["nomination_keys"] = ["verified-attribution"]
    with pytest.raises(dispatch.DispatchError, match="verified attribution"):
        dispatch.generate_files(parse(source), verified_nominations=nominations)

    source_item["attribution"] = "preexisting_bug_exposed_by_testing"
    dispatch.generate_files(parse(source), verified_nominations=nominations)


def test_dispatch_groups_shipped_by_theme_and_omits_empty_optional_sections() -> None:
    source = manifest_data()
    source["sections"][0]["items"].extend(
        [
            item(title="Second in theme"),
            item(theme="Operator access", title="Another theme"),
        ]
    )
    rendered = dispatch.render_dispatch(parse(source))
    assert rendered is not None
    assert rendered.count("### Evidence boundaries") == 1
    assert rendered.index("Second in theme") < rendered.index("Operator access")
    assert "## Worth knowing" not in rendered
    assert "## Factory pulse" not in rendered


def test_lens_section_requires_review_attribution_snippet_and_lesson() -> None:
    review = {
        "title": "Freeze exact presentation bytes",
        "body": "Review exposed same-revision body drift.",
        "attribution": "lens_review_finding",
        "snippet": {"language": "python", "code": "if ready:\n    freeze()"},
        "lesson": "Semantic revisions and selected bytes must advance together.",
        "evidence": [evidence(kind="pr", label="PR #446", url="https://github.com/craigbalding/safeyolo/pull/446")],
    }
    source = manifest_data(
        sections=[
            {"kind": "shipped", "items": [item()]},
            {"kind": "lens_caught", "items": [review]},
        ]
    )
    rendered = dispatch.render_dispatch(parse(source))
    assert rendered is not None
    assert "Independent review finding (Lens)" in rendered
    assert "```python\nif ready:" in rendered
    assert "**Lesson:**" in rendered

    review["attribution"] = "forge_implementation_discovery"
    with pytest.raises(dispatch.DispatchError, match="Lens review"):
        parse(source)


def test_quiet_input_produces_no_file_or_filler() -> None:
    manifest = parse(manifest_data(sections=[], topic_updates=[]))
    assert dispatch.render_dispatch(manifest) is None
    assert dispatch.generate_files(manifest) == ()

    with pytest.raises(dispatch.DispatchError, match="cannot be empty"):
        parse(manifest_data(sections=[{"kind": "worth_knowing", "items": []}]))


@pytest.mark.parametrize(
    "unsafe",
    [
        "Bearer abcdefghijklmnopqrstuvwxyz",
        "github_pat_abcdefghijklmnopqrstuvwxyz",
        "sgw_abcdefghijklmnopqrstuvwxyz",
        "msg-" + "a" * 32,
        "ag-" + "a" * 32,
        "sy-" + "a" * 32,
        "rm-" + "a" * 32,
        "attn-" + "a" * 32,
        "coord sequence=240",
        "coord seq 296",
        "coord sequence #296",
        "private chain-of-thought follows",
        "read /app/agent_token",
        "-----BEGIN " + "PRIVATE KEY-----",
    ],
)
def test_public_fields_reject_secrets_private_coord_and_raw_reasoning(unsafe: str) -> None:
    source = manifest_data()
    if "coord" in unsafe:
        source["definitions"] = {"coord": "SafeYolo's canonical attributed coordination channel."}
    source["sections"][0]["items"][0]["body"] = unsafe
    with pytest.raises(
        dispatch.DispatchError,
        match="credential|private coordination|reasoning material",
    ):
        parse(source)


def test_safe_yolo_specific_terms_require_expansion_without_unused_filler() -> None:
    source = manifest_data()
    source["sections"][0]["items"][0]["body"] = "The coord boundary stayed canonical."
    with pytest.raises(dispatch.DispatchError, match="require public definitions"):
        parse(source)

    source["definitions"] = {"coord": "SafeYolo's canonical attributed coordination channel."}
    rendered = dispatch.render_dispatch(parse(source))
    assert rendered is not None
    assert "`coord` — SafeYolo's canonical attributed coordination channel." in rendered

    source["definitions"] = {
        "coord": "The channel associates every message with a run_id.",
        "run_id": "SafeYolo's identifier for one sandbox run.",
    }
    rendered = dispatch.render_dispatch(parse(source))
    assert rendered is not None
    assert "`run_id` — SafeYolo's identifier for one sandbox run." in rendered

    source["sections"][0]["items"][0]["body"] = "The boundary stayed canonical."
    source["definitions"] = {"coord": "SafeYolo's canonical attributed coordination channel."}
    with pytest.raises(dispatch.DispatchError, match="unused"):
        parse(source)


def test_evidence_labels_require_and_render_safe_yolo_term_definitions() -> None:
    source = manifest_data()
    source["sections"][0]["items"][0]["evidence"][0]["label"] = "Coord generation issue"
    with pytest.raises(dispatch.DispatchError, match="require public definitions"):
        parse(source)

    source["definitions"] = {"coord": "SafeYolo's canonical attributed coordination channel."}
    rendered = dispatch.render_dispatch(parse(source))
    assert rendered is not None
    assert "`coord` — SafeYolo's canonical attributed coordination channel." in rendered

    source["sections"][0]["items"][0]["evidence"][0]["label"] = "Issue #437"
    source["topic_updates"] = [topic_source()]
    source["topic_updates"][0]["evidence"][0]["label"] = "Coord topic issue"
    topic = next(
        generated
        for generated in dispatch.generate_files(parse(source))
        if generated.relative_path == Path("topics/coord.md")
    )
    assert "`coord` — SafeYolo's canonical attributed coordination channel." in topic.content


@pytest.mark.parametrize(
    ("kind", "url"),
    [
        ("issue", "http://github.com/craigbalding/safeyolo/issues/437"),
        ("issue", "https://example.com/craigbalding/safeyolo/issues/437"),
        ("issue", "https://github.com/other/private/issues/1"),
        ("pr", ISSUE_URL),
        ("commit", "https://github.com/craigbalding/safeyolo/commit/main"),
        ("test", "https://github.com/craigbalding/safeyolo/blob/master/secret"),
        ("issue", ISSUE_URL + "?token=secret"),
    ],
)
def test_material_claims_require_matching_public_github_evidence(kind: str, url: str) -> None:
    source = manifest_data()
    source["sections"][0]["items"][0]["evidence"] = [evidence(kind=kind, url=url)]
    with pytest.raises(dispatch.DispatchError):
        parse(source)


def test_relay_copy_is_plain_markdown_and_only_evidence_becomes_a_link() -> None:
    source = manifest_data()
    source["sections"][0]["items"][0]["body"] = "Authored [link](relative-path) and <script> stay inert."
    rendered = dispatch.render_dispatch(parse(source))
    assert rendered is not None
    assert "[link](relative-path)" not in rendered
    assert r"\[link\](relative-path)" in rendered
    assert r"\<script\>" in rendered
    assert f"[Issue #437]({ISSUE_URL})" in rendered

    source["sections"][0]["items"][0]["body"] = "Raw https://example.com is not validated evidence."
    with pytest.raises(dispatch.DispatchError, match="cannot contain links"):
        parse(source)


def test_code_fence_expands_around_authored_backticks() -> None:
    source = manifest_data(
        sections=[
            {
                "kind": "lens_caught",
                "items": [
                    {
                        "title": "Fence safely",
                        "body": "The example remains one inert code block.",
                        "attribution": "lens_review_finding",
                        "snippet": {
                            "language": "text",
                            "code": "before\n```\nafter",
                        },
                        "lesson": "Choose a fence longer than any run in the snippet.",
                        "evidence": [evidence()],
                    }
                ],
            }
        ]
    )
    rendered = dispatch.render_dispatch(parse(source))
    assert rendered is not None
    assert "````text\nbefore\n```\nafter\n````" in rendered


@pytest.mark.parametrize(
    ("kind", "start", "end", "path"),
    [
        ("daily", "2026-08-29", "2026-08-29", "dispatch/2026-08-29.md"),
        ("weekly", "2026-08-24", "2026-08-30", "snapshots/2026-W35.md"),
        ("monthly", "2026-08-01", "2026-08-31", "snapshots/2026-08.md"),
    ],
)
def test_one_content_model_supports_daily_weekly_and_monthly_paths(kind: str, start: str, end: str, path: str) -> None:
    source = manifest_data(period={"kind": kind, "start": start, "end": end})
    files = dispatch.generate_files(parse(source))
    assert files[0].relative_path.as_posix() == path


@pytest.mark.parametrize(
    ("kind", "start", "end"),
    [
        ("daily", "2026-08-29", "2026-08-30"),
        ("weekly", "2026-08-25", "2026-08-31"),
        ("monthly", "2026-08-02", "2026-08-31"),
    ],
)
def test_invalid_period_boundaries_fail_closed(kind: str, start: str, end: str) -> None:
    with pytest.raises(dispatch.DispatchError):
        parse(manifest_data(period={"kind": kind, "start": start, "end": end}))


def topic_source(*, state_key: str = "coord-v1", summary: str = "Current state.") -> dict[str, Any]:
    return {
        "slug": "coord",
        "title": "Coord collaboration",
        "state_key": state_key,
        "material_change": "A verified transport change altered the current coord boundary.",
        "summary": summary,
        "current_state": ["Coord remains the attributed message authority."],
        "evidence": [evidence()],
    }


def topic_manifest(**topic_updates: Any) -> dispatch.DispatchManifest:
    source = manifest_data(
        definitions={"coord": "SafeYolo's canonical attributed coordination channel."},
        topic_updates=[topic_source(**topic_updates)],
    )
    return parse(source)


def test_topic_same_state_is_idempotent_and_copy_only_change_is_rejected() -> None:
    manifest = topic_manifest()
    initial = dispatch.generate_files(manifest)
    topic = next(item for item in initial if item.relative_path.as_posix() == "topics/coord.md")
    existing = {"topics/coord.md": topic.content}
    assert dispatch.generate_files(manifest, existing_topics=existing) == initial

    changed_copy = topic_manifest(summary="Wording changed without a state change.")
    with pytest.raises(dispatch.DispatchError, match="material state_key"):
        dispatch.generate_files(changed_copy, existing_topics=existing)

    material = topic_manifest(state_key="coord-v2", summary="Material state changed.")
    generated = dispatch.generate_files(material, existing_topics=existing)
    changed_topic = next(item for item in generated if item.relative_path.as_posix() == "topics/coord.md")
    assert "safeyolo-topic-state: coord-v2" in changed_topic.content


def test_existing_topic_without_semantic_marker_fails_closed() -> None:
    with pytest.raises(dispatch.DispatchError, match="lacks"):
        dispatch.generate_files(topic_manifest(), existing_topics={"topics/coord.md": "# Hand-written\n"})


def test_strict_source_rejects_duplicates_unknowns_and_decoder_abuse() -> None:
    with pytest.raises(dispatch.DispatchError, match="duplicate"):
        dispatch.parse_manifest_text('{"version":1,"version":1}')
    source = manifest_data(extra="unknown")
    with pytest.raises(dispatch.DispatchError, match="unknown"):
        parse(source)
    with pytest.raises(dispatch.DispatchError):
        dispatch.parse_manifest_text("[" * 10_000 + "0" + "]" * 10_000)
    with pytest.raises(dispatch.DispatchError, match="integer"):
        dispatch.parse_manifest_text('{"version":' + "9" * 100 + "}")
    with pytest.raises(dispatch.DispatchError, match="exceeds"):
        dispatch.parse_manifest_text(" " * (dispatch.MAX_MANIFEST_BYTES + 1))


def test_source_fingerprint_and_rendering_are_deterministic() -> None:
    first = parse(manifest_data())
    second = parse(manifest_data())
    assert dispatch.source_fingerprint(first) == dispatch.source_fingerprint(second)
    assert dispatch.generate_files(first) == dispatch.generate_files(second)


def test_writer_is_atomic_idempotent_and_check_only(tmp_path: Path) -> None:
    files = dispatch.generate_files(parse(manifest_data()))
    root = tmp_path / "site"
    assert dispatch.write_generated_files(root, files) == (Path("dispatch/2026-08-29.md"),)
    target = root / "dispatch/2026-08-29.md"
    original = target.read_bytes()
    assert dispatch.write_generated_files(root, files) == ()
    assert dispatch.write_generated_files(root, files, check=True) == ()
    assert target.read_bytes() == original

    target.write_text("stale\n", encoding="utf-8")
    with pytest.raises(dispatch.DispatchError, match="stale"):
        dispatch.write_generated_files(root, files, check=True)
    assert target.read_text(encoding="utf-8") == "stale\n"


def test_check_mode_does_not_create_missing_output_tree(tmp_path: Path) -> None:
    root = tmp_path / "missing"
    with pytest.raises(dispatch.DispatchError, match="missing"):
        dispatch.write_generated_files(root, dispatch.generate_files(parse(manifest_data())), check=True)
    assert not root.exists()


def test_writer_rejects_symlinks_and_path_escape(tmp_path: Path) -> None:
    files = dispatch.generate_files(parse(manifest_data()))
    real = tmp_path / "real"
    real.mkdir()
    root_link = tmp_path / "site-link"
    root_link.symlink_to(real, target_is_directory=True)
    with pytest.raises(dispatch.DispatchError, match="symlink|real directory"):
        dispatch.write_generated_files(root_link, files)

    root = tmp_path / "site"
    root.mkdir()
    (root / "dispatch").symlink_to(real, target_is_directory=True)
    with pytest.raises(dispatch.DispatchError, match="symlink"):
        dispatch.write_generated_files(root, files)

    escaped = dispatch.GeneratedFile(Path("../outside.md"), "safe\n")
    with pytest.raises(dispatch.DispatchError, match="escapes"):
        dispatch.write_generated_files(root, [escaped])

    nested = dispatch.GeneratedFile(Path("topics/nested/out.md"), "safe\n")
    with pytest.raises(dispatch.DispatchError, match="outside"):
        dispatch.write_generated_files(root, [nested])


def test_directory_swap_cannot_redirect_final_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    files = dispatch.generate_files(parse(manifest_data()))
    root = tmp_path / "site"
    dispatch.write_generated_files(root, files)
    publication_directory = root / "dispatch"
    held_directory = root / "dispatch-held"
    outside = tmp_path / "outside"
    outside.mkdir()
    original_existing = dispatch._existing_output
    swapped = False

    def swap_after_read(parent_fd: int, name: str) -> str | None:
        nonlocal swapped
        result = original_existing(parent_fd, name)
        if not swapped:
            publication_directory.rename(held_directory)
            publication_directory.symlink_to(outside, target_is_directory=True)
            swapped = True
        return result

    monkeypatch.setattr(dispatch, "_existing_output", swap_after_read)
    changed = dispatch.GeneratedFile(
        files[0].relative_path,
        files[0].content + "race-safe\n",
    )
    dispatch.write_generated_files(root, [changed])
    assert not (outside / files[0].relative_path.name).exists()
    assert (held_directory / files[0].relative_path.name).read_text(encoding="utf-8") == changed.content


def test_failed_atomic_replace_preserves_existing_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    files = dispatch.generate_files(parse(manifest_data()))
    root = tmp_path / "site"
    dispatch.write_generated_files(root, files)
    target = root / files[0].relative_path
    original = target.read_bytes()
    changed = dispatch.GeneratedFile(files[0].relative_path, files[0].content + "changed\n")

    def fail_replace(_source: str, _target: str, **_kwargs: Any) -> None:
        raise OSError("simulated replace failure")

    monkeypatch.setattr(dispatch.os, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated"):
        dispatch.write_generated_files(root, [changed])
    assert target.read_bytes() == original
    assert list(target.parent.glob(f".{target.name}.*.tmp")) == []


def test_dogfood_source_generates_exact_repository_dispatch_and_topic() -> None:
    source = REPO_ROOT / "site/_sources/dispatch/2026-08-29.json"
    manifest = dispatch.load_manifest(source)
    existing = {}
    topic_path = REPO_ROOT / "site/topics/coord.md"
    if topic_path.exists():
        existing["topics/coord.md"] = topic_path.read_text(encoding="utf-8")
    files = dispatch.generate_files(manifest, existing_topics=existing)
    expected = {
        "dispatch/2026-08-29.md": REPO_ROOT / "site/dispatch/2026-08-29.md",
        "topics/coord.md": topic_path,
    }
    assert {item.relative_path.as_posix() for item in files} == set(expected)
    for generated in files:
        assert expected[generated.relative_path.as_posix()].read_text(encoding="utf-8") == generated.content
    dispatch_text = expected["dispatch/2026-08-29.md"].read_text(encoding="utf-8")
    assert "Freeze the proposal body" in dispatch_text
    assert "Put process locks beside SQLite" in dispatch_text
    assert "coord sequence" not in dispatch_text
    assert "marketing" not in dispatch_text.lower()
