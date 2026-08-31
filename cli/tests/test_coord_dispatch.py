from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from safeyolo.coord import dispatch

REPO_ROOT = Path(__file__).resolve().parents[2]
ISSUE_URL = "https://github.com/craigbalding/safeyolo/issues/437"


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


def test_quiet_input_produces_no_file_or_filler(tmp_path: Path) -> None:
    manifest = parse(manifest_data(sections=[], topic_updates=[]))
    assert dispatch.render_dispatch(manifest) is None
    assert dispatch.generate_files(manifest) == ()
    output_root = tmp_path / "site"
    assert dispatch.write_generated_files(output_root, ()) == ()
    assert not output_root.exists()

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


def test_definitions_are_content_owned_extensible_and_omit_unused_filler() -> None:
    source = manifest_data()
    source["sections"][0]["items"][0]["body"] = "The plumb route stayed bounded."
    source["definitions"] = {"plumb": "SafeYolo's operator-approved agent collaboration path."}
    rendered = dispatch.render_dispatch(parse(source))
    assert rendered is not None
    assert "`plumb` — SafeYolo's operator-approved agent collaboration path." in rendered

    source["definitions"] = {
        "plumb": "The path associates every exchange with a run_id.",
        "run_id": "SafeYolo's identifier for one sandbox run.",
    }
    rendered = dispatch.render_dispatch(parse(source))
    assert rendered is not None
    assert "`run_id` — SafeYolo's identifier for one sandbox run." in rendered

    source["sections"][0]["items"][0]["body"] = "The route stayed bounded."
    source["definitions"] = {"plumb": "SafeYolo's operator-approved agent collaboration path."}
    with pytest.raises(dispatch.DispatchError, match="unused"):
        parse(source)


def test_used_definitions_are_scoped_to_dispatch_and_topic_content() -> None:
    source = manifest_data()
    source["sections"][0]["items"][0]["evidence"][0]["label"] = "Plumb generation issue"
    source["definitions"] = {"plumb": "SafeYolo's operator-approved agent collaboration path."}
    rendered = dispatch.render_dispatch(parse(source))
    assert rendered is not None
    assert "`plumb` — SafeYolo's operator-approved agent collaboration path." in rendered

    source["sections"][0]["items"][0]["evidence"][0]["label"] = "Issue #437"
    source["topic_updates"] = [topic_source()]
    source["topic_updates"][0]["evidence"][0]["label"] = "Plumb topic issue"
    topic = next(
        generated
        for generated in dispatch.generate_files(parse(source))
        if generated.relative_path == Path("topics/coord.md")
    )
    assert "`plumb` — SafeYolo's operator-approved agent collaboration path." in topic.content


@pytest.mark.parametrize(
    ("kind", "url"),
    [
        ("issue", "https://github.com/python/cpython/issues/12345"),
        ("test", "https://github.com/python/cpython/blob/main/Lib/test/test_json/test_decode.py"),
        ("document", "https://sqlite.org/lockingv3.html"),
        ("runtime", "https://www.sqlite.org/lockingv3.html#locking"),
    ],
)
def test_authoritative_upstream_and_public_evidence_is_allowed(kind: str, url: str) -> None:
    source = manifest_data()
    source["sections"][0]["items"][0]["evidence"] = [evidence(kind=kind, url=url)]
    parse(source)


@pytest.mark.parametrize(
    ("kind", "url"),
    [
        ("issue", "http://github.com/craigbalding/safeyolo/issues/437"),
        ("runtime", "https://service.internal/report"),
        ("runtime", "https://127.0.0.1/report"),
        ("runtime", "https://127.1/report"),
        ("runtime", "https://0177.0.0.1/report"),
        ("runtime", "https://example .com/report"),
        ("runtime", "https://example%20.com/report"),
        ("runtime", "https://example.com/report) **INJECTED**"),
        ("pr", ISSUE_URL),
        ("pr", "https://github.com./craigbalding/safeyolo/issues/455"),
        ("commit", "https://github.com/craigbalding/safeyolo/commit/main"),
        ("test", ISSUE_URL),
        ("issue", ISSUE_URL + "?token=secret"),
    ],
)
def test_evidence_rejects_non_public_urls_and_known_kind_mismatches(kind: str, url: str) -> None:
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


def test_topic_copy_and_evidence_corrections_can_keep_the_same_state_key() -> None:
    manifest = topic_manifest()
    initial = dispatch.generate_files(manifest)
    assert dispatch.generate_files(manifest) == initial

    changed_copy = topic_manifest(summary="Wording changed without a state change.")
    corrected = next(
        item for item in dispatch.generate_files(changed_copy) if item.relative_path.as_posix() == "topics/coord.md"
    )
    assert "safeyolo-topic-state: coord-v1" in corrected.content
    assert "Wording changed without a state change." in corrected.content

    material = topic_manifest(state_key="coord-v2", summary="Material state changed.")
    generated = dispatch.generate_files(material)
    changed_topic = next(item for item in generated if item.relative_path.as_posix() == "topics/coord.md")
    assert "safeyolo-topic-state: coord-v2" in changed_topic.content


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


def test_rendering_is_deterministic() -> None:
    first = parse(manifest_data())
    second = parse(manifest_data())
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


def test_manifest_requires_a_regular_non_symlink_source(tmp_path: Path) -> None:
    source = tmp_path / "dispatch.json"
    source.write_text(json.dumps(manifest_data()), encoding="utf-8")
    assert dispatch.load_manifest(source).sections[0].items[0].title == "Structured completion notes"

    link = tmp_path / "dispatch-link.json"
    link.symlink_to(source)
    with pytest.raises(dispatch.DispatchError, match="non-symlink"):
        dispatch.load_manifest(link)


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

    (root / "dispatch").unlink()
    (root / "dispatch").mkdir()
    outside_file = real / "outside.md"
    outside_file.write_text("outside\n", encoding="utf-8")
    (root / files[0].relative_path).symlink_to(outside_file)
    with pytest.raises(dispatch.DispatchError, match="non-symlink"):
        dispatch.write_generated_files(root, files)
    assert outside_file.read_text(encoding="utf-8") == "outside\n"

    escaped = dispatch.GeneratedFile(Path("../outside.md"), "safe\n")
    with pytest.raises(dispatch.DispatchError, match="escapes"):
        dispatch.write_generated_files(root, [escaped])

    nested = dispatch.GeneratedFile(Path("topics/nested/out.md"), "safe\n")
    with pytest.raises(dispatch.DispatchError, match="outside"):
        dispatch.write_generated_files(root, [nested])


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
    topic_path = REPO_ROOT / "site/topics/coord.md"
    files = dispatch.generate_files(manifest)
    expected = {
        "dispatch/2026-08-29.md": REPO_ROOT / "site/dispatch/2026-08-29.md",
        "topics/coord.md": topic_path,
    }
    assert {item.relative_path.as_posix() for item in files} == set(expected)
    for generated in files:
        assert expected[generated.relative_path.as_posix()].read_text(encoding="utf-8") == generated.content
    dispatch_text = expected["dispatch/2026-08-29.md"].read_text(encoding="utf-8")
    assert "Freeze proposal text with the revision that selected it" in dispatch_text
    assert "A process lock conflicted with SQLite on macOS" in dispatch_text
    assert "uses SQLite to remember processed messages" in dispatch_text
    assert "does not ship that capability today" in dispatch_text
    assert "coord sequence" not in dispatch_text
    assert "marketing" not in dispatch_text.lower()
