"""Contracts for the optional agent-facing GitHub composite checks."""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SKILL_ROOT = REPO_ROOT / "cli/src/safeyolo/agent_context/skills/safeyolo"
HELPER_PATH = SKILL_ROOT / "scripts/github_checks.py"


def _load_helper():
    spec = importlib.util.spec_from_file_location("agent_github_checks_test", HELPER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _intake_payload() -> dict:
    return {
        "request": {
            "repository": "different-owner/another-project",
            "issue": 27,
            "expectations": {
                "owner_login": "different-owner",
                "owner_type": "Organization",
                "visibility": "private",
                "issue_type": "issue",
                "issue_state": "open",
                "issue_author_login": "reporter",
                "archived": False,
            },
        },
        "evidence": {
            "repository": {
                "status": "ok",
                "facts": {
                    "full_name": "different-owner/another-project",
                    "owner_login": "different-owner",
                    "owner_type": "Organization",
                    "visibility": "private",
                    "archived": False,
                    "default_branch": "trunk",
                },
            },
            "issue": {
                "status": "ok",
                "facts": {
                    "repository": "different-owner/another-project",
                    "number": 27,
                    "type": "issue",
                    "state": "open",
                    "author_login": "reporter",
                    "url": "https://github.com/different-owner/another-project/issues/27",
                },
            },
        },
    }


def _candidate_payload() -> dict:
    head = "a" * 40
    return {
        "request": {
            "repository": "different-owner/another-project",
            "pull_request": 31,
            "linked_issue": 27,
            "expected_head_sha": head,
            "review_head_sha": head,
            "acceptance_head_sha": head,
        },
        "evidence": {
            "pull_request": {
                "status": "ok",
                "facts": {
                    "repository": "different-owner/another-project",
                    "number": 31,
                    "base_ref": "trunk",
                    "base_sha": "b" * 40,
                    "head_ref": "fix-27",
                    "head_sha": head,
                    "body": "Closes different-owner/another-project#27.",
                    "state": "open",
                    "draft": False,
                    "url": "https://github.com/different-owner/another-project/pull/31",
                },
            },
            "tree": {
                "status": "ok",
                "facts": {"commit_sha": head, "tree_sha": "c" * 40},
            },
            "linked_issue": {
                "status": "ok",
                "facts": {
                    "repository": "different-owner/another-project",
                    "number": 27,
                    "type": "issue",
                    "state": "open",
                    "author_login": "reporter",
                    "url": "https://github.com/different-owner/another-project/issues/27",
                },
            },
        },
    }


def test_intake_success_returns_all_decision_facts() -> None:
    helper = _load_helper()

    result = helper.evaluate_intake(_intake_payload())

    assert result["passed"] is True
    assert result["outcome"] == "pass"
    assert result["failed_conditions"] == []
    assert result["unavailable_evidence"] == []
    assert result["facts"]["repository"] == {
        "full_name": "different-owner/another-project",
        "owner_login": "different-owner",
        "owner_type": "Organization",
        "visibility": "private",
        "archived": False,
        "default_branch": "trunk",
    }
    assert result["facts"]["issue"]["author_login"] == "reporter"


def test_intake_reports_every_proved_mismatch() -> None:
    helper = _load_helper()
    payload = _intake_payload()
    payload["evidence"]["repository"]["facts"].update(
        owner_login="someone-else", visibility="public"
    )
    payload["evidence"]["issue"]["facts"].update(state="closed", author_login="other")

    result = helper.evaluate_intake(payload)

    assert result["passed"] is False
    assert result["outcome"] == "rule_mismatch"
    assert {item["field"] for item in result["failed_conditions"]} == {
        "repository.owner_login",
        "repository.visibility",
        "issue.state",
        "issue.author_login",
    }


def test_unavailable_intake_evidence_is_not_an_ordinary_rule_mismatch() -> None:
    helper = _load_helper()
    payload = _intake_payload()
    payload["evidence"]["repository"] = {"status": "unavailable", "reason": "unauthorized"}
    payload["evidence"]["issue"]["facts"]["state"] = "closed"

    result = helper.evaluate_intake(payload)

    assert result["passed"] is False
    assert result["outcome"] == "evidence_unavailable"
    assert result["unavailable_evidence"] == [
        {"field": "repository", "reason": "unauthorized"},
        {"field": "repository.full_name", "reason": "missing"},
        {"field": "repository.owner_login", "reason": "missing"},
        {"field": "repository.owner_type", "reason": "missing"},
        {"field": "repository.visibility", "reason": "missing"},
        {"field": "repository.archived", "reason": "missing"},
    ]
    assert [item["field"] for item in result["failed_conditions"]] == ["issue.state"]


def test_malformed_intake_reference_fails_before_evidence_is_interpreted() -> None:
    helper = _load_helper()
    payload = _intake_payload()
    payload["request"]["repository"] = "https://github.com/owner/project"

    result = helper.evaluate_intake(payload)

    assert result["outcome"] == "invalid_request"
    assert result["facts"] == {}
    assert result["request_errors"][0]["field"] == "request.repository"


def test_candidate_success_returns_base_head_tree_issue_and_current_evidence() -> None:
    helper = _load_helper()

    result = helper.evaluate_candidate(_candidate_payload())

    assert result["passed"] is True
    assert result["outcome"] == "pass"
    assert result["facts"]["pull_request"]["base_ref"] == "trunk"
    assert result["facts"]["pull_request"]["head_sha"] == "a" * 40
    assert "body" not in result["facts"]["pull_request"]
    assert result["facts"]["tree"] == {"commit_sha": "a" * 40, "tree_sha": "c" * 40}
    assert result["facts"]["linked_issue"]["number"] == 27
    assert result["facts"]["linked_issue_reference"] is True
    assert result["facts"]["evidence_currency"] == {
        "review": {"status": "current", "head_sha": "a" * 40},
        "acceptance": {"status": "current", "head_sha": "a" * 40},
    }


def test_moved_head_and_stale_review_are_reported_separately() -> None:
    helper = _load_helper()
    payload = _candidate_payload()
    payload["evidence"]["pull_request"]["facts"]["head_sha"] = "d" * 40
    payload["evidence"]["tree"]["facts"].update(
        commit_sha="d" * 40, tree_sha="e" * 40
    )
    payload["request"]["acceptance_head_sha"] = "d" * 40

    result = helper.evaluate_candidate(payload)

    assert result["passed"] is False
    assert result["outcome"] == "rule_mismatch"
    assert {item["field"] for item in result["failed_conditions"]} == {
        "pull_request.head_sha",
        "review.head_sha",
    }
    assert result["facts"]["evidence_currency"] == {
        "review": {"status": "stale", "head_sha": "a" * 40},
        "acceptance": {"status": "current", "head_sha": "d" * 40},
    }


def test_missing_or_ambiguous_candidate_evidence_is_unavailable() -> None:
    helper = _load_helper()
    payload = _candidate_payload()
    payload["evidence"]["tree"] = {"status": "unavailable", "reason": "missing"}
    payload["evidence"]["linked_issue"] = {
        "status": "unavailable",
        "reason": "ambiguous",
    }

    result = helper.evaluate_candidate(payload)

    assert result["passed"] is False
    assert result["outcome"] == "evidence_unavailable"
    assert {item["reason"] for item in result["unavailable_evidence"]} == {
        "missing",
        "ambiguous",
    }


def test_malformed_candidate_fact_is_unavailable_and_not_a_mismatch() -> None:
    helper = _load_helper()
    payload = _candidate_payload()
    payload["evidence"]["pull_request"]["facts"]["head_sha"] = "not-a-sha"

    result = helper.evaluate_candidate(payload)

    assert result["outcome"] == "evidence_unavailable"
    assert {item["field"] for item in result["unavailable_evidence"]} == {
        "pull_request.head_sha"
    }
    assert result["failed_conditions"] == []
    assert result["facts"]["evidence_currency"]["review"]["status"] == "unavailable"


def test_candidate_requires_an_exact_linked_issue_reference() -> None:
    helper = _load_helper()
    payload = _candidate_payload()
    payload["evidence"]["pull_request"]["facts"]["body"] = "Related maintenance only."

    result = helper.evaluate_candidate(payload)

    assert result["outcome"] == "rule_mismatch"
    assert result["failed_conditions"] == [
        {
            "field": "pull_request.linked_issue_reference",
            "expected": True,
            "observed": False,
        }
    ]


def test_skill_routes_both_helpers_without_replacing_raw_connector_calls() -> None:
    skill = (SKILL_ROOT / "SKILL.md").read_text()
    reference = (SKILL_ROOT / "references/github-checks.md").read_text()

    assert "references/github-checks.md" in skill
    for expected in (
        "configured GitHub App connector",
        "github_checks.py intake",
        "github_checks.py candidate",
        "evidence_unavailable",
        "Raw connector operations remain",
        "available for investigations",
        "do not define factory policy",
    ):
        assert expected in reference
