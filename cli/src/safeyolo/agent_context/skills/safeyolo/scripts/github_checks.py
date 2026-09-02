#!/usr/bin/env python3
"""Evaluate normalized evidence from the optional GitHub composite helpers."""

from __future__ import annotations

import json
import re
import sys
from typing import Any

_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]+$")
_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_UNAVAILABLE_REASONS = {
    "ambiguous",
    "malformed",
    "missing",
    "unauthorized",
    "unavailable",
}


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _invalid(check: str, errors: list[dict[str, str]]) -> dict[str, Any]:
    details = "; ".join(f"{item['field']}: {item['reason']}" for item in errors)
    return {
        "check": check,
        "passed": False,
        "outcome": "invalid_request",
        "diagnostic": f"GitHub {check} request is invalid: {details}",
        "facts": {},
        "failed_conditions": [],
        "unavailable_evidence": [],
        "request_errors": errors,
    }


def _result(
    check: str,
    facts: dict[str, Any],
    mismatches: list[dict[str, Any]],
    unavailable: list[dict[str, str]],
) -> dict[str, Any]:
    if unavailable:
        outcome = "evidence_unavailable"
        diagnostic = (
            f"GitHub {check} check could not prove a result: "
            f"{len(unavailable)} required evidence item(s) are unavailable."
        )
    elif mismatches:
        outcome = "rule_mismatch"
        diagnostic = (
            f"GitHub {check} check failed: "
            f"{len(mismatches)} condition(s) did not match."
        )
    else:
        outcome = "pass"
        diagnostic = f"GitHub {check} check passed."
    return {
        "check": check,
        "passed": outcome == "pass",
        "outcome": outcome,
        "diagnostic": diagnostic,
        "facts": facts,
        "failed_conditions": mismatches,
        "unavailable_evidence": unavailable,
        "request_errors": [],
    }


def _request(payload: Any, check: str) -> tuple[dict[str, Any], list[dict[str, str]]]:
    if not isinstance(payload, dict):
        return {}, [{"field": "request", "reason": "payload must be an object"}]
    request = payload.get("request")
    if not isinstance(request, dict):
        return {}, [{"field": "request", "reason": "must be an object"}]
    errors: list[dict[str, str]] = []
    repository = request.get("repository")
    if not isinstance(repository, str) or not _REPOSITORY_RE.fullmatch(repository):
        errors.append(
            {
                "field": "request.repository",
                "reason": "must be an owner/name repository on github.com",
            }
        )
    number_field = "issue" if check == "intake" else "pull_request"
    number = request.get(number_field)
    if not _is_int(number) or number < 1:
        errors.append(
            {"field": f"request.{number_field}", "reason": "must be a positive integer"}
        )
    return request, errors


def _evidence_facts(
    payload: dict[str, Any],
    name: str,
    unavailable: list[dict[str, str]],
) -> dict[str, Any]:
    evidence = payload.get("evidence")
    block = evidence.get(name) if isinstance(evidence, dict) else None
    if not isinstance(block, dict):
        unavailable.append({"field": name, "reason": "missing"})
        return {}
    status = block.get("status")
    if status != "ok":
        reason = block.get("reason")
        if not isinstance(reason, str) or reason not in _UNAVAILABLE_REASONS:
            reason = "unavailable"
        unavailable.append({"field": name, "reason": reason})
        return {}
    facts = block.get("facts")
    if not isinstance(facts, dict):
        unavailable.append({"field": name, "reason": "malformed"})
        return {}
    return facts


def _require_facts(
    source: dict[str, Any],
    fields: tuple[str, ...],
    prefix: str,
    unavailable: list[dict[str, str]],
) -> dict[str, Any]:
    observed: dict[str, Any] = {}
    for field in fields:
        value = source.get(field)
        if value is None or isinstance(value, str) and not value:
            unavailable.append({"field": f"{prefix}.{field}", "reason": "missing"})
            continue
        observed[field] = value
    return observed


def _mismatch(
    mismatches: list[dict[str, Any]],
    field: str,
    expected: Any,
    observed: Any,
) -> None:
    if observed is None:
        return
    if observed != expected:
        mismatches.append({"field": field, "expected": expected, "observed": observed})


def _reject_malformed_fact(
    facts: dict[str, Any],
    field: str,
    valid: bool,
    prefix: str,
    unavailable: list[dict[str, str]],
) -> None:
    if field in facts and not valid:
        unavailable.append({"field": f"{prefix}.{field}", "reason": "malformed"})
        facts.pop(field)


def _is_github_resource_url(
    value: Any,
    repository: Any,
    resource: str,
    number: Any,
) -> bool:
    if (
        not isinstance(value, str)
        or not isinstance(repository, str)
        or not _REPOSITORY_RE.fullmatch(repository)
        or not _is_int(number)
        or number < 1
    ):
        return False
    expected = f"https://github.com/{repository}/{resource}/{number}"
    return value.casefold() == expected.casefold()


def evaluate_intake(payload: Any) -> dict[str, Any]:
    """Compare explicit intake expectations with normalized connector evidence."""
    request, errors = _request(payload, "intake")
    expectations = request.get("expectations") if request else None
    required_expectations = (
        "owner_login",
        "owner_type",
        "visibility",
        "issue_type",
        "issue_state",
        "issue_author_login",
    )
    if not isinstance(expectations, dict):
        errors.append({"field": "request.expectations", "reason": "must be an object"})
        expectations = {}
    for field in required_expectations:
        value = expectations.get(field)
        if not isinstance(value, str) or not value:
            errors.append(
                {"field": f"request.expectations.{field}", "reason": "must be a string"}
            )
    issue_type = expectations.get("issue_type")
    if isinstance(issue_type, str) and issue_type not in {"issue", "pull_request"}:
        errors.append(
            {
                "field": "request.expectations.issue_type",
                "reason": "must be issue or pull_request",
            }
        )
    if "archived" in expectations and not isinstance(expectations["archived"], bool):
        errors.append(
            {"field": "request.expectations.archived", "reason": "must be a boolean"}
        )
    if errors:
        return _invalid("intake", errors)

    unavailable: list[dict[str, str]] = []
    mismatches: list[dict[str, Any]] = []
    repository_source = _evidence_facts(payload, "repository", unavailable)
    issue_source = _evidence_facts(payload, "issue", unavailable)
    repository = _require_facts(
        repository_source,
        ("full_name", "owner_login", "owner_type", "visibility", "archived"),
        "repository",
        unavailable,
    )
    issue = _require_facts(
        issue_source,
        ("repository", "number", "type", "state", "author_login"),
        "issue",
        unavailable,
    )
    for optional in ("default_branch",):
        if optional in repository_source:
            repository[optional] = repository_source[optional]
    for optional in ("url",):
        if optional in issue_source:
            issue[optional] = issue_source[optional]
    _reject_malformed_fact(
        repository,
        "full_name",
        isinstance(repository.get("full_name"), str)
        and bool(_REPOSITORY_RE.fullmatch(repository["full_name"])),
        "repository",
        unavailable,
    )
    for field in ("owner_login", "owner_type", "visibility"):
        _reject_malformed_fact(
            repository,
            field,
            isinstance(repository.get(field), str),
            "repository",
            unavailable,
        )
    _reject_malformed_fact(
        repository,
        "archived",
        isinstance(repository.get("archived"), bool),
        "repository",
        unavailable,
    )
    _reject_malformed_fact(
        repository,
        "default_branch",
        isinstance(repository.get("default_branch"), str)
        and bool(repository["default_branch"]),
        "repository",
        unavailable,
    )
    _reject_malformed_fact(
        issue,
        "repository",
        isinstance(issue.get("repository"), str)
        and bool(_REPOSITORY_RE.fullmatch(issue["repository"])),
        "issue",
        unavailable,
    )
    _reject_malformed_fact(
        issue,
        "number",
        _is_int(issue.get("number")) and issue["number"] > 0,
        "issue",
        unavailable,
    )
    _reject_malformed_fact(
        issue,
        "type",
        isinstance(issue.get("type"), str)
        and issue["type"] in {"issue", "pull_request"},
        "issue",
        unavailable,
    )
    for field in ("state", "author_login"):
        _reject_malformed_fact(
            issue,
            field,
            isinstance(issue.get(field), str),
            "issue",
            unavailable,
        )
    _reject_malformed_fact(
        issue,
        "url",
        _is_github_resource_url(
            issue.get("url"),
            issue.get("repository"),
            "issues",
            issue.get("number"),
        ),
        "issue",
        unavailable,
    )
    facts = {"repository": repository, "issue": issue}

    _mismatch(mismatches, "repository.full_name", request["repository"], repository.get("full_name"))
    _mismatch(
        mismatches,
        "repository.owner_login",
        expectations["owner_login"],
        repository.get("owner_login"),
    )
    _mismatch(
        mismatches,
        "repository.owner_type",
        expectations["owner_type"],
        repository.get("owner_type"),
    )
    _mismatch(
        mismatches,
        "repository.visibility",
        expectations["visibility"],
        repository.get("visibility"),
    )
    if "archived" in expectations:
        _mismatch(
            mismatches,
            "repository.archived",
            expectations["archived"],
            repository.get("archived"),
        )
    _mismatch(mismatches, "issue.repository", request["repository"], issue.get("repository"))
    _mismatch(mismatches, "issue.number", request["issue"], issue.get("number"))
    _mismatch(mismatches, "issue.type", expectations["issue_type"], issue.get("type"))
    _mismatch(mismatches, "issue.state", expectations["issue_state"], issue.get("state"))
    _mismatch(
        mismatches,
        "issue.author_login",
        expectations["issue_author_login"],
        issue.get("author_login"),
    )
    return _result("intake", facts, mismatches, unavailable)


def _links_issue(body: str, repository: str, issue: int) -> bool:
    escaped_repository = re.escape(repository)
    reference_end = r"(?![\w/-])"
    references = (
        rf"(?<![\w./-])https://github\.com/{escaped_repository}/issues/{issue}"
        rf"{reference_end}",
        rf"(?<![\w./-]){escaped_repository}#{issue}{reference_end}",
        rf"(?<![\w/#-])#{issue}{reference_end}",
    )
    return any(re.search(pattern, body, flags=re.IGNORECASE) for pattern in references)


def evaluate_candidate(payload: Any) -> dict[str, Any]:
    """Resolve exact candidate identity and compare supplied revision evidence."""
    request, errors = _request(payload, "candidate")
    linked_issue = request.get("linked_issue") if request else None
    if not _is_int(linked_issue) or linked_issue < 1:
        errors.append(
            {"field": "request.linked_issue", "reason": "must be a positive integer"}
        )
    for field in ("expected_head_sha", "review_head_sha", "acceptance_head_sha"):
        value = request.get(field) if request else None
        if field == "expected_head_sha" or value is not None:
            if not isinstance(value, str) or not _SHA_RE.fullmatch(value):
                errors.append(
                    {"field": f"request.{field}", "reason": "must be a full commit SHA"}
                )
    if errors:
        return _invalid("candidate", errors)

    unavailable: list[dict[str, str]] = []
    mismatches: list[dict[str, Any]] = []
    pull_request_source = _evidence_facts(payload, "pull_request", unavailable)
    tree_source = _evidence_facts(payload, "tree", unavailable)
    issue_source = _evidence_facts(payload, "linked_issue", unavailable)
    pull_request = _require_facts(
        pull_request_source,
        (
            "repository",
            "number",
            "base_ref",
            "base_sha",
            "head_ref",
            "head_sha",
        ),
        "pull_request",
        unavailable,
    )
    body = pull_request_source.get("body")
    if not isinstance(body, str):
        unavailable.append({"field": "pull_request.body", "reason": "missing"})
    tree = _require_facts(
        tree_source,
        ("commit_sha", "tree_sha"),
        "tree",
        unavailable,
    )
    issue = _require_facts(
        issue_source,
        ("repository", "number", "type", "state", "author_login"),
        "linked_issue",
        unavailable,
    )
    for optional in ("state", "draft", "url"):
        if optional in pull_request_source:
            pull_request[optional] = pull_request_source[optional]
    if "url" in issue_source:
        issue["url"] = issue_source["url"]

    _reject_malformed_fact(
        pull_request,
        "repository",
        isinstance(pull_request.get("repository"), str)
        and bool(_REPOSITORY_RE.fullmatch(pull_request["repository"])),
        "pull_request",
        unavailable,
    )
    _reject_malformed_fact(
        pull_request,
        "number",
        _is_int(pull_request.get("number")) and pull_request["number"] > 0,
        "pull_request",
        unavailable,
    )
    for field in ("base_ref", "head_ref"):
        _reject_malformed_fact(
            pull_request,
            field,
            isinstance(pull_request.get(field), str),
            "pull_request",
            unavailable,
        )
    for field in ("base_sha", "head_sha"):
        _reject_malformed_fact(
            pull_request,
            field,
            isinstance(pull_request.get(field), str)
            and bool(_SHA_RE.fullmatch(pull_request[field])),
            "pull_request",
            unavailable,
        )
    _reject_malformed_fact(
        pull_request,
        "state",
        isinstance(pull_request.get("state"), str)
        and pull_request["state"] in {"open", "closed"},
        "pull_request",
        unavailable,
    )
    _reject_malformed_fact(
        pull_request,
        "draft",
        isinstance(pull_request.get("draft"), bool),
        "pull_request",
        unavailable,
    )
    _reject_malformed_fact(
        pull_request,
        "url",
        _is_github_resource_url(
            pull_request.get("url"),
            pull_request.get("repository"),
            "pull",
            pull_request.get("number"),
        ),
        "pull_request",
        unavailable,
    )
    for field in ("commit_sha", "tree_sha"):
        _reject_malformed_fact(
            tree,
            field,
            isinstance(tree.get(field), str) and bool(_SHA_RE.fullmatch(tree[field])),
            "tree",
            unavailable,
        )
    _reject_malformed_fact(
        issue,
        "repository",
        isinstance(issue.get("repository"), str)
        and bool(_REPOSITORY_RE.fullmatch(issue["repository"])),
        "linked_issue",
        unavailable,
    )
    _reject_malformed_fact(
        issue,
        "number",
        _is_int(issue.get("number")) and issue["number"] > 0,
        "linked_issue",
        unavailable,
    )
    _reject_malformed_fact(
        issue,
        "type",
        isinstance(issue.get("type"), str)
        and issue["type"] in {"issue", "pull_request"},
        "linked_issue",
        unavailable,
    )
    for field in ("state", "author_login"):
        _reject_malformed_fact(
            issue,
            field,
            isinstance(issue.get(field), str),
            "linked_issue",
            unavailable,
        )
    _reject_malformed_fact(
        issue,
        "url",
        _is_github_resource_url(
            issue.get("url"),
            issue.get("repository"),
            "issues",
            issue.get("number"),
        ),
        "linked_issue",
        unavailable,
    )

    observed_head = pull_request.get("head_sha")
    if tree and observed_head and tree.get("commit_sha") != observed_head:
        unavailable.append({"field": "tree", "reason": "ambiguous"})
    links_issue = (
        _links_issue(body, request["repository"], request["linked_issue"])
        if isinstance(body, str)
        else False
    )
    evidence_currency = {
        "review": _currency(request.get("review_head_sha"), observed_head),
        "acceptance": _currency(request.get("acceptance_head_sha"), observed_head),
    }
    facts = {
        "pull_request": pull_request,
        "tree": tree,
        "linked_issue": issue,
        "linked_issue_reference": links_issue,
        "evidence_currency": evidence_currency,
    }

    _mismatch(
        mismatches,
        "pull_request.repository",
        request["repository"],
        pull_request.get("repository"),
    )
    _mismatch(
        mismatches,
        "pull_request.number",
        request["pull_request"],
        pull_request.get("number"),
    )
    _mismatch(
        mismatches,
        "pull_request.head_sha",
        request["expected_head_sha"],
        observed_head,
    )
    _mismatch(mismatches, "linked_issue.repository", request["repository"], issue.get("repository"))
    _mismatch(mismatches, "linked_issue.number", request["linked_issue"], issue.get("number"))
    _mismatch(mismatches, "linked_issue.type", "issue", issue.get("type"))
    if isinstance(body, str):
        _mismatch(mismatches, "pull_request.linked_issue_reference", True, links_issue)
    for kind, request_field in (
        ("review", "review_head_sha"),
        ("acceptance", "acceptance_head_sha"),
    ):
        supplied = request.get(request_field)
        if supplied is not None and evidence_currency[kind]["status"] == "stale":
            mismatches.append(
                {
                    "field": f"{kind}.head_sha",
                    "expected": observed_head,
                    "observed": supplied,
                }
            )
    return _result("candidate", facts, mismatches, unavailable)


def _currency(supplied: Any, current: Any) -> dict[str, Any]:
    if supplied is None:
        return {"status": "not_supplied", "head_sha": None}
    if not isinstance(current, str) or not _SHA_RE.fullmatch(current):
        return {"status": "unavailable", "head_sha": supplied}
    return {
        "status": "current" if supplied == current else "stale",
        "head_sha": supplied,
    }


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args not in (["intake"], ["candidate"]):
        print("usage: github_checks.py {intake|candidate}", file=sys.stderr)
        return 2
    line = sys.stdin.readline()
    try:
        payload = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        result = _invalid(args[0], [{"field": "request", "reason": "input is not valid JSON"}])
    else:
        result = evaluate_intake(payload) if args[0] == "intake" else evaluate_candidate(payload)
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
