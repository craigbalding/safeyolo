"""Retained contract-reader and role instructions used by Coord tooling.

Native Factory entry and installed staging tests live in
tests/proxy_contracts/test_native_factory_cli.py.
"""

import json
from pathlib import Path

import pytest

from safeyolo.factory_contract import FactoryContractError, approve_snapshot, load_approved_snapshot, load_factory_file

BACKLOG_COORDINATOR_CONTRACT = Path(__file__).parents[2] / "docs/factories/backlog-coordinator.md"
BACKLOG_REVIEWER_CONTRACT = Path(__file__).parents[2] / "docs/agent-roles/independent-reviewer.md"
BACKLOG_OWNER_CONTRACT = Path(__file__).parents[2] / "docs/agent-roles/issue-owner.md"


def test_backlog_coordinator_status_contract_is_low_noise():
    contract = " ".join(BACKLOG_COORDINATOR_CONTRACT.read_text().split())

    assert "Send an ordinary answer with no agent attention." in contract
    assert "Do not expect a new `ACCEPTED` after a Lens disposition." in contract
    assert "report that the updated candidate is pending" in contract


def test_backlog_coordinator_contract_owns_proactive_flow_and_backfill():
    contract = " ".join(BACKLOG_COORDINATOR_CONTRACT.read_text().split())

    assert "Relay owns productive and resilient factory flow." in contract
    assert "Do not require the operator to name each work item." in contract
    assert "When Forge has useful capacity" in contract
    assert "When Lens has useful capacity" in contract
    assert "Treat an actionable `BLOCKED` or `FAILED` response as coordinator work." in contract
    assert "the factory does not require a brief" in contract
    assert "product acceptance graph" in contract
    assert "Assign one bounded path, not the whole graph" in contract


def test_backlog_reviewer_contract_binds_install_trust_and_complexity_checks():
    contract = " ".join(BACKLOG_REVIEWER_CONTRACT.read_text().split())

    assert "trusted base revision's tracked dependency inventory" in contract
    assert "operator-bound acceptance graph" in contract
    assert "separate validation-tool inventory" in contract
    assert "outside both trusted-base inventories" in contract
    assert "it does not grant itself standing approval" in contract
    assert "Run deterministic post-change quality analysis" in contract
    # Repository-specific invocations live in repository guidance, not the
    # shared multi-repository role contract.
    developer_guide = BACKLOG_REVIEWER_CONTRACT.parents[1] / "DEVELOPERS.md"
    assert "--select C901,PLR0911,PLR0912,PLR0913,PLR0915" in developer_guide.read_text()
    assert "A tool finding is evidence, not an automatic veto" in contract
    assert "product acceptance graph" in contract
    assert "rather than from a candidate as self-authorization" in contract


def test_backlog_alert_intake_reuses_issue_flow_and_distinguishes_lookup_failure():
    contract = " ".join(BACKLOG_COORDINATOR_CONTRACT.read_text().split())

    assert "open issues, pull requests, and code-scanning alerts" in contract
    assert "do not create one task per alert by default" in contract
    assert "Use that issue as the ordinary task target." in contract
    assert "assign Lens a bounded triage task" in contract
    assert "existing coding rule or a focused prevention improvement" in contract
    assert "A failed or unauthorized alert lookup is not an empty inventory" in contract
    assert "Do not require the whole alert inventory to be cleared" in contract


def test_backlog_intake_preserves_requirements_and_starting_revision():
    contract = " ".join(BACKLOG_COORDINATOR_CONTRACT.read_text().split())

    assert "issue title and the affected acceptance text verbatim" in contract
    assert "pull-request title and body" in contract
    assert "other issue text and comments verbatim only when material" in contract
    assert "full issue URL and record when Relay read it in UTC" in contract
    assert "Keep the captured source text separate from Relay's instructions and assessment." in contract
    assert "repository, branch and exact starting commit" in contract
    assert "retain that text in Coord messages" in contract
    assert "their exact room and message sequences" in contract
    assert "do not silently truncate requirements" in contract


@pytest.mark.parametrize("path", [BACKLOG_OWNER_CONTRACT, BACKLOG_REVIEWER_CONTRACT])
def test_worker_contract_establishes_checkout_before_repo_map(path):
    contract = " ".join(path.read_text().split()).lower()

    assert "establish the task checkout before using `repo-map`" in contract
    assert "behaviour, concepts and symbols, not issue/pr numbers or factory wording" in contract
    assert "after a revision change, refresh it before relying on its locations" in contract


def test_review_handoff_reuses_original_coord_requirements_not_owner_copy():
    owner = " ".join(BACKLOG_OWNER_CONTRACT.read_text().split())
    reviewer = " ".join(BACKLOG_REVIEWER_CONTRACT.read_text().split())

    assert "Relay's original Coord room and canonical message sequence" in owner
    assert "Keep the new candidate head distinct from Relay's starting commit." in owner
    assert "do not reset them to the original starting commit" in owner
    assert "Check the canonical Relay sender and assigned target." in reviewer
    assert "A copy quoted by Forge is not a substitute for Relay's retained message." in reviewer
    assert "Do not routinely reread the linked issue on first involvement." in reviewer
    assert "Obtain missing source text when the capture is unavailable" in reviewer


def test_acceptance_checklist_has_evidence_owner_and_publication_recovery():
    coordinator = " ".join(BACKLOG_COORDINATOR_CONTRACT.read_text().split())
    owner = " ".join(BACKLOG_OWNER_CONTRACT.read_text().split())
    reviewer = " ".join(BACKLOG_REVIEWER_CONTRACT.read_text().split())

    assert "Lens owns acceptance evidence and the issue's acceptance checklist." in coordinator
    assert "own that recovery using Lens's supplied evidence" in coordinator
    assert "do not mark them passed on the strength of Forge's implementation claims" in owner
    assert "tick an item only when independent acceptance establishes that it passed" in reviewer
    assert "Leave failed or untested items unchecked and explain why." in reviewer
    assert "correct any checkmark whose evidence no longer holds" in reviewer
    assert "Do not overwrite the current issue with Relay's historical capture." in reviewer
    assert "If publication fails, include the unposted item outcomes and evidence" in reviewer
    assert "The issue acceptance record above is required." in reviewer
    assert "GitHub findings are an optional additional record" not in reviewer


def test_coordinator_owns_exact_candidate_merge_without_closing_partial_issue():
    contract = " ".join(BACKLOG_COORDINATOR_CONTRACT.read_text().split())
    reviewer = " ".join(BACKLOG_REVIEWER_CONTRACT.read_text().split())

    assert "Relay owns the merge after that exact-candidate acceptance." in contract
    assert "verify that the pull request head is still the commit accepted by Lens" in contract
    assert "If the head changed, do not merge it" in contract
    assert "ensure the merge will not automatically close the incomplete issue" in contract
    assert "Close the issue only when independent evidence proves all" in contract
    assert "The pull request can be a bounded increment that proves only part of the issue." in reviewer
    assert "does not claim that every acceptance criterion in the issue is complete" in reviewer


def test_reviewer_repairs_execution_failures_and_escalates_without_false_blocked():
    contract = " ".join(BACKLOG_REVIEWER_CONTRACT.read_text().split())

    assert "Fix unexpected failures that prevent tests or validation tools from running, then rerun them." in contract
    assert "always raise it directly to the operator with what failed, what you tried, and what is needed" in contract
    assert "Do not silently skip it or call it a limitation." in contract
    assert "awaiting an operator response is not `BLOCKED`" in contract
    assert "A test that runs and detects a product defect is different" in contract
    assert "through the assigned task or review response" in contract


@pytest.mark.parametrize("role", ["issue-owner", "independent-reviewer"])
def test_worker_layout_separates_acceptance_material_without_banning_project_tools(role):
    path = Path(__file__).parents[2] / "docs/agent-roles" / f"{role}.md"
    contract = " ".join(path.read_text().split())

    assert "Keep reusable acceptance environments" in contract
    assert "retained evidence outside product checkouts" in contract
    assert "otherwise use a directory in your persistent home outside the checkout" in contract
    assert "`.venv`, `.pytest_cache`, and `.ruff_cache`" in contract
    assert "Tests may still create fixtures at specific paths" in contract
    assert "Evidence requested as a repository deliverable belongs in the repository." in contract


def _factory_file(
    tmp_path: Path,
    *,
    name: str = "backlog",
    owner_harness: str | None = None,
    owner_args: list[str] | None = None,
    extra: str = "",
) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "coordinator.md").write_text("# Coordinator\n\nDelegate exact tasks.\n")
    (tmp_path / "owner.md").write_text("# Owner\n\nOwn the issue.\n")
    (tmp_path / "reviewer.md").write_text("# Reviewer\n\nReview independently.\n")
    path = tmp_path / "backlog.toml"
    path.write_text(
        'schema = "safeyolo.factory/v1"\n'
        f'name = "{name}"\n'
        'room = "backlog"\n\n'
        "[operator_input]\n"
        'to = "coordinator"\n'
        'types = ["ACTIVATE", "PAUSE", "RESUME", "PRIORITY", "NEXT", "DIRECTION"]\n\n'
        '[roles.coordinator]\nagent = "relay"\ncontract = "coordinator.md"\n\n'
        '[roles.owner]\nagent = "forge"\ncontract = "owner.md"\n'
        + (f'harness = "{owner_harness}"\n' if owner_harness is not None else "")
        + (f"args = {json.dumps(owner_args)}\n" if owner_args is not None else "")
        + "\n"
        '[roles.reviewer]\nagent = "lens"\ncontract = "reviewer.md"\n\n'
        '[[handoffs]]\nrequest = "TASK"\nfrom = "coordinator"\nto = "owner"\n'
        'responses = ["DONE", "BLOCKED", "FAILED"]\n'
        'response_to = ["coordinator"]\n\n'
        '[[handoffs]]\nrequest = "TASK"\nfrom = "coordinator"\nto = "reviewer"\n'
        'responses = ["DONE", "BLOCKED", "FAILED"]\n'
        'response_to = ["coordinator"]\n\n'
        '[[handoffs]]\nrequest = "REVIEW_READY"\nfrom = "owner"\nto = "reviewer"\n'
        'responses = ["READY", "CHANGES_REQUIRED", "BLOCKED"]\n'
        'response_to = ["owner", "coordinator"]\n' + extra
    )
    return path


def test_factory_role_selects_a_harness_and_defaults_to_codex(tmp_path):
    default = load_factory_file(_factory_file(tmp_path / "default"))
    selected = load_factory_file(_factory_file(tmp_path / "selected", owner_harness="pi"))

    assert {role.name: role.harness for role in default.roles} == {
        "coordinator": "codex",
        "owner": "codex",
        "reviewer": "codex",
    }
    assert {role.name: role.harness for role in selected.roles}["owner"] == "pi"
    assert selected.snapshot_payload()["roles"]["owner"]["harness"] == "pi"


def test_factory_role_can_snapshot_explicit_harness_arguments(tmp_path):
    selected = load_factory_file(
        _factory_file(
            tmp_path,
            owner_harness="pi",
            owner_args=["--provider", "openai-codex", "--thinking", "xhigh"],
        )
    )

    owner = next(role for role in selected.roles if role.name == "owner")
    assert owner.args == ("--provider", "openai-codex", "--thinking", "xhigh")
    assert selected.snapshot_payload()["roles"]["owner"]["args"] == [
        "--provider",
        "openai-codex",
        "--thinking",
        "xhigh",
    ]


def _extension_toml(harness="codex"):
    args = (
        ["--model", "stronger", "--thinking", "medium"]
        if harness == "pi"
        else [
            "--model",
            "stronger",
            "-c",
            "model_reasoning_effort=medium",
        ]
    )
    return (
        '\n[[updates]]\ntype = "CONTEXT"\nfrom = "coordinator"\nto = "owner"\nfields = ["target"]\n'
        '\n[roles.owner.repair]\nrequest = "REPAIR"\nfrom = "coordinator"\n'
        f'args = {json.dumps(args)}\nafter_rounds = 5\nmax_rounds = 3\nrelease_on = "REVIEW_READY"\n'
    )


@pytest.mark.parametrize(
    "old,new",
    [
        ('type = "CONTEXT"', 'type = "TASK"'),
        ('fields = ["target"]', 'fields = ["target", "target"]'),
        ('fields = ["target"]', 'fields = ["not a field"]'),
        ("max_rounds = 3", "max_rounds = true"),
        ("after_rounds = 5", "after_rounds = 0"),
        ('release_on = "REVIEW_READY"', 'release_on = "UNKNOWN"'),
        ('request = "REPAIR"', 'request = "CONTEXT"'),
        ('from = "coordinator"', 'from = ["coordinator"]'),
    ],
)
def test_invalid_protocol_extensions_fail_at_source(tmp_path, old, new):
    source = _factory_file(tmp_path, extra=_extension_toml().replace(old, new))
    with pytest.raises(FactoryContractError):
        load_factory_file(source)


def test_factory_role_rejects_non_string_harness_arguments(tmp_path):
    path = _factory_file(tmp_path)
    path.write_text(
        path.read_text().replace(
            '[roles.owner]\nagent = "forge"\ncontract = "owner.md"\n',
            '[roles.owner]\nagent = "forge"\ncontract = "owner.md"\nargs = [1]\n',
        )
    )

    with pytest.raises(FactoryContractError, match="args must be an array"):
        load_factory_file(path)


def test_factory_rejects_an_unknown_role_harness(tmp_path):
    with pytest.raises(FactoryContractError, match="harness must be one of codex, pi"):
        load_factory_file(_factory_file(tmp_path, owner_harness="unknown"))


def test_factory_snapshot_storage_rejects_a_symlink_escape(tmp_path, tmp_config_dir):

    outside = tmp_path / "outside"
    outside.mkdir()
    factories = tmp_config_dir / "factories"
    factories.mkdir()
    (factories / "backlog").symlink_to(outside, target_is_directory=True)

    with pytest.raises(FactoryContractError, match="factory path escapes"):
        approve_snapshot(load_factory_file(_factory_file(tmp_path)))

    assert list(outside.iterdir()) == []


@pytest.mark.parametrize(
    "mutation, message",
    [
        (lambda raw: raw.replace('name = "backlog"', 'name = "backlog"\nunknown = true'), "unknown"),
        (lambda raw: raw.replace('agent = "lens"', 'agent = "forge"'), "more than one role"),
        (lambda raw: raw.replace('request = "REVIEW_READY"', 'request = "review-ready"'), "uppercase"),
        (lambda raw: raw.replace('to = "reviewer"', 'to = "missing"'), "unknown role"),
        (
            lambda raw: raw.replace(
                'response_to = ["coordinator"]',
                'response_to = ["reviewer"]',
                1,
            ),
            "must include the source role",
        ),
        (
            lambda raw: raw.replace(
                'response_to = ["coordinator"]',
                'response_to = ["coordinator", "coordinator"]',
                1,
            ),
            "contains a duplicate",
        ),
    ],
)
def test_factory_contract_rejects_unknown_or_ambiguous_authority(tmp_path, mutation, message):
    path = _factory_file(tmp_path)
    path.write_text(mutation(path.read_text()))

    with pytest.raises(FactoryContractError, match=message):
        load_factory_file(path)


def test_approved_snapshot_rejects_tampering(tmp_path, tmp_config_dir):

    identifier, snapshot_path = approve_snapshot(load_factory_file(_factory_file(tmp_path)))
    payload = json.loads(snapshot_path.read_text())
    payload["room"] = "other"
    snapshot_path.write_text(json.dumps(payload))

    with pytest.raises(FactoryContractError, match="content hash"):
        load_approved_snapshot("backlog")
    assert identifier in snapshot_path.name


def test_factory_rejects_missing_operator_input_and_unreachable_roles(tmp_path):
    path = _factory_file(tmp_path)
    source = path.read_text()
    start = source.index("[operator_input]")
    end = source.index("[roles.coordinator]")
    path.write_text(source[:start] + source[end:])
    with pytest.raises(FactoryContractError, match="must declare operator_input"):
        load_factory_file(path)

    path = _factory_file(tmp_path)
    path.write_text(path.read_text().replace('to = "coordinator"', 'to = "owner"', 1))
    with pytest.raises(FactoryContractError, match="unreachable from operator_input.to: coordinator"):
        load_factory_file(path)


def test_factory_binds_exact_utf8_contract_bytes(tmp_path):
    path = _factory_file(tmp_path)
    encoded = b"# Owner\r\n\r\nExact bytes.\r\n"
    (tmp_path / "owner.md").write_bytes(encoded)

    contract = load_factory_file(path)
    owner = next(role for role in contract.roles if role.name == "owner")

    assert owner.contract_bytes == len(encoded)
    assert owner.contract_sha256 == __import__("hashlib").sha256(encoded).hexdigest()
    assert owner.contract_text.encode() == encoded
