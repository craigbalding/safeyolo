# GitHub composite checks

Use these optional helpers when repeated GitHub facts must be checked through
the configured GitHub App connector. The helpers do not define factory policy.
The caller supplies every expectation from the current authoritative context.

Do not use local `gh`, alternate credentials, direct unauthenticated HTTP, or a
Markdown brief parser for these checks. Use the official `github.com` service
through the existing GitHub App connector. Raw connector operations remain
available for investigations that do not fit either helper.

## Common result

Each helper returns one JSON result with these fields:

- `passed` is the pass/fail decision.
- `outcome` is `pass`, `rule_mismatch`, `evidence_unavailable`, or
  `invalid_request`.
- `facts` contains only the normalized facts used for the decision.
- `failed_conditions` contains every proved expectation mismatch.
- `unavailable_evidence` identifies required evidence that could not be
  proved. Its reason is `missing`, `unauthorized`, `malformed`, `ambiguous`, or
  `unavailable`.
- `request_errors` identifies malformed caller input.

`evidence_unavailable` takes precedence over `rule_mismatch`. The result can
still list proved mismatches so the caller does not lose useful evidence.
Never copy connector response bodies, credentials, brief text, or unrelated
repository facts into the result.

The deterministic evaluator is
[`scripts/github_checks.py`](../scripts/github_checks.py). It reads one JSON
object from standard input and supports the `intake` and `candidate`
subcommands. Use the skill directory reported by the harness to locate the
script. Do not assume that the `safeyolo` Python package is installed in the
sandbox. Keep the evaluator attached to the composed harness call while the
call writes the one input line and reads the one result.

Wrap successful evidence as `{"status":"ok","facts":{...}}`. If a connector
read fails, use `{"status":"unavailable","reason":"..."}` with one of the
bounded reasons above. Classify the connector failure without copying its raw
response or error body into the evaluator input or result.

## Intake helper

One helper invocation performs this bounded sequence:

1. Validate the explicit repository, issue number, and expectations.
2. In one composed harness call, use the GitHub App connector to read the
   repository and issue from `github.com`. The two reads may run concurrently.
3. Normalize only these repository facts: full name, owner login, owner type,
   visibility, archived state, and default branch.
4. Normalize only these issue facts: repository, number, issue or pull-request
   type, state, author login, and canonical URL.
5. Pass the normalized request and evidence to `github_checks.py intake` and
   return its single result.

The request shape is:

```json
{
  "repository": "owner/project",
  "issue": 123,
  "expectations": {
    "owner_login": "owner",
    "owner_type": "User",
    "visibility": "public",
    "issue_type": "issue",
    "issue_state": "open",
    "issue_author_login": "owner",
    "archived": false
  }
}
```

`archived` is optional. The other expectations are required. Different callers
can supply different owners, repository names, visibility, states, and authors.

Pass this normalized evidence beside that request:

```json
{
  "repository": {
    "status": "ok",
    "facts": {
      "full_name": "owner/project",
      "owner_login": "owner",
      "owner_type": "User",
      "visibility": "public",
      "archived": false,
      "default_branch": "main"
    }
  },
  "issue": {
    "status": "ok",
    "facts": {
      "repository": "owner/project",
      "number": 123,
      "type": "issue",
      "state": "open",
      "author_login": "owner",
      "url": "https://github.com/owner/project/issues/123"
    }
  }
}
```

## Exact candidate helper

One helper invocation performs this bounded sequence:

1. Validate the explicit repository, pull request, linked issue, and full
   expected head commit SHA.
2. In one composed harness call, use the GitHub App connector to read the pull
   request from `github.com`.
3. Read the current head commit through that connector to obtain its Git tree
   SHA. Read the explicit linked issue through the connector. These reads may
   run concurrently after the pull-request read supplies the current head.
4. Normalize the current base ref and SHA, head ref and SHA, tree SHA, linked
   issue identity, and the minimal pull-request body needed to prove the issue
   reference.
5. Pass the normalized request and evidence to `github_checks.py candidate`
   and return its single result.

The request shape is:

```json
{
  "repository": "owner/project",
  "pull_request": 456,
  "linked_issue": 123,
  "expected_head_sha": "0123456789abcdef0123456789abcdef01234567",
  "review_head_sha": "0123456789abcdef0123456789abcdef01234567",
  "acceptance_head_sha": null
}
```

`review_head_sha` and `acceptance_head_sha` are optional. For each supplied
value, the result reports `current` when it equals the current pull-request
head and `stale` when it does not. A moved expected head and stale evidence are
proved rule mismatches. Missing or inconsistent head or tree evidence is
unavailable evidence instead of an ordinary mismatch.

Pass this normalized evidence beside that request:

```json
{
  "pull_request": {
    "status": "ok",
    "facts": {
      "repository": "owner/project",
      "number": 456,
      "base_ref": "main",
      "base_sha": "1234567890abcdef1234567890abcdef12345678",
      "head_ref": "fix-123",
      "head_sha": "0123456789abcdef0123456789abcdef01234567",
      "body": "Closes #123.",
      "state": "open",
      "draft": false,
      "url": "https://github.com/owner/project/pull/456"
    }
  },
  "tree": {
    "status": "ok",
    "facts": {
      "commit_sha": "0123456789abcdef0123456789abcdef01234567",
      "tree_sha": "abcdef0123456789abcdef0123456789abcdef01"
    }
  },
  "linked_issue": {
    "status": "ok",
    "facts": {
      "repository": "owner/project",
      "number": 123,
      "type": "issue",
      "state": "open",
      "author_login": "owner",
      "url": "https://github.com/owner/project/issues/123"
    }
  }
}
```

The evaluator uses the pull-request body only to prove the explicit issue
reference. The result does not include that body.

The helper only reads GitHub. It does not approve, merge, mutate, select work,
create factory state, or replace agent judgement. Helper success is not a
prerequisite for work that does not need the corresponding check.
