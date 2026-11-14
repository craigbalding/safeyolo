# Installed GitHub and artifact checks

Use the host account that owns the selected SafeYolo instance. The example
adds two required native Work bindings to an already approved factory: a live
GitHub author check before issue admission/delegation and a check of a small
JSON artifact before output acceptance. It uses one selected engine in normal
operation. Running both is a parity/qualification exercise.

## Find the installed entry

A native package contains this skill in `assets/skills/job-authoring`. Managed
Codex and Claude homes discover it as `job-authoring`; the read-only guest
entry is `/safeyolo/skills/job-authoring/SKILL.md`. The shared `safeyolo` skill
also links here. No repository checkout is needed for the installed example.

On the owning host, a Codex agent can discover the installed skill by linking
it into its normal discovery directory. These commands assume the chosen
instance is `$HOME/.safeyolo` and the discovery name is unused. For a host
Claude agent, use `$HOME/.claude/skills` instead.

```sh
mkdir -p "$HOME/.agents/skills"
ln -s "$HOME/.safeyolo/assets/skills/job-authoring" "$HOME/.agents/skills/job-authoring"
```

Refresh the host agent's skill discovery and ask it to use `job-authoring`.
Keep the same selected root through preparation, adoption and inspection.
An agent running inside a normal guest has no host adoption authority.

## Check prerequisites and proposed authority

The installed package must include the optional matching Hyperlight bundle
under `assets/hyperlight`. Linux x86_64/aarch64 needs accessible KVM;
Apple-silicon macOS needs Hypervisor.framework and the entitled helper. A Mac
VM without nested virtualization can prepare source but cannot run this example.
See [engine selection](engines.md) before choosing a runtime.

The host preparation helper requires Python 3.12+. The commands below use uv
to resolve its declared TOMLKit 0.14.0 and PyYAML 6.0.3 authoring dependencies.
If the selected Python environment already supplies those versions, invoke
the same helper with `python3` instead of `uv run --script`. These are host
authoring tools, separate from native product startup. The guest runtime is
the pinned bundle, not the host Python install.
Select an existing GitHub credential by its vault reference name. Select the
existing approved factory and room; creating or changing a factory remains the
ordinary `safeyolo-factory` workflow. No factory change is performed by this
walkthrough.

Before adoption, inspect the actual instance and saved/current authority:
replace `example` with the existing factory name before running its doctor.

```sh
safeyolo --root "$HOME/.safeyolo" status
safeyolo --root "$HOME/.safeyolo" policy show
safeyolo --root "$HOME/.safeyolo" services show github
safeyolo --root "$HOME/.safeyolo" credentials list
safeyolo --root "$HOME/.safeyolo" factory doctor example
safeyolo --root "$HOME/.safeyolo" job validate "$HOME/.safeyolo/assets/hyperlight/hyperlight-service.json"
```

For Python, validate `hyperlight-unikraft-service.json` instead. Missing
artifacts, runtime/architecture mismatches or unavailable virtualization stop
the run; there is no engine fallback. A validation pass is not a VM execution.

The core examples have a five-second job deadline; the Unikraft examples have
a fifteen-second deadline. The helper gives each named check five additional
seconds for its surrounding execution. These are finite budgets, not latency
promises. Retained Unikraft runs took 7.2–8.3 seconds; an installed attempt with
the earlier five-second budget timed out before delegation. Increasing the
budget does not establish faster execution or installed qualification.

The proposed dependency grant belongs only to
`gate:hyperlight-service-check`. It permits authenticated `GET` of issues in
one repository through service `github`, with no GitHub write route. The
provider credential stays in the host store. The check receives the complete
bounded response through a host call; it has no socket, gateway token or
administrative token. The admitted response, including a private issue body,
becomes Work input visible to that room's authorized readers. Select the room
with that disclosure in mind.

### Authorship and autonomy

This check verifies the author identity recorded by GitHub, not whether a human
personally created the issue. If an agent's granted GitHub access causes its new
issues to be attributed to the configured user, those issues satisfy the author
condition, provided the other configured conditions also pass. That may be
exactly what the operator wants for autonomous backlog creation. A
prompt-injected agent with the same capability can use that trust path too.
The trade-off begins with understanding the granted authority and the identity
GitHub records. Inspect the actual credential behavior and returned author ID;
a separate GitHub App bot identity does not become the expected human identity
merely because that human owns the installation. This note is an awareness
requirement, not a requirement to remove issue-creation access or add recurring
human approval.

The example never creates a live issue to imply a credential mode. Its parity
fixtures cover an issue attributed to the configured user and a distinct bot ID.
Comment authorship, later edits, repository ownership, assignees and content
safety are separate claims. Login names help readers; the predicate uses stable
numeric `user.id`.

## Develop and test a checker

For the Python implementation, develop and test inside the selected agent's
existing sandbox. The host owner supplies the nonsecret
`assets/hyperlight/service_checker.py` from the selected installation in that
agent's existing workspace as `supplied-service_checker.py`. The installed
skill and Python 3.12+ must be available in that guest. Run these commands as
the ordinary agent in its workspace, with `service_checker.py` unused. They
copy source and run controlled cases with Python's standard library. They
contact no provider, launch no Hyperlight runtime and change no instance
authority.

```sh
cp supplied-service_checker.py service_checker.py
python3 /safeyolo/skills/job-authoring/examples/test_service_checker.py service_checker.py
```

Expected: seven tests pass. The cases cover a matching author, another author,
a pull request, a different repository, malformed evidence, a missing author
and a denied service call. The injected capture includes multiple chunks.
The denial is a controlled exception, not proof of live capability enforcement.

Read and edit `service_checker.py` to implement the requested
predicate through its existing `service_check(request, call)` interface. Keep
authority in the declared inputs and host calls. Extend the local tests for
the requested behavior in a workspace copy of the example, then rerun them.
Host paths in a proposal do not grant guest access to that host.

Return to the owning host. In a private working directory, copy the installed
bundle to an unused `proposed-bundle` directory. Follow source symlinks so the
copy is independent of the installed bundle. Replace
`/path/to/selected/workspace` with that agent's existing host-mounted workspace
before running these commands. Copy and review the tested source as data;
execute agent-developed code inside the sandbox.

```sh
cp -R -L "$HOME/.safeyolo/assets/hyperlight" proposed-bundle
cp /path/to/selected/workspace/service_checker.py proposed-bundle/service_checker.py
```

Update the proposed definition's digest from the same host working directory:

```sh
python3 - <<'PY'
import hashlib
import json
from pathlib import Path

bundle = Path("proposed-bundle")
path = bundle / "hyperlight-unikraft-service.json"
definition = json.loads(path.read_text())
checker = definition["engine"]["checker"]
checker["sha256"] = hashlib.sha256((bundle / checker["path"]).read_bytes()).hexdigest()
path.write_text(json.dumps(definition, indent=2) + "\n")
PY
```

The runtime and artifact checker keep their existing pins. A Rust checker
instead needs the matching core guest build; use the bundle producer's
toolchain and application binary interface (ABI). Update `guest.sha256` in
each definition that selects that rebuilt guest, including the artifact check
when it shares the executable. The Python tests do not qualify Rust or the
selected virtual machine runtime.

## Prepare, inspect and adopt

In a private host working directory, replace `OWNER/REPOSITORY`,
`STABLE_USER_ID`, `ISSUE_NUMBER`, `engineering`, `example` and `factory-github`
with the selected repository, expected numeric user ID, existing issue,
authorized room, approved factory and existing credential reference. The helper
writes a new private `candidate` directory; it contacts no provider and changes
no saved or active instance state.

Choose one preparation command: the first uses the installed bundle; the
second uses the developed Python bundle. Both write `candidate`, so run only
the selected variant before validation.

```sh
uv run --script "$HOME/.safeyolo/assets/skills/job-authoring/scripts/prepare.py" --root "$HOME/.safeyolo" --engine hyperlight --repository OWNER/REPOSITORY --author-id STABLE_USER_ID --issue ISSUE_NUMBER --room engineering --factory example --credential factory-github --output candidate
```

Select `--engine hyperlight-unikraft` for the Python implementation. Preparation
pins the installed checker/definition digests, fixes the expected identity in
operator-owned inputs, adds the two bindings and proposes a repository-scoped
service capability. It preserves existing controls and other capabilities.
A conflicting example block stops generation; an existing explicit host denial
remains effective. Resolve the named conflict through the existing authority.

For the developed Python bundle, run this variant instead of the preparation
command above. Use the same selected instance, room, factory and credential
choices. The bundle must be at its reviewed host path before adoption:

```sh
uv run --script "$HOME/.safeyolo/assets/skills/job-authoring/scripts/prepare.py" --root "$HOME/.safeyolo" --bundle proposed-bundle --engine hyperlight-unikraft --repository OWNER/REPOSITORY --author-id STABLE_USER_ID --issue ISSUE_NUMBER --room engineering --factory example --credential factory-github --output candidate
```

`--bundle` selects the proposed definitions and digest-checked checker bytes;
it defaults to the instance's installed bundle. The receipt names the selected
bundle. Review the proposed code, runtime pins, capabilities and limits before
the same service/policy checks and owner adoption below. Digest agreement and
offline tests do not approve code. Existing adopted definitions that differ
still require the owner's explicit reconciliation; this option does not
replace them or remove a required binding.

Review `candidate.toml`, `github.yaml` and the printed root, policy and service
target. Then validate the selected proposal:

```sh
safeyolo --root "$HOME/.safeyolo" services check candidate/github.yaml
safeyolo --root "$HOME/.safeyolo" policy check candidate/candidate.toml
```

`policy check` compiles; offline `policy evaluate` cannot execute a
dynamic job and cannot prove live admission. A direct `job run` with
`author-request.json` renamed to `request.json` in its input directory is an
execution test, not adoption or a passed factory requirement.

Retain the current saved policy and any user GitHub override before activation.
The following commands assume the default native installation's user catalogue
is `data/services`; use the helper's reported `service_target` if configured
differently. Copying the reviewed override adds a capability to the GitHub
catalogue. The running proxy watches that directory separately from policy
activation. First observe the new capability in the loaded catalogue:

```sh
cp candidate/github.yaml "$HOME/.safeyolo/data/services/github.yaml"
safeyolo --root "$HOME/.safeyolo" services show github
```

Continue when `definition.capabilities.read_example_issues.routes` shows only
`GET /repos/OWNER/REPOSITORY/issues/*` for the selected repository. If the
watcher has not loaded the override, repeat this read. A failed read or a
different definition requires inspection of the selected path and proxy's
configuration errors. `services check` validates a file; it does not load it.

Then apply the reviewed candidate. Policy apply saves and activates against
the loaded catalogue. Neither operation changes factory contracts:

```sh
safeyolo --root "$HOME/.safeyolo" policy apply candidate/candidate.toml
safeyolo --root "$HOME/.safeyolo" policy show
safeyolo --root "$HOME/.safeyolo" services authorized gate:hyperlight-service-check
```

Expected: active policy, `saved_matches_active=true` and the selected read-only
capability. The authorized `github` entry must name the selected credential and
contain only the expected repository's `GET` issue route. An empty `routes`
array grants no callable route, even if the capability name is correct. If
that readback differs, stop before admission and inspect the loaded definition
and effective policy. Do not revoke/reissue a grant or retry admission blindly.
A written file alone does not establish active authority. If a reply is lost,
read the same root's current state before another change. Restore a
retained policy through `policy apply`; restore a catalogue override separately.
Standing adopted grants require no repeated routine approval.

## Run admission and consume its snapshot

The host can import the selected existing issue. Replace the repository, issue
and room with the prepared values before this command:

```sh
safeyolo --root "$HOME/.safeyolo" coord work import-github engineering https://github.com/OWNER/REPOSITORY/issues/ISSUE_NUMBER --operation-id author-example-1
```

This performs the required read before Work creation, even though import does
not supply a factory selector. An authorized coordinator can instead call
`create_work` with that issue reference. The proxy selects the bound approved
factory. An author mismatch or pull request cannot be admitted; denied or
malformed evidence holds the transition. The caller cannot submit its own
verdict or expected author. Delegation of existing issue Work runs the same
requirement.

Use `read_work` or host `coord work show ROOM WORK_ID` to read the retained
`automatic` admission evidence. Under `evidence.execution.checked_input`,
decode `content_base64` and verify its `sha256` before consuming its issue title
and body. That captured response is the assigned issue input. Adjacent service
evidence retains observation times and available ETag/Date/Last-Modified.
Missing upstream metadata stays missing. Subsequent admission/delegation
refreshes the read and replaces the checked snapshot; it does not reuse a
previous admission result. A fresh observation does not promise that GitHub
remains unchanged after it.

Attempt a known author mismatch and a pull-request number in the same selected
repository to inspect rejection without creating new GitHub issues. Omitting
the factory selector or changing the web reference to its equivalent API URL
does not skip the check. Work outside the configured repository remains generic.
This binding does not discover an issue reference hidden in unstructured prose.

## Produce and verify a small artifact

In the assigned worker's guest workspace, produce a JSON result and prepare its
native publication fields. These commands write only `result.json` locally:

```sh
printf '{"status":"ready"}\n' > result.json
python3 /safeyolo/skills/job-authoring/scripts/publication.py result.json
```

The second command prints `target_ref=sha256:…` and `artifact_base64` as JSON.
Read the current Work. The retained holder calls `publish_work_output` with
those fields, the current work/claim/output generations, an honest execution
outcome, summary and chosen operation ID. Publication retains the bytes and
creates a verification obligation atomically. The proxy automatically runs the
selected `ArtifactCheck` or `artifact_checker.py`, with no network grant.

The predicate accepts well-formed JSON whose `status` equals the policy-owned
`expected_status` (`ready` in this example). `draft` is a negative finding;
missing/invalid JSON, missing status or execution failure is unavailable evidence.
Neither permits output acceptance. This checks a bounded example, not arbitrary
application correctness.

Inspect current Work after publication: automatic execution may advance its
version beyond the publication receipt. The selected decider can approve only
when this exact output's automatic requirement and the factory's independent
reviews both qualify. Publication and execution completion are separate native
transitions. An automatic predicate is not an independent participant review.

To demonstrate replacement, produce `{"status":"draft"}`, retain/publish its
new bytes and observe a fresh unsatisfied obligation. The earlier ready output
cannot satisfy the replacement. Replacing it with new ready bytes creates
another obligation; do not attest old evidence onto the new generation.

## Inspect failures and follow-up effects

Read `automatic`, `acceptance_status`, `execution.outcome`, `runtime_report`,
`observation_error`, captured digests and policy/service authority. The host
audit's `ops.work_requirement` also retains rejected admission attempts by
operation ID. Missing, stale, substituted, revoked or failed evidence is not a
negative author observation and never becomes a pass from exit status alone.

An `after_complete` binding is a different supported boundary: it retains a
follow-up obligation with completion and dispatches under its adopted effect
capability. Its failure cannot undo completion or a remote effect. An action
left dispatching after restart is uncertain and is not automatically retried.
The host owner reconciles it with `coord work resolve-action` after inspecting
the external authority. These examples adopt no effectful follow-up.

Retain exact source, installed package/runtime/checker digests, adopted
definitions, actual host/architecture and observed results for independent
acceptance. Source fixtures, package discovery and one working engine cannot
establish both-engine Linux/macOS installed acceptance. Real GitHub grant,
revocation/off-scope controls, factory enforcement and output replacement each
need their actual consumer result.
