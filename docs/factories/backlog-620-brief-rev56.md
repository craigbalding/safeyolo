# #620 Rust proxy release factory brief

## Goal and durable sources

Complete the first Rust proxy release in craigbalding/safeyolo. Work from the
current feat/rust-proxy-620 integration branch without resetting or discarding
later commits. GitHub #620 and its child issues define the release acceptance
contract. The #620 execution index and native issue dependencies define the
remaining path. #621 defines the shared Python/Rust black-box lane.
docs/proxy-parity.md is the discrepancy and deletion inventory; do not create
a second one. Keep #620 open until #640's final exact-commit criteria pass.

The supervisor checkpoint and canonical Coord transitions identify live tasks,
not product acceptance. GitHub issue bodies and Lens's short acceptance comments
identify proven criteria. The Project is a view of those records. Refresh live
issue and branch state before relying on an old status or exception note.

The trusted-base SafeYolo acceptance graph is
`cli/src/safeyolo/agent_context/skills/safeyolo/references/graph/accept-safeyolo.yaml`.
For each material #620 candidate claim, Lens starts at `sym.accept_candidate`
or the matching symptom and follows only the applicable boundary path. The
graph selects a probe; it is not a whole-graph checklist. If the graph lacks
the Rust boundary or tool needed for a claim, Lens reports that specific gap
to Relay and uses an approved focused direct probe where one exists.

On the first resume, preserve the stopped Forge task, Lens review, exact
candidate, and any unfinished local work. Finish or explicitly re-scope those
assignments before dispatching a new feature. The old task and review messages
name evidence bundles, manifests, hashes, and narrow test work. Those process
instructions are superseded: do not create, refresh, or recheck a bundle merely
because an old handoff named one. Use the current code, a focused run, and a
short observed result. Keep any existing artifact that is genuinely needed to
judge a non-repeatable result. A new contract does not erase an accepted result
or turn a stopped review into a new task.
At this pause, Lens still owns the #637 guest-ingress investigation. Lens
accepted PR #749's first head `7b8ceb57`, but Forge then sent a new
`REVIEW_READY` for head `c1da231a`; the earlier READY does not accept this
new head. Reconcile these live handoffs and the checkpoint before resuming
either assignment. Preserve the #637 task and review the latest #749 head;
do not replace either with a new task.

## Feature-sized work

Relay gives Forge a coherent feature or fix that can run and be reviewed as one
result. For example, several #621 cases about the same response handoff belong
in one task with their relevant negative cases. A single fixture row, test
name, or checkbox is not a task by default. Forge stays on that feature through
Lens's correction rounds. No new unrelated Forge task starts at REVIEW_READY.
When several known producer paths break the same invariant, put the remaining
paths and their negative control in one repair. For #635, repair the proven network-guard false-pending prompt and check
the adjacent credential-guard prompt in the same task; repair it if the
same defect is confirmed. Do not make each path a separate PR.

Forge may experiment locally and use local commits. It publishes one review
candidate when the related change works. The candidate is the immutable head
commit of the pull request (PR). The handoff needs a short account of the
behavior, the action or command, and the observed result. Lens checks it independently and
returns one consolidated defect list where needed. Do not produce routine
evidence directories, manifests, copied transcripts, or file hashes.

Some repository fixtures pin the source used to generate them. If a change
touches that source, update the affected fixture and run its direct producer
or check and consumer test. This is product data, not a review-pack or handoff
hash requirement. Trusted validation-tool identity checks belong to tool
setup, not to each feature review.

## Tests and integration

During implementation, use quick local checks of the changed behavior. Lens
uses a focused independent probe that could reveal a defect, including the
real system boundary when the requirement depends on it. Start with affected
test functions or modules. Do not run the entire `cli/tests` tree as a routine
candidate check. Expand to named related modules only when a specific result or
shared call path warrants it. Reserve a repository-wide local suite for a
coherent integrated checkpoint or the release candidate. A clean broad suite
is not required for `READY`. New security promises need a concrete adversarial
check.

For a feature or fix involving structured input or a meaningful request/state
sequence, Lens reads $HOME/.codex/skills/lens-hypothesis/SKILL.md and uses actual
Hypothesis generation and shrinking as the default focused adversarial probe.
Drive the relevant real boundary and check the result against the requirement;
for #621 parity, replay the same generated cases against Python and Rust when
practical. Keep the result in the ordinary review disposition, without a new
evidence pack or extra CI run.

For Rust, the affected Cargo test and a direct boundary probe take priority
over a scanner badge. Lens's small Rust review pack is at
`/evidence/reviewer-tools/rust-semgrep-rules` (operator path:
`/home/agent/safeyolo-rust-620-evidence/reviewer-tools/rust-semgrep-rules`).
It contains fixed copies of five Semgrep Rust security rules and Trail of
Bits's `panic-in-function-returning-result` rule. The sources are the
[Semgrep Rust security rules](https://github.com/semgrep/semgrep-rules/tree/develop/rust/lang/security)
and [Trail of Bits's Rust rules](https://github.com/trailofbits/semgrep-rules/tree/main/rs).
Keep these copies outside the public repository. Do not refresh them during a
candidate review. Lens runs
the following command in its clean candidate checkout, using Semgrep from the
trusted `tools/acceptance` environment. On the first review, set
`review_base` to the starting commit supplied in Relay's TASK. On a
correction, set it to the last Lens-reviewed candidate commit. Replace the
first line's placeholder with that commit:

    review_base=COMMIT_FROM_TASK_OR_LAST_REVIEW
    tools/acceptance/.venv/bin/semgrep scan \
      --config /evidence/reviewer-tools/rust-semgrep-rules \
      --baseline-commit "$review_base" --metrics=off \
      --disable-version-check --disable-nosem --strict \
      --exclude 'tests.rs' --exclude '*_tests.rs' \
      --exclude 'tests/**' proxy/src

Use the merge base if that commit is not an ancestor. Check scan errors and
exclusions. Exclude test-only files and ignore matches inside inline
`#[cfg(test)]` modules. Revisit an old match only when the candidate changes
its code or the guard, caller, or input path that justified the earlier
decision. The pack is a review aid, not a complete security scan; its
`rustls-dangerous` rule does not cover `with_custom_certificate_verifier`, so
inspect changed TLS verifier behavior directly. Use `p/rust` for a specific
additional question, or `p/python` on changed production Python files when
relevant. The small local Python rule set supplements those checks. Do not
send Forge unrelated existing alerts. The public `observe_reconciled` method
in `proxy/src/agent_discovery.rs` can panic on an inconsistent caller-created
`ReconciledIdentity`. Relay should include this open fix in related
agent-discovery work or assign it when no related work remains. It is not a
dismissed baseline finding or a veto on unrelated candidates.

The repository pins CodeQL 2.26.3, which has no native Linux ARM64 bundle. A
newer native bundle exists, but this factory has not bound it as a review
tool. Do not run CodeQL for each feature. Relay can seek a narrow tool
decision for an integrated checkpoint or a specific security question. An
incomplete scan is not an independent result.

The repository's focused Ubuntu PR workflow currently runs automatically for
matching feature PRs. It is not a reason to split work, delay Lens's review, or
rerun the same tests locally for a badge. Relay checks any repository-required
result once at the reviewed head before merge. A skipped, failed, cancelled,
or stale-head required check is not a pass.

The full Ubuntu/macOS Rust matrix is for a coherent integrated checkpoint and
the final release candidate, through the existing ci/proxy-rust-620 ref and
ready release PR path. Do not advance that ref for each small PR, each Lens
correction, or elapsed time. A final #640 pass must cover the current
post-deletion candidate, not an older checkpoint. Diagnose a failure with a
small reproducer before repeating a full run.

Do not delete production Python proxy code until #640 authorizes and validates
the exact deletion commit. Keep the 41 rows in
docs/proxy-cutover-deletion-map.md accounted for.
The #638 task-policy persistence choice remains an operator decision; work on
other ready outcomes while it is pending.

## GitHub Project and issue acceptance

Relay maintains issue-level Status in
https://github.com/users/craigbalding/projects/1 after a real transition:
Ready, Active, Review, Blocked, Accepted, or Integrated. A partly accepted
issue follows its remaining work. Lens alone marks an affected acceptance
criterion passed. A PR merge alone does not complete the issue.

Relay's Project-only credential is at
~/.config/safeyolo/github-project.token. Set GH_TOKEN from that file only
for a single gh api graphql Project call; ordinary repository calls use the
existing credential. Do not print or share the token. Native sub-issue
relationships and Project membership matter; body text alone does not create
them. If a Project write fails, repair the view without blocking unrelated
product work or claiming the view is current.

## Resources

Each role uses its configured /workspace checkout and only its approved mounts.
A required handoff path must be visible and readable to the recipient; private
home paths are not cross-role handoff paths. The shared /evidence mount is
available for a material result that cannot be reproduced from code. Forge's
permitted artifact area is /evidence/forge; Lens reads the same path. Verify
actual write and read access before naming an artifact in a handoff. An exact
PR commit and a focused result normally suffice. Keep only the raw result
needed to judge a non-repeatable claim, with a short explanation.
If a host-produced result refers to other files by absolute host path, the
handoff must also name each file's guest-visible `/evidence` path. Do not ask
the recipient to infer that mapping from the result file.
In this nested Linux factory, `/evidence/forge` is owned by guest root.
When a material shared artifact is needed, Forge uses `sudo -n` to create
directories and copy files within that permitted subtree, then gives files
readable modes (0644, or 0755 for scripts). An ordinary-user permission
error here does not mean the mount is read-only. If guest sudo also fails,
report the exact path and error instead of trying another location.

Use scripts/cargo_with_space.sh with CARGO_BUILD_JOBS=1 for Cargo work with the
configured 20 GiB reserve. Reuse warm targets within the same source tree.
When Lens compares a candidate with a mutated checkout, keep each built binary
at a distinct path or use separate Cargo targets. Cargo can reuse the wrong
checkout's binary when both trees share one target directory; confirm which
binary a behavioral probe executes. Relay schedules
at most one genuinely memory-heavy clean Cargo build or multi-guest probe
across Forge and Lens at a time; the other role may continue source work or
small warm checks. Do not assign a task whose only next action is waiting for
the reserved resource. Do not interrupt an active build merely for scheduling.

safeyolo-tahoe is the Tart macOS route for work that does not need Apple's
Virtualization.framework (VZ). Forge and Lens may use the mailbox directly.
If it fails before a command starts, use the
already-approved isolated Bristol seatbelt-mac route for the same task.
If a submitted Tart response exists but guest permissions block reading it,
use guest `sudo -n` to read that response; it is not a failed command.
Bristol VZ tests use the physical Mac through
ssh -F ~/.ssh/seatbelt-agent/config seatbelt-mac. Relay serializes that
shared resource. Build the signed test helper on Tart and verify its identity
when transferring it to Bristol. In the isolated sy-agent directory on Bristol, run disposable
VZ helpers through this wrapper with a positive test deadline:

    /Users/sy-agent/bin/run-vz-test --timeout-seconds N -- /absolute/path/to/safeyolo-vm run ...

Use an isolated overlay. Call the helper directly through the runner, without
an intervening shell script. The runner owns process cleanup; do not
background an untracked helper or replace the host's production helper or
configuration. Run sustained churn or stress on an isolated host with bounded
concurrency and a deadline, not in these four-vCPU factory sandboxes.

For an operator-owned disposable Linux host witness, state whether its proxy
and target sandbox must already be running. Verify those prerequisites before
the run. Afterward stop both: `safeyolo stop` leaves the sandbox running, so
stop the disposable agent separately and verify it stopped.

## Operator attention

Relay records one self-contained Coord message before waking the operator
through ~/.safeyolo/operator-attention/request. Use that wake signal for a
genuine unresolved blocker, unavailable capability, or material scope
decision, not routine progress. Continue other authorized work while a
decision is pending. Keep issue acceptance and exact-candidate rules intact.
