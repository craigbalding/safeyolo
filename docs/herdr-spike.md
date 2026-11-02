# Herdr phase-one native-agent spike

The phase-one journey for
[#572](https://github.com/craigbalding/safeyolo/issues/572) passed on 31 October
2026 in owned Rundeck execution 12426. Two separately sandboxed Codex agents
accepted real input, called tools and answered through Herdr. Named navigation,
detach/reattach, native identity continuity, conversation continuation and
normal owned stop passed. This report records that journey and the earlier
failures; independent Lens acceptance remains separate.
The whole issue remains open, with Size M and Medium uncertainty. Its other
integration questions remain in the issue.

## Scope and demonstrated operator workflow

Use Herdr **terminal user interface (TUI) 0.9.5** on the trusted Linux operator
host. Start two existing, separately sandboxed native SafeYolo Codex agents in
adjacent panes. Send one
harmless prompt to each agent. Focus each agent by name, detach the TUI with
Ctrl+B, Q, then reattach and continue both conversations. Finally, stop both
owned agents through SafeYolo and stop the disposable Herdr server.

Allow 1–2 hours including preparation, execution and interpretation. The script
has a 30-minute journey deadline by default, followed by bounded cleanup. Stop
and reassess a material setup or scope expansion within that session budget.
Do not add a launcher plugin, scheduler, registry, policy-mediated mutations or
a general compatibility layer to finish this spike.

## Trusted-host pane wrapper

[The wrapper](../scripts/safeyolo_herdr.py) uses the installed native command-line
interface (CLI). In a Herdr pane on the trusted host, supply an existing agent
name, the installed
CLI's absolute path and its instance root. In this example, `demo` is an already
configured agent, `/trusted/checkout` is this source checkout, and
`/installed/safeyolo` is that instance's root. The command starts the coding
command with the pane's terminal input and output:

```sh
python3 /trusted/checkout/scripts/safeyolo_herdr.py demo \
  --safeyolo /installed/safeyolo/bin/safeyolo \
  --root /installed/safeyolo
```

The wrapper delegates `agent start NAME --foreground`, reads `agent status NAME`
and publishes a name plus native agent/run/launch identity. It refreshes
metadata while the command runs, with a five-second metadata expiry. Failed status
reads clear the native tokens. A display failure is reported without ending the
coding command. The wrapper releases its display when the command exits and
returns the command's exit code. Proxy and certificate-authority settings are
inherited. Herdr controls and unrelated outer tmux identity are removed from
the native child's environment. The wrapper adds no guest socket mount.

The displayed semantic state stays **unknown**. Native runtime, command and
terminal states appear as separately named metadata. A running sandbox does
not establish a live coding command, working/idle state, approval state, or
Factory completion. The wrapper reads no task records and emits no Coord
handoffs.

Herdr client reattachment reconnects to its retained pane and foreground
process. This differs from native `agent attach`. The wrapper's `--attach`
option delegates that existing native operation for a launch whose recorded
terminal supports attachment, such as a tmux launch. Production `377a54e0`
does not supply a native attach path for a foreground launch.

## Executable real-journey oracle

[The journey script](../scripts/accept_herdr_native.py) uses Python 3.11 or newer
on Sylab's owned Linux guest through the existing Rundeck route. It requires
the verified preparation file, the complete existing Codex 0.164.0 packages and
their authorized agent-local login state. Both prepared sandboxes must have
their recorded identities and no coding command yet. A previous or uncertain
run must be inspected before another execution. The script does not retry a
prompt or start automatically.

The bound runtime is production native
`377a54e06ebf0f6962f61ab8080a23fdfe6b1592`. The source candidate starts from
approved `4bc7b3ccecb661de89ffa1069e8ade02fba174f1`. Its native lifecycle
command files match that runtime's interfaces; no product build is needed.
The preparation file records the exact installed paths, Herdr binary digest,
both native agent/run identities, workspaces and 10 GiB reserve. It proves
sandbox and tool preflight, not model input or output.

On that guest, from the exact candidate source checkout root, set `PREPARATION`
to Sylab's refreshed, verified preparation file. Each completed execution stopped
both prepared sandboxes; a consumed preparation file cannot identify fresh
ready inputs. Sylab refreshes only those owned sandbox generations and records
their actual identities, reusing packages, authorized login, workspace and
the working Coord ports. Set `OUTPUT` to a new absolute directory under the existing private
`/home/agent/375-build-storage-d62/frontend572` workspace. Its parent must
exist. The command starts coding commands and makes four model requests. It
creates a private disposable Herdr server and stops the two owned sandboxes
on exit, retaining their homes, configuration and useful installed inputs:

```sh
python3 -m scripts.accept_herdr_native \
  --preparation "$PREPARATION" --output "$OUTPUT"
```

The oracle requires all of these observations:

- Each pane reports the prepared native agent/run identity and a live launch.
  The two agent identities and sandbox generations differ.
- Pane input reaches a **new Codex rollout** as a user message. A tool call
  follows it, and an assistant message contains the requested SHA-256 answer.
  A fresh workspace receipt and visible pane output must agree. The expected
  digest is absent from the input, so an echoed prompt or synthetic pane text
  cannot satisfy this check.
- Focus-by-name selects each bound pane. Both names render in the actual TUI.
  Ctrl+B, Q exits each of two pseudoterminal (PTY) clients successfully. Native
  agent/run/launch identities remain unchanged before detach, while detached,
  after reattach and after continuation.
- After reattachment, each agent computes another answer using its previous
  token. The continuation does not resend the token. Its input and answer must
  occur in the same Codex session as its first turn.
- Normal native stop reports stopped sandbox/command state and an absent
  terminal for both agents. Cleanup preserves a changed generation rather
  than stopping another run. The owned Herdr server exits normally and its
  control socket disappears.

The Codex observer reads only complete current `response_item` records from
the two owned homes. Its version-bound shape comes from upstream
[rollout serialization](https://github.com/openai/codex/blob/rust-v0.164.0/codex-rs/history/src/rollout_payload.rs)
and [persistence policy](https://github.com/openai/codex/blob/rust-v0.164.0/codex-rs/rollout/src/policy.rs).
It is proof tooling, not a source of Factory semantics. Login state and full
rollouts remain private. The output directory is private too; transfer only
`result.json` and a concise operator assessment to `/evidence/operator/572`
through Sylab. Keep `server.log` and Herdr state private. A failure or cleanup
fallback returns nonzero and retains partial observations. Herdr protocol and
response-shape failures retain a reason in `result.json` before cleanup.
Startup questions or onboarding require inspection, not blind acceptance or a
passed result.

## Observed result and exact bindings

Execution 12426 ran the scripts at
`b440ab4f63d90f4567653ae52a62e0c1238b1cc4` against the production native runtime
`377a54e06ebf0f6962f61ab8080a23fdfe6b1592` on Ubuntu Linux with Kernel-based
Virtual Machine (KVM), Herdr TUI 0.9.5/protocol 22 and Codex 0.164.0. The command
below is a record: cleanup consumed its prepared sandbox generations, and its
output directory exists. Inspect the retained result instead of replaying the
command. From `/home/agent/375-build-storage-d62/frontend572/source-b440ab4f63d9`,
Sylab ran:

```sh
/usr/bin/python3 -m scripts.accept_herdr_native \
  --preparation /home/agent/375-build-storage-d62/frontend572/native-preparation-after12421.json \
  --output /home/agent/375-build-storage-d62/frontend572/journey-b440ab4f-retained-login \
  --timeout 1200
```

Guest exit was 0, with no timeout. The driver took 62.129 seconds; the outer
command took 62.208 seconds, from 18:02:45 to 18:03:47 Coordinated Universal Time
(UTC).
Preparation, login repair and earlier attempts are outside those intervals.

The sanitized result is `/evidence/operator/572/journey-b440ab4f-12426.json`,
SHA-256 `4c3acd69764818ba5c5442a92ff488895de398d2325c8958d5ad8cc2578bd2e9`.
It binds `/evidence/operator/572/native-preparation-after12421.json`, SHA-256
`8d0c6c83a5c3234c7702d9dd89f8ffd6313df565bec8041cd3a2603e828094dd`, and both
script hashes. The preparation binds the installed Herdr binary to SHA-256
`14d9e8bc8b4a9e0118d77c32266f76d461f09b40342eb23752960bd89f59929d`.
These bindings remain valid for a report-only commit; neither script changed.

- Both `frontend572-a` and `frontend572-b` received first and continued prompts.
  All four turns had real Codex tool calls, expected assistant answers, matching
  fresh workspace receipts and answers visible in the corresponding panes.
- Focus by name selected the bound panes, and both names rendered in both TUI
  clients. Both Ctrl+B, Q detach operations exited 0. The recorded agent/run/launch
  identities stayed unchanged before detach, while detached, after reattach and
  after continuation. Native commands and runtimes remained running.
- Each agent retained its original Codex session. Agent A used
  `01a19321-01ea-7c60-99f0-32916cf7841a`; agent B used
  `01a19320-fea1-7ff3-a4d0-370a85dd81ae`. Continuation used the previous token
  without resending it.
- Normal SafeYolo stop left both agents and runtimes stopped, with absent
  terminals. Normal Herdr stop and control-socket absence passed.

The result retains all five native snapshots, four turn results and cleanup
identities. Full rollouts, login state, pane logs and Herdr state remain private.
This is a short automated terminal journey, not a sustained coding or human
usability study. It covers two agents on Ubuntu/KVM; it does not cover another
platform, another Herdr frontend, server restart or semantic harness activity.

## Earlier failures and corrected causes

Rundeck execution 12403 ran source
`95c2dd07c8473067624be94611c6c66106dd9d13` against native runtime
`377a54e06ebf0f6962f61ab8080a23fdfe6b1592` on 31 October 2026. It returned
guest exit 1 after 8.176 seconds in the driver and 8.371 seconds in the outer
command. Both native foreground launch identities were created.
`Journey.read_pane` then raised `KeyError: text` before `ready` returned or
`turn` ran. No smoke prompt was sent. Read-only diagnostic execution 12404
found no new Codex rollout in either prepared home.

Normal native stop reached stopped sandbox/command state and an absent terminal
for both agents. Owned Herdr stop and socket absence also passed. The failed
execution establishes an observer defect. It supplies no model journey,
operator-usefulness conclusion, runtime-defect finding or product acceptance.
The original sanitized result remains at
`/evidence/operator/572/journey-95c2dd07-12403.json`, SHA-256
`aa0a32fc6e2c4103caba9e466c39f89601fdb86e9fc65f997abbc90255396183`.
That execution remains a failed attempt.

Herdr TUI 0.9.5 serializes pane output as
`result.read.text`. Its tagged
[response enum](https://github.com/herdrdev/herdr/blob/2ecf19a92fc3a7fff75b6ce3655ef04f4625ec01/src/api/schema/response.rs#L162)
contains a `read` member, and the
[pane-read producer](https://github.com/herdrdev/herdr/blob/2ecf19a92fc3a7fff75b6ce3655ef04f4625ec01/src/app/api/panes.rs#L1512)
populates that member with `PaneReadResult`. The corrected consumer reads that
member after `Herdr.call` removes the outer `result`. Malformed JSON, invalid
response envelopes and malformed pane reads report the method and expected
shape without copying terminal output into the result. Unexpected missing or
mistyped fields in the other observer accesses also leave a failure reason.
The release's ping, workspace-create, pane-split, agent-get and agent-focus
producers match the other consumed fields.

For a focused protocol check on a Linux host with the repository's locked test
environment, set `HERDR_TEST_BINARY` to the absolute path of a verified official
TUI 0.9.5 release binary for that host's architecture. From the source root, run:

```sh
uv run --frozen pytest -q tests/test_herdr_native.py
```

With that variable set, the test exercises the real Herdr server and pane reader,
including metadata, name focus and the other consumed response structures.
It starts no SafeYolo sandbox or model. Without the variable, only that live
protocol control is skipped. The same control reproduced the original
`KeyError` before the repair and passed afterward. The remaining controls
exercise malformed replies and verify that a failed observer writes its reason
through cleanup. These results support the observer repair. Execution 12426
also exercised the corrected reader through the real two-agent journey.

Execution 12408 used `b440ab4f` and reached actual pane output, but both Codex
processes stayed at sign-in before any prompt or session. Ordinary guest login
status reported logged in. Sylab stopped the verified driver after 474.718
seconds (474.800 seconds outer); guest exit was 143. A targeted credential
import corrected the copied login's missing proxy authorization. Execution
12421 verified that authorization, then the provider returned `401 token_expired`.
The driver was stopped after 216.820 seconds (216.891 seconds outer), again with
guest exit 143 and no model turn. Both attempts passed normal native and Herdr
cleanup. Their results remain failed at
`/evidence/operator/572/journey-b440ab4f-12408.json` and
`/evidence/operator/572/journey-b440ab4f-12421.json`.

Sylab reused a newer authorized login from the same provisioned account in an
owned stopped fixture, adopted it into the two owned homes and imported it for
those agents. The successful preparation records that correction. Execution
12426 verified the actual consumer afterward. No source change, native build,
new sign-in or broader credential authority was needed.

## Findings and remaining questions

The retained [Lens feasibility finding](https://github.com/craigbalding/safeyolo/issues/572#issuecomment-6533770500)
establishes custom display metadata, pane input, split/focus and synthetic
detach/reattach. Custom `agent.prompt` returned `agent_not_ready`; a blocked
report returned `agent_blocked`. This spike therefore uses pane input on the
trusted host. The separate native Herdr app/core is outside this TUI spike.

The demonstrated operator value is one grouped terminal view for two separately
sandboxed conversations. Names select the correct pane, native identities help
identify the running agents, and reconnect preserves both conversations without
restarting the coding commands or resending their context. This can reduce
separate terminal windows and manual navigation in a two-agent lab. The run
does not measure productivity or establish usability at larger scale.

The minimum observed integration is one trusted-host wrapper using native
SafeYolo lifecycle/status commands and Herdr's custom report, metadata and
release calls. Host pane input supplies prompting. No native runtime change or
launcher plugin was required. The sign-in failures show why copied login state
and a successful login-status check alone do not establish model readiness.

No new guest policy capability was needed for this operator workflow. The run
does not select policy-mediated create/prompt/wait/stop capabilities; those
remain later-phase questions in #572. The demonstrated simplification is
grouped terminal operation. No evidence supports removing Lab, Coord, Factory,
policy, approvals or evidence storage. Herdr display state supplies no authority
or completion semantics, and semantic harness activity remains unknown.

The prior schema comparison and this live journey support a small integration
bound to TUI 0.9.5/protocol 22. Broader upstream application programming interface
(API) stability remains unproved.
Keep #572 open with its original outcomes, Size M and Medium uncertainty.
Reassess the bounded spike before selecting any later integration phase.
