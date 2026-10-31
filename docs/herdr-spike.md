# Herdr phase-one native-agent spike

This spike provides a host wrapper and a journey script for
[#572](https://github.com/craigbalding/safeyolo/issues/572). The first execution
failed in the pane observer before any smoke prompt. The corrected observer
awaits refreshed preparation and another owned execution. Local wrapper and
observer tests do not establish a passed Herdr/Codex journey.
The whole issue remains open, with Size M and Medium uncertainty. Its other
integration questions remain in the issue.

## Scope and expected operator workflow

Use Herdr **TUI 0.9.5** on the trusted Linux operator host. Start two existing,
separately sandboxed native SafeYolo Codex agents in adjacent panes. Send one
harmless prompt to each agent. Focus each agent by name, detach the TUI with
Ctrl+B, Q, then reattach and continue both conversations. Finally, stop both
owned agents through SafeYolo and stop the disposable Herdr server.

Allow 1–2 hours including preparation, execution and interpretation. The script
has a 30-minute journey deadline by default, followed by bounded cleanup. Stop
and reassess a material setup or scope expansion within that session budget.
Do not add a launcher plugin, scheduler, registry, policy-mediated mutations or
a general compatibility layer to finish this spike.

## Trusted-host pane wrapper

[The wrapper](../scripts/safeyolo_herdr.py) uses the installed native CLI. In a
Herdr pane on the trusted host, supply an existing agent name, the installed
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
the verified preparation JSON, the complete existing Codex 0.164.0 packages and
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
to Sylab's refreshed, verified preparation JSON. The first execution stopped
both prepared sandboxes; their old preparation file cannot identify fresh
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
  Ctrl+B, Q exits each of two PTY clients successfully. Native agent/run/launch
  identities remain unchanged before detach, while detached, after reattach
  and after continuation.
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

## First execution and observer repair

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
Keep that execution when recording the next result.

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
through cleanup. These results support the observer repair; the real two-agent
journey still requires Sylab's owned execution and normal Lens review.

## Findings and remaining questions

The retained [Lens feasibility finding](https://github.com/craigbalding/safeyolo/issues/572#issuecomment-6533770500)
establishes custom display metadata, pane input, split/focus and synthetic
detach/reattach. Custom `agent.prompt` returned `agent_not_ready`; a blocked
report returned `agent_blocked`. This spike therefore uses pane input on the
trusted host. The separate native Herdr app/core is outside this TUI spike.

The proposed immediate operator value is grouped terminals, names and stable
native identity during navigation and reconnect. Actual usefulness remains to
be observed. The minimum integration under test is one host wrapper plus
Herdr's custom report/metadata and release calls. No runtime change has been
identified. No evidence yet supports removing Lab, Coord, Factory, policy,
approvals or evidence storage. Policy-mediated create/prompt/wait/stop remains
an unanswered later-phase question. The prior schema comparison supports
this version-bound experiment; broader upstream API stability is unproved.

After the real session, record the exact source candidate, consumed runtime,
command, elapsed time, result and concrete navigation/usefulness limits in
the issue and independent review. A preparation-only merge must leave #572
open. Revisit sizing before expanding into another phase.
