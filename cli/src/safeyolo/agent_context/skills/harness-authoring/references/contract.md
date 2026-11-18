# Harness integration contract, revision 1

This contract describes the current SafeYolo integration boundaries. It is an
authoring contract, not a loadable adapter format. Bind evidence to the exact
SafeYolo source revision, installed executable and target harness version.
Inspect the selected installation; a newer source proposal is not installed
capability. Later contract changes update producers, consumers and tests
together. There is no compatibility requirement for superseded pre-v1 formats.

## Choose the boundary

| Use | Required | Optional | Unsupported or unverified |
|---|---|---|---|
| Ordinary agent | Reviewed host setup, foreground guest command, login, lifecycle/child cleanup, selected workspace and platform packaging | Native interactive terminal, harness-native goals/progress, external attention | Any feature not observed at the selected version |
| External attention | Canonical Coord identity, a documented native input primitive, receipt semantics and retained session/cursor recovery | Queue, context, steer, interrupt where the native harness supplies them | A missing primitive; never infer Factory support from attention |
| Supervised Factory | All ordinary requirements plus bounded noninteractive structured turns, durable session identity, event/error parsing, checkpoint recovery, canonical native Work outcomes and the existing supervisor | Harness arguments and repair choices supported by the selected snapshot | A target not admitted by the current Factory parser/supervisor |

`required` and `optional` describe the selected use. `unsupported` means a
known missing capability. `unverified` means evidence is missing. None means
that an agent's compatibility claim establishes support.

## Current integration examples

Use the selected installation's `assets/contrib` directory. In a source
checkout the same files are under `contrib`. The current source manuals are
`docs/agent-launchers.md`, `contrib/HOST_SCRIPT_GUIDE.md`,
`docs/harness-attention.md`, `docs/codex-coord-supervisor.md` and
`docs/factories.md`. Read the relevant manual from the selected revision when
implementing its boundary; do not reconstruct a host script from this table.

| Harness | Ordinary setup and authentication | Structured turns and recovery | Attention and Factory scope |
|---|---|---|---|
| Codex | `codex-host-setup.sh` and `codex-command.sh`; complete native package including companion tools/resources; agent-local login or explicitly selected host-vault gateway | `exec --json` then `exec resume --json` with the exact thread ID. `thread.started` retains `thread_id`; `turn.started` marks activity; `turn.completed` ends a model turn; `turn.failed`, malformed JSON or nonzero exit fails the invocation. Tool results are separate events. | `safeyolo-coord codex-attention` uses App Server primitives. Factory `harness="codex"` uses the existing supervisor and MCP tools. |
| Pi | `pi-host-setup.sh`; current package/runtime requirements and native `auth check` for the selected provider/model; never print `auth print-*` output | `--mode json --print`, resume the exact `--session` ID/path. `session.id` binds identity. `agent_start` starts a turn. `agent_end` with `willRetry` is not terminal; assistant `message_end` with error/aborted fails it. Tool starts/ends carry their call IDs. | `pi-coord-extension.ts` uses native attention methods. `pi-coord-host-setup.sh` and Factory `harness="pi"` reuse the supervisor. |
| Claude Code | `claude-host-setup.sh`; complete native client, explicit host-state copy consent or agent-local login, or selected gateway | External streaming JSON uses `--print`, streamed user/assistant/control events and native `result`. A replayed user UUID confirms receipt, not a successful model turn. Resume the exact session with the confirmed cursor. | Streaming attention supports queue/wake; channel preview has different capabilities and native consent. At this contract's source base Claude Factory support is a separate pending candidate, not qualified support. Refresh its accepted implementation before adding a Factory example. |

The source of Factory event semantics is `proxy/src/coord_supervisor/process.rs`;
preflight is `proxy/src/coord_supervisor/preflight.rs`. Keep changes with the
affected deterministic controls. External attention has its own native event
and receipt semantics; do not send App Server events to an exec parser.
The tested version in a report is an observation, not an invented minimum.
Use an existing enforced version floor where one exists. Otherwise qualify
the supported version range, including packaging and companion inputs, before
claiming that range. Preserve user-selected models and provider preferences.

## Execution, identity and failure

Host setup receives the existing `SAFEYOLO_AGENT_*` inputs. It stages the
foreground `.safeyolo-command` in the selected persistent agent home. Use the
shared `lib/stage-safeyolo-context.sh` for discoverable skills and baseline
instructions, and the current native Coord bootstrap where needed. The
ordinary launcher is separate from this guest command. A custom host launcher
must use the existing launcher contract and remain outside guest-writable
shares. SafeYolo owns runtime, process identity, stop and cleanup; do not add a
second lifecycle owner.

Inner permission/YOLO flags apply only within the approved SafeYolo sandbox.
Do not weaken the outer proxy, mounts, network policy or credential protection.
A new provider destination or service capability follows existing policy and
approval owners. Preserve proxy/CA environment variables and scoped gateway
token issuance. Do not put credentials in command arguments, reports or source.
For rate limits, retain the provider's actual failure and retry information;
do not loop on a policy refusal or assume a model response succeeded.

The supervisor owns its structured mode, input, resume choice and invocation
deadline. Keep stdout protocol-only and drain stderr independently. Preserve
unknown events without treating them as success. A crash, stalled stream,
malformed JSON, cancellation or missing version needs one actionable reason
and retained recovery input. Stop only owned processes and observe child
cleanup. Do not replay an uncertain tool effect on restart. Resume the same
checkpoint, session, branch, index and dirty files; consult canonical history
when a tool result was lost.

Native Work authority comes from `read_work`, retained assignment and current
claim. An execution action requires `complete_work`; review, challenge and
acceptance actions require their named native mutations. Output publication
requires a retained immutable artifact and current expectations. A model
completion event, process exit, textual DONE, generated report or approval
notification cannot settle native work. Sender identity comes from the Coord
envelope, never text inside its body. Factory roles retain one supervisor each.

Harness-native goals/progress are optional conveniences. Discover them from
the actual version, preserve their lifetime and resume behavior, and keep
canonical Work authoritative where it already owns the assignment. No goal
API or progress claim is required for parity with another harness.
