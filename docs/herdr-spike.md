# Herdr terminals and claimed work

Use Herdr **terminal user interface (TUI) 0.9.5** on the trusted Linux operator
host to group separately sandboxed SafeYolo conversations. Each pane runs the
existing native terminal command. Names select panes, and native identities
identify the corresponding agents and launches. Herdr client reattachment
retains those foreground conversations.

## Trusted-host pane wrapper

[The wrapper](../scripts/safeyolo_herdr.py) uses the installed native command-line
interface (CLI). In a Herdr pane on the trusted host, supply an existing agent
name, the installed CLI's absolute path and its instance root. In this example,
`demo` is an already configured agent, `/trusted/checkout` is this source
checkout, and `/installed/safeyolo` is that instance's root. The command starts
the coding command with the pane's terminal input and output:

```sh
python3 /trusted/checkout/scripts/safeyolo_herdr.py demo \
  --safeyolo /installed/safeyolo/bin/safeyolo \
  --root /installed/safeyolo
```

The wrapper delegates `agent start NAME --foreground`, reads `agent status NAME`
and publishes a name plus native agent/run/launch identity. It refreshes
metadata while the command runs, with a five-second metadata expiry. Failed
status reads clear the native tokens. A display failure is reported without
ending the coding command. The wrapper releases its display when the command
exits and returns the command's exit code. Proxy and certificate-authority
settings are inherited. Herdr controls and unrelated outer tmux identity are
removed from the native child's environment. The wrapper adds no guest socket
mount.

Herdr client reattachment reconnects to its retained pane and foreground
process. The wrapper's `--attach` option instead delegates native `agent attach`
for an existing launch whose recorded terminal supports attachment, such as a
tmux launch. Native attach does not start an absent coding command or attach to
a foreground launch without an attachable host terminal.

## Optional claimed work

If the instance has a Coord room that you want to observe, add `--coord-room` to
the wrapper command. In this example, `delivery` is that room:

```sh
python3 /trusted/checkout/scripts/safeyolo_herdr.py demo \
  --safeyolo /installed/safeyolo/bin/safeyolo \
  --root /installed/safeyolo --coord-room delivery
```

The wrapper reads native `coord status delivery --json` during refresh. It
selects claimed rows whose `claim_agent_id` equals the named agent's durable
`agent_id`. Agent display names do not establish ownership. Without
`--coord-room`, the wrapper makes no Coord reads and keeps its identity and
terminal behavior. The wrapper does not discover a Factory or emit Coord
handoffs.

To show the metadata, edit the trusted host's Herdr configuration before
starting its server. The default Linux path is `~/.config/herdr/config.toml`;
`herdr --help` shows the resolved path. Merge the following rows into your existing
`[ui.sidebar.agents]` table; do not create a duplicate table. These rows replace
the Agent sidebar layout and show up to ten title/reference pairs:

```toml
[ui.sidebar.agents]
rows = [
  ["state_icon", "agent", "state_text"],
  ["workspace", "tab"],
  ["$coord_room"],
  ["$claimed_work"],
  ["$claim_warning"],
  ["$claim_1_title", "$claim_1_ref"],
  ["$claim_2_title", "$claim_2_ref"],
  ["$claim_3_title", "$claim_3_ref"],
  ["$claim_4_title", "$claim_4_ref"],
  ["$claim_5_title", "$claim_5_ref"],
  ["$claim_6_title", "$claim_6_ref"],
  ["$claim_7_title", "$claim_7_ref"],
  ["$claim_8_title", "$claim_8_ref"],
  ["$claim_9_title", "$claim_9_ref"],
  ["$claim_10_title", "$claim_10_ref"],
]
```

`Claimed work` reports how many matching claims the returned page contains.
If more than ten claims match, the count shows displayed/seen, such as `10/11`.
The separate warning row says `Display truncated`. If the room page is also
incomplete, that row says `Room truncated` instead. Keep the room, count and
warning on separate rows so a long room name cannot hide the count or warning.
Each reference is the work's external GitHub URL when available, otherwise its
candidate target or durable work ID. References are display text; the wrapper
does not fetch their contents. The separate runtime, control, command and
terminal observations remain available as native metadata.

Herdr limits a pane to 32 metadata tokens and each value to 80 characters. The
wrapper uses ten title/reference pairs within that limit. It marks text
excerpts with `…`. Coord also bounds its active-work page and title excerpts.
If `Room truncated` appears, the count covers only the returned page. Even a
count of `0` then does not establish that the agent has no claims.
Use native `coord status ROOM --json` to inspect
the projection, or `coord work show ROOM WORK_ID` for a full known work record.
The count and warning fit Herdr's default 26-column expanded sidebar. Narrower
sidebars can clip them. Titles and references can need more space. To widen the
sidebar, merge these settings into the same configuration's `[ui]` table:

```toml
[ui]
sidebar_width = 80
sidebar_max_width = 80
```

Text can still exceed the available width. Use the native work record to read
the full title and references.

Released or completed claims disappear on refresh. If a Coord read fails or
returns malformed data, the wrapper clears the claim titles/references and
reports `Claimed work: unavailable` with `Unavailable` on the warning row.
If native identity is unavailable, the
wrapper also clears the claims. If Herdr cannot receive an update, the existing
five-second expiry removes stale metadata.

A claim describes **ownership**, not present activity, process liveness or
completion. Claims persist until an explicit transition, and an agent can own
several claims. Reviewers need not hold the owner's claim. The pane's harness
activity stays **unknown**. Displayed work supplies no authority for policy,
approvals, orchestration or completion.

## Focused protocol control

On a Linux host with the repository's locked test environment, set
`HERDR_TEST_BINARY` to the absolute path of a verified official TUI 0.9.5 release
binary for that host's architecture. From the source root, run:

```sh
uv run --frozen pytest -q tests/test_herdr_native.py
```

With that variable set, the control exercises the real Herdr server, metadata,
name focus and pane reader. It checks the claim tokens at the display limits,
clears them, and renders the documented layout at the default sidebar width.
The rendered control checks the count and warning for incomplete room pages,
omitted display rows and unavailable reads. It starts no SafeYolo sandbox or model.
Without the variable, only the live protocol control is skipped. The remaining
controls exercise wrapper terminal behavior, ownership selection, claim
release/completion, unavailable and malformed reads, and projection limits.

## Real-agent acceptance tooling

[The journey script](../scripts/accept_herdr_native.py) uses Python 3.11 or newer
on an owned Linux guest through the existing Rundeck route. To run the journey,
obtain a verified preparation file for two owned, separately sandboxed Codex
0.164.0 agents with their authorized agent-local login state. Both sandboxes must have their
recorded identities and no coding command yet. The preparation records the
installed native CLI/root, verified Herdr binary digest, agent/run identities,
workspaces and disk reserve. Preflight alone does not prove model readiness.
Inspect an uncertain prior run before another execution. The script does not
retry a prompt or start automatically.

On the prepared guest, from the candidate source root, set `PREPARATION` to
that file. Set `OUTPUT` to a new absolute directory on disk-backed storage
outside the checkout, with an existing parent. Each completed execution stops
its prepared sandbox generations; obtain fresh identities before another run.
The command starts coding commands and makes four model requests. It creates
a private disposable Herdr server and stops its two owned sandboxes on exit,
retaining homes, configuration and useful installed inputs:

```sh
python3 -m scripts.accept_herdr_native \
  --preparation "$PREPARATION" --output "$OUTPUT"
```

The journey has a 30-minute default deadline followed by bounded cleanup. It
requires distinct agent/run identities, live launches, received user messages,
real tool calls, expected assistant answers, fresh workspace receipts and
matching visible pane output. The expected answer is absent from the input.
Focus by name must select each bound pane. Both names must render in two
pseudoterminal (PTY) clients, and both Ctrl+B, Q detach operations must succeed.
Agent/run/launch identities must remain unchanged through detach and reattach.
Each continuation must use the prior token in the same Codex session without
resending that token. Normal stop must leave both sandboxes and commands
stopped, terminals absent and the disposable Herdr socket removed. Cleanup
preserves a changed sandbox generation rather than stopping another run.

The observer reads complete current `response_item` records from the two owned
homes. Its version-bound shape comes from upstream
[rollout serialization](https://github.com/openai/codex/blob/rust-v0.164.0/codex-rs/history/src/rollout_payload.rs)
and [persistence policy](https://github.com/openai/codex/blob/rust-v0.164.0/codex-rs/rollout/src/policy.rs).
The observer is proof tooling, not a source of Factory semantics. Login state,
full rollouts, pane logs and Herdr state remain private. Transfer only sanitized
`result.json` and a concise operator assessment through the existing evidence
route. A failure or cleanup fallback returns nonzero and retains partial
observations, including protocol failure reasons. Inspect startup or sign-in
questions instead of blindly accepting them.
