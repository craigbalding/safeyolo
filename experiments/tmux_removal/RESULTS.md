# Hard tmux dependency: feasibility probes

These probes implement the ordered experiments in [issue #912](https://github.com/craigbalding/safeyolo/issues/912).
They do not change the installed product or remove its terminal integrations.
Results below are Forge's observations. Independent acceptance remains with Lens.

| Experiment | Observed disposition | Implementation decision |
| --- | --- | --- |
| PoC1: native proxy supervision | **FAIL** for the temporary direct held launch controlled by native stop. Normal native CLI launch, detached operation, later stop, identity controls, diagnostics and cleanup passed on Bristol. | The direct held launch needs an identity and a working stop path before readiness. Its result does not establish failure of the normal CLI's separate startup timeout and child-kill path. Do not widen Seatbelt permissions. |
| PoC2: PTY and screen state | Deterministic fixture and actual Codex session passed. **BLOCKED** on an authenticated Claude Code session. | Keep this one prototype. Its successful fixture and Codex run do not qualify it for production or establish whole PoC2 success. |
| PoC3: SafeYolo session lifecycle | **NOT RUN**. PoC2 has not succeeded in full. | Reuse the same prototype only after the missing Claude witness succeeds. |

## PoC1: direct held launch lacks a native stop record

On 20 October 2026, production-profile `safeyolo` and `safeyolo-proxy` were built
from `87382b0a969712b7646ed764eb970df32f7ce67f` on Tart. The build reused the
existing release target with an APFS copy-on-write clone. It took 3m42s. Both
binaries reported that commit. Tests ran through the existing Bristol
`sy-agent` SSH route, in `/Users/sy-agent/f912-873/run2`.

The effective, root-owned Seatbelt profile already contains `(allow signal)`.
The repository template's same-sandbox signal rule is not the installed rule.
No policy or host permission changed. An initial relay experiment was discarded
when a fresh SSH connection successfully stopped the native proxy directly.
There is no relay in the retained probe. This setup rework came from reading
the repository template before checking the effective installed policy.
The abandoned relay trial's retained records run from 03:00:47 to 03:00:49 UTC.
The replacement probe was staged by 03:03:11 UTC. The held-launch stop result
was recorded at 03:03:20 UTC. These are observed bounds, not a separate measure
of active drafting time. The compiler reported 3m42s within the retained Tart
command's 02:54:18–02:58:05 UTC bounds.

The retained probe observed:

- Native `start` launched the real proxy without a tmux executable in the
  isolated instance. The initiating SSH connection then closed.
- Fresh connections found the same kernel process birth and native readiness.
  Native `stop` returned success, the process disappeared, and readiness was
  removed.
- A real replacement launch survived stop attempts using the old process
  record and using its own PID with a wrong birth token. The native command
  ignored both records. It returned a stopped response even though the
  replacement remained alive. A correct record then stopped the replacement.
- A temporary fixture held the real policy file lock and launched the proxy
  directly, rather than through native `start`. A fresh
  connection reached its bound Admin listener while readiness and the native
  process record were absent. Native `stop` returned success and reported
  `proxy_state: stopped`. The same kernel process birth remained alive.
- The held proxy was PID 40106, birth `darwin:40106:1792465399:47182`.
  Fixture cleanup released the lock, delivered termination, and reaped the
  original child with exit status zero. This cleanup is separate from the
  failed native stop.
- A malformed policy caused native startup to fail. `logs/proxy.log` retained
  the original `unclosed table, expected ']'` diagnostic.
- The existing macOS account-process inspection found no process under the
  owned run root. The fixed-port probe passed after cleanup.

The direct held-launch result follows the current source. `record_proxy` runs after
`Proxy::start`, which loads policy and publishes readiness. `stop_proxy` does
nothing when `proxy_live` cannot find the process record. Signal handlers are
registered early, but the main loop consumes termination only after startup
completes. This directly launched process held in policy loading therefore lacks
native control identity. A queued termination does not itself cancel the
blocked load.

Normal native `start` has its own five-second readiness deadline and kills
its child when that deadline expires. The direct held fixture does not use
that parent control path. The reached result does not establish an equivalent
normal CLI startup failure. No normal proof was repeated for this attribution
correction, and no production repair was added.

The missing property for a direct launcher is ownership and stop control before
blocking startup completes. A wider signal permission is unnecessary on this
tested route. The complete proxy-supervision pass remains unestablished.

### Run PoC1

From a Linux control checkout, use Python 3 and the approved Bristol SSH config.
Reserve one approved loopback Admin port, default 46375. Use a new owned run
parent each time. Keep the production instance and other fixtures separate.

Stage these files through SSH stdin into one owned directory on Bristol:

- `poc1_proxy.py` from this directory;
- `tests/blackbox/harness/macos_process_argv.py` from the repository;
- exact-source macOS production binaries `safeyolo` and `safeyolo-proxy`
  in its `inputs` subdirectory.

For the retained staging directory, run:

```sh
python3 experiments/tmux_removal/run_poc1.py \
  --ssh-config /home/agent/.ssh/seatbelt-agent/config \
  --ssh-host seatbelt-mac \
  --remote-probe /Users/sy-agent/f912-873/poc1_proxy.py \
  --root /Users/sy-agent/f912-873/new-owned-run \
  --inputs /Users/sy-agent/f912-873/inputs
```

Every operation opens a fresh SSH connection. The driver refuses an existing
run parent. It deliberately makes per-instance Coord startup fail locally;
this proxy-only probe starts no NATS server and makes no acquisition request.

Expected current result: exit status 1 with `FAIL PoC1` after the held-start
stop result. The command first checks the other controls and completes owned
cleanup. Original native command results and failure diagnostics remain in
the individual instance directories. No failed stop is reported as a pass.

## PoC2: one PTY and screen-state prototype

The standalone Rust crate uses the issue's selected combination:
`pty-process` 0.5.3 and `vt100` 0.18.1. Tokio supplies asynchronous I/O.
`serde_json` frames local viewer and test commands. These dependencies belong
only to the experiment; production manifests and lockfiles are unchanged.

A host-owned keeper holds the child PTY and parser. Viewers can connect and
leave. The parser retains at most 200 history rows. Attach sends a formatted
current screen; ongoing output sends formatted state. This also prevents
child terminal queries from reaching a real viewer and receiving duplicate
answers. A small `vt100` callback answers cursor-position queries, including
when no viewer is attached. Other unhandled CSI/OSC command identifiers are
available in state for failure diagnosis. The prototype is not a complete
terminal emulator or an installed launcher.

The deterministic fixture passed on Linux ARM64. It generated 250 labeled
normal-screen lines while detached, completed the cursor query with
`ESC[6;9R`, and became idle on the alternate screen. A new viewer reconstructed
`ALT-DETACHED-IDLE` without any new child bytes. Resize from 24×80 to 18×64
reached the actual child. Return to the normal screen also reconstructed
without new child output. History retained 200 rows, including a recent
labeled row and excluding the oldest row. Reattached arrows, Unicode paste
and Ctrl-C bytes reached the child unchanged. The original child exited 7.
The keeper and socket were cleaned up.

The actual Codex 0.159.1 session also passed. It started with no viewer,
using an isolated test home and an approved private copy of provisioned
Codex authentication. After accepting trust for the empty owned workspace,
the actual viewer exercised one resize to 28×100, left/right editing,
backspace, a real model response, detach/reconnect, bracketed Unicode paste,
and Ctrl-C to clear the draft. The response was `POC-CODEX OK`.
A replay of the actual viewer's terminal bytes retained that response.
PID 44381 and session `44381-1792465933888522729` stayed unchanged. The child
later exited zero on Ctrl-C. No process with the owned workspace as its
working directory remained after keeper cleanup.

Claude Code 2.1.303 was installed through mise. Its packaged postinstall had
not run; the supplied local postinstall linked the already downloaded native
binary. `claude --version` then worked. The available isolated test home
reported `loggedIn: false` and `authMethod: none`. No authenticated Claude
session was run. This is an unavailable input, not a terminal compatibility
failure. Do not count a login screen as the required actual session.

### Build and run the deterministic fixture

From this repository on Linux with Rust 1.94 and Python 3, use a disk-backed
Cargo target and a new fixture root. The commands build only the prototype.
Preserve the configured proxy and CA environment.

```sh
CARGO_BUILD_JOBS=1 SAFEYOLO_CARGO_RESERVE_GIB=10 \
  CARGO_TARGET_DIR="$PWD/experiments/tmux_removal/terminal/target" \
  scripts/cargo_with_space.sh build --locked \
  --manifest-path experiments/tmux_removal/terminal/Cargo.toml

python3 experiments/tmux_removal/run_poc2.py \
  --binary experiments/tmux_removal/terminal/target/debug/tmux-removal-poc \
  --root /home/agent/issue-912-inputs/new-fixture
```

Expected result: `fixture: PASS`, 200 history rows, one answered query and
original child exit status 7. The driver stops the keeper and checks socket
removal. The experimental crate also passed Clippy with `-D warnings`.

### Run the actual harness probe

Use an owned Linux test home with provisioned, working authentication and an
empty owned workspace. Keep credentials private and outside evidence. Preserve
proxy and CA variables. Set `CODEX_HOME` or `CLAUDE_CONFIG_DIR` to that private
home as appropriate. Verify `codex login status` or `claude auth status` before
starting. Claude must report `loggedIn: true`.

For the following Claude example, first create a new private directory
`/home/agent/issue-912-claude` and its empty `workspace` subdirectory. Start in
this repository. Run the keeper in one terminal with the approved
authentication environment:

```sh
poc_binary="$PWD/experiments/tmux_removal/terminal/target/debug/tmux-removal-poc"
cd /home/agent/issue-912-claude/workspace
"$poc_binary" \
  /home/agent/issue-912-claude/session.sock 24 80 \
  claude --setting-sources ''
```

The keeper is independent of viewers. Complete only the harness's first-use
setup in that owned workspace if needed. From this repository in a second
terminal, run:

```sh
python3 experiments/tmux_removal/attach.py \
  /home/agent/issue-912-claude/session.sock
```

Ctrl-] detaches the viewer. It leaves the original harness running. After an
authenticated input prompt is present and the viewer has detached, run the
finite probe. `--ready` must identify text in that actual input prompt:

```sh
python3 experiments/tmux_removal/exercise_harness.py \
  --socket /home/agent/issue-912-claude/session.sock \
  --binary experiments/tmux_removal/terminal/target/debug/tmux-removal-poc \
  --name claude --ready 'TEXT FROM THE AUTHENTICATED INPUT PROMPT'
```

Expected result: `harness: claude`, `result: PASS`, and one unchanged PID and
session. The probe sends one short prompt that forbids tool use. It tests the
real viewer, resize, arrows, reconnect, paste and Ctrl-C. It detaches the viewer
and leaves the harness for its owner to stop. Stop the harness through its
terminal. Then remove the keeper:

```sh
python3 - <<'PY'
import socket
with socket.socket(socket.AF_UNIX) as client:
    client.connect('/home/agent/issue-912-claude/session.sock')
    client.sendall(b'{"op":"quit"}\n')
PY
```

Verify owned process and socket cleanup.

For Codex, use the same commands with `codex -C` and the owned workspace as
its argument, `--name codex`, and `--ready 'Ask Codex'` after first-use trust.
The probe's Codex result is not a substitute for the missing Claude result.

## Remaining input and stop rule

Relay must supply execution with existing approved Claude authentication in an
owned test home, through the existing operator route. No fresh sign-in, new
host permission, public credential copy or wider terminal implementation is
requested. Return the harness version, authentication success as a boolean,
the probe result, and owned cleanup observations. Never return credential values.

After that witness, reassess PoC2. Run PoC3 only on success. Preserve the PoC1
failure as a separate implementation decision. Do not expand this issue into
product tmux removal, a crate comparison, a benchmark or a terminal rewrite.
