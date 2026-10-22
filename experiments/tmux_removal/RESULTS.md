# Hard tmux dependency: feasibility probes

These probes implement the ordered experiments in [issue #912](https://github.com/craigbalding/safeyolo/issues/912).
They do not change the installed product or remove its terminal integrations.
Results below are Forge's observations, except for the attributed operator
Claude witness. Independent acceptance remains with Lens.

| Experiment | Observed disposition | Implementation decision |
| --- | --- | --- |
| PoC1: native proxy supervision | **FAIL** for the temporary direct held launch controlled by native stop. Normal native CLI launch, detached operation, later stop, identity controls, diagnostics and cleanup passed on Bristol. | The direct held launch needs an identity and a working stop path before readiness. Its result does not establish failure of the normal CLI's separate startup timeout and child-kill path. Do not widen Seatbelt permissions. |
| PoC2: PTY and screen state | **PASS** in the bounded probes: deterministic fixture, actual Codex 0.159.1 and operator-run Claude Code 2.1.304. | This combination supports the selected terminal behavior. Reuse it for PoC3. These finite results do not qualify a production terminal implementation. |
| PoC3: SafeYolo session lifecycle | **PASS** on one real Bristol VZ guest, with two same-size viewers, either viewer disconnected, proxy restart, original identity and later attach reporting exit 23. | The same prototype fits the tested trusted entrypoint. Keep viewer and keeper lifetime separate. Production integration remains separate work. |

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

Claude Code 2.1.303 was first installed through mise. Its packaged postinstall had
not run; the supplied local postinstall linked the already downloaded native
binary. `claude --version` then worked. The available isolated test home
reported `loggedIn: false` and `authMethod: none`. No authenticated Claude
session could run in that home. This was an unavailable input, not a terminal
compatibility failure.

The operator then ran the same probe on Linux ARM64 with actual Claude Code
**2.1.304**. The existing installation updated during setup. The operator reused
the compiled prototype from `c2dbb329a1de39af7136cdbc7dd2fd7cdd9e6364`;
there was no rebuild or replay of the deterministic fixture or Codex session.
The real viewer, resize, editing, model response `POC-CLAUDE OK`, reconnect,
Unicode paste and Ctrl-C passed. PID 11380 and session
`11380-1792468353059293944` stayed unchanged. The child exited zero. Keeper,
child and socket cleanup were verified.

The first operator setup copied a stale provisioned profile. Login status
reported success, but actual token refresh failed. The operator cleaned up
that session before a renewed, provisioned profile supplied the successful
witness. No new sign-in was needed. Authentication and raw screens remain
private. The nonsecret operator result is
`/evidence/operator/912/claude-witness-20261020.json`, from operator path
`/home/agent/safeyolo-rust-620-evidence/operator/912/claude-witness-20261020.json`.
Forge read it and verified the supplied SHA-256
`2ce1ebae9132285bb7493c0f51502c20692035b781ead0fb7070f7a89ebf6e36`.
Canonical operator HANDOFF8313 and
[the issue result](https://github.com/craigbalding/safeyolo/issues/912#issuecomment-6283018560)
attribute this witness. It is operator evidence, not independent acceptance.

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
The two actual harness results are separate observations.

## PoC3: the same keeper around the trusted guest entrypoint

After reconciling the delivered Claude result, Forge ran `run_poc3.py` on the
approved physical Bristol VZ route. The crate source and lockfile were unchanged
from `c2dbb329a1de39af7136cdbc7dd2fd7cdd9e6364`. Only its first macOS build was
needed. Tart compiled that small crate in 12.89 seconds. The production-profile
CLI and proxy were the existing `87382b0a969712b7646ed764eb970df32f7ce67f`
binaries from PoC1. The installed VM helper came from the qualified
`acdd7b4bdb19f72a84dfbf0f2ca434950650cadb` package. The existing guest was
`guest-2026-10-17.39055525961001`, source
`51e2e3da38517edaf48a95d3f04f952681699345`, OCI index
`sha256:49f604c105e83d695f1bc39e42b4ae9069977f2c8f0bf94f269396a6fce3f5b0`.
No product rebuild, channel change or permission change was needed.

The probe created an owned agent and started its sandbox. The keeper then ran
native `agent start bbtest --foreground`. That command prepared the host-owned
launch record and called the existing `run_entrypoint`. The entrypoint used
the normal SSH guest transport and `safeyolo-guest observe exec` to run the
configured guest command. The command printed its PID and kernel start time,
answered terminal input, and returned 23 on request. It was a real SafeYolo
guest command; PoC3 needed no further model session.

The isolated instance had no `bin/tmux`. `TMUX` and `TMUX_PANE` were unset.
The foreground entrypoint did not invoke a terminal launcher. Its record still
has the existing `tmux_session` name field; a saved name is not a tmux process.
The maintained preparation and cleanup helpers supplied fresh credentials,
the owned NATS instance and verified process cleanup. Unchanged boot images
used APFS copy-on-write clones. The supported VM runner had a positive
180-second deadline.

The final run observed:

- Two actual `attach.py` viewers, each 24×80, reconstructed the same original
  screen and received the same reply from guest PID 1363, kernel start time 188.
- Killing the initiating viewer without a detach command left the other viewer
  and child usable. Reconnect reached the same keeper child PID 44409 and
  session `44409-1792469781780917000`. Killing the other original viewer also
  left the child usable. The replacement viewers used the same dimensions.
- Native proxy stop completed and the old proxy PID 44371 disappeared.
  Native start created PID 44429. The keeper stayed alive. Both viewers
  received another reply from guest PID 1363. Guest run
  `3ed1e4292e7f41dea2944bf6abbc4be0` and launch
  `launch-787b72f2e717406b962baf73315e952f` were unchanged.
- The original child returned 23. Both attached viewers returned 23. A later
  actual viewer also returned 23, with the original PID, session and launch
  still recorded. The host launch record said `exited`, `exit_code: 23`.
- A duplicate native entrypoint for that completed launch was refused with
  `No matching unclaimed coding-agent launch is ready`. The original result
  remained intact; no replacement agent was launched.
- The keeper exited zero and removed its socket. Maintained cleanup reported
  no surviving owned process or cleanup failure. All four stopped PoC3
  fixtures were removed after those checks. The postflight fixed-port and
  denied-port/UDP checks passed. Required binary inputs and warm targets remain.

Two earlier probe runs were incomplete. The first observer waited for viewer
exit without draining its display PTY. A full display could block the viewer's
last screen write. The original native child had already recorded exit 23.
The observer now drains while waiting. The second observer read the identity
line before the child's separate start-time output arrived. It now waits for
the complete identity. Both failed fixtures were cleaned up. A corrected run
passed, then the final run added the other-viewer disconnect and explicit
guest-run identity checks required by the issue. No terminal emulation or
production code changed to address these observer failures.

The final nonsecret result is `/evidence/forge/912/poc3.json`. The two original
incomplete observations are `/evidence/forge/912/poc3-viewer-wait.json` and
`/evidence/forge/912/poc3-partial-identity.json`. The operator prefix for all
three files is `/home/agent/safeyolo-rust-620-evidence/forge/912`.
Recorded fixture paths identify historical runs; the removed fixture trees
are not required review inputs.

### Run PoC3

Use the approved Bristol `sy-agent` SSH account. Reserve its physical VZ lane
and the approved ports first. Use an existing prepared native package with
its guest assets and NATS binary. Keep the configured proxy and CA environment;
the confined account requires a readable CA bundle. Use the existing Python
environment with `tomlkit`. Keep the paths short enough for macOS Unix sockets.

On Tart, build the unchanged experimental crate with the build command above,
using a disk-backed target. Transfer the macOS prototype through SSH stdin.
Stage `run_poc3.py`, `run_poc2.py` and `attach.py` in one owned Bristol directory.
Stage the repository's `tests/blackbox` Python files below its `source`
directory. These are the maintained preparation and cleanup helpers.
The following retained inputs remain available; the new `--base` must not exist.

From Bristol, with the readable public certifi CA bundle exported as
`SSL_CERT_FILE` and `REQUESTS_CA_BUNDLE`, run:

```sh
/Users/sy-agent/f1105-7418/.venv/bin/python -B \
  /Users/sy-agent/f912p3/run_poc3.py \
  --prepared /Users/sy-agent/s8/sy-package.9SdPnz/prepared \
  --repository /Users/sy-agent/f912p3/source \
  --native-binaries /Users/sy-agent/f912-873/inputs \
  --binary /Users/sy-agent/f912p3/tmux-removal-poc \
  --base /Users/sy-agent/p912-new
```

Expected result: `result: PASS`, original `exit: 23`, `keeper_exit: 0`,
`socket_absent: true`, and an empty `cleanup_failures` list. The command starts
and stops its own proxy, Coord instance and guest. A successful native proxy
stop alone does not establish guest teardown. Verify the owned stopped fixture
before removing it. Do not delete the prepared inputs or warm build targets.

## Finite implementation decision

The selected `pty-process` + `vt100` component supports the tested terminal
and SafeYolo lifecycle requirements. Keep that combination if implementation
proceeds. Differently sized simultaneous viewers, broader terminal compatibility,
and production session integration remain outside this experiment.

PoC1's direct held-launch failure remains a separate decision. A direct launcher
needs ownership and stop control before blocking startup completes. Normal
native start already has a separate timeout and child-kill path; the held probe
does not establish an equivalent failure there. The complete proxy-supervision
pass remains unestablished. These results do not authorize product tmux removal.
No wider permission, crate comparison or terminal rewrite is proposed.
