# Controller bootstrap and reconnection

Read this reference when the operator starts or reconnects to a SafeYolo lab.

## Operator workflow

On the native instance host, run `safeyolo lab`. The entry asks for the
objective before preparing its guest and checking its own Codex authentication.
The operator does not enter a guest shell or discover a controller pane first.

The internal `safeyolo-lab` helper creates the owned guest session and a
persistent interactive controller shell. The runner invokes the staged Codex
command without replacing that shell. The recorded objective and base
instructions are supplied as developer instructions. Codex receives `Hello.`
as the short first user message, acknowledges the objective and proposes the
smallest useful experiment before mutations.

When the controller exits, its shell remains alive with the real exit marker.
`lab --status` reports that the controller is dead. `lab --recover` explicitly
restarts it; reattach alone does not start a second controller.

The guest prefix is `C-a`. A host tmux can retain `C-b`. Exit the Lab viewer
with `C-a d`.

The tmux profile does not start a shell, harness, or provider. It sets the
prefix, status, borders, labels, and scrollback. Its UI-only hooks adapt pane
layout when the visible terminal size or pane count changes. The launcher, not
the profile, starts the controller.

The status line gives concise navigation and evidence hints. `C-a` plus an
arrow changes panes. `C-a q` shows large pane numbers. `C-a e` marks or clears
the current evidence fragment. `C-a E` opens its explanation. The controller
is the default focus target. An experimental pane becomes the target only while
the operator must interact with it.

## Reconnect

After a disconnection, run `safeyolo lab` on the same instance host. Use
`--agent NAME` when several Labs exist. A live owned controller is reused;
Lab does not inject its runner or startup message again.

## Internal guest command

A pre-lab shell in `/home/agent` prints this discovery hint:

```text
SafeYolo lab: run safeyolo-lab
```

If the command is absent after the skill is installed, run the internal
installer once:

```bash
/safeyolo/skills/safeyolo-lab-controller/scripts/install-operator-entrypoint.sh
```

The installer creates `$HOME/.local/bin/safeyolo-lab`. It adds that persistent
user command directory to interactive Bash shells. It refuses to replace an
unrelated command or a non-regular `.bashrc` file.

Use `safeyolo-lab --help` for the short command description. This option does
not start the lab.

## Bootstrap failure

If `.safeyolo-command` is missing or is not executable, the controller runner
records its path and safe file metadata. It reports the exact blocker and
returns to the persistent shell. Do not reconstruct the host command.

When a host tmux or application-owned tmux is also present, record each layer's
socket path during the experiment. A pane ID has meaning only with its tmux
server and layer.
