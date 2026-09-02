# Controller bootstrap and reconnection

Read this reference when the operator starts or reconnects to a SafeYolo lab.

## Operator workflow

From the host, enter the SafeYolo agent:

```bash
safeyolo agent shell AGENT
```

The guest shell starts in `/home/agent`. Run one command there:

```bash
safeyolo-lab
```

Do not run another startup command inside tmux.

On first use, `safeyolo-lab`:

1. creates the named guest tmux session `lab`;
2. creates a persistent interactive controller shell;
3. injects the SafeYolo controller runner with hidden startup instructions;
4. attaches the operator to the session.

The runner invokes `/home/agent/.safeyolo-command` without replacing the
interactive shell. When the controller exits, the shell remains alive and
shows the controller exit marker.

Codex receives `Hello.` as the short first user message. The startup briefing is
in developer instructions, so Codex does not show it as a long user message.
The first controller response explains that the lab is a visible tmux workspace
for experiments. It gives brief examples and invites the operator to state what
they want to explore. It makes no tool call and does not change lab state. The
controller discusses the pass condition, constraints, evidence, and teardown
only after the operator describes the work.

The same `safeyolo-lab` command works when the guest is displayed directly and
when a host tmux pane displays the guest. The guest prefix is `C-a`. A host tmux
can retain `C-b`. Detach from the guest with `C-a d`.

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

After a disconnection, enter the agent again and run:

```bash
safeyolo-lab
```

If the `lab` session exists, the command only attaches. It does not inject the
runner again. Inspect the controller pane before you authorize a new controller
invocation.

## Command installation

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
