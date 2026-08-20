# Desktop and operator preview

SafeYolo owns the lifecycle and security boundary for its optional graphical
desktop. The guest components listen only on loopback; the operator reaches
noVNC through a token-gated SafeYolo preview.

## Divide host and guest responsibilities

The preferred operator command is:

```sh
safeyolo agent desktop AGENT --open
```

It starts or reuses the guest desktop and runs the host preview in the
foreground. The operator should use a separate terminal or tmux pane when the
agent session must remain available.

Inside the guest, inspect or start the desktop with:

```sh
/safeyolo/guest-desktop status
/safeyolo/guest-desktop start
```

A guest-side start creates Xvfb, the window manager, x11vnc, and noVNC, but it
cannot create the host preview. Ask the operator to run the host command printed
by the launcher. Do not expose guest ports 5900 or 6080 directly.

## Start a browser

For a generic browser profile, the operator can combine startup and preview:

```sh
safeyolo agent desktop AGENT --browser URL --open
```

If the task owns its own browser launcher, profile, or debugging-port allocation,
use `safeyolo agent desktop AGENT --open` without `--browser`, then start that
browser inside the ready guest desktop. This avoids profile and port collisions.

The guest launcher also provides:

```sh
/safeyolo/guest-desktop browser URL
/safeyolo/guest-desktop terminal
```

Both require the desktop to be ready. A running headless display is not proof
that the operator can see it; confirm that the host preview is open whenever the
workflow requires operator control.

## Diagnose in ownership order

```sh
/safeyolo/guest-desktop check
/safeyolo/guest-desktop status
```

- `check` reports missing graphical packages or programs.
- `status` distinguishes the Xvfb, x11vnc, and noVNC layers.
- Browser startup errors are written to `/tmp/chrome.log` by the core launcher.
- A missing `/safeyolo/guest-desktop` indicates stale or incomplete per-run
  guest files; ask the operator to stop and run the agent with current SafeYolo.

Do not treat a desktop failure as a proxy-policy failure, and do not weaken the
network boundary to repair a graphical component.
