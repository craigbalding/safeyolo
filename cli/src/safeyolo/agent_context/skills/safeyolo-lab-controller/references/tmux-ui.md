# Tmux lab UI

Use this reference when creating, driving, styling, capturing, or closing lab
panes.

## Identify the controller

Inspect before changing layout:

```bash
printf 'controller_pane=%s\n' "${TMUX_PANE:-unset}"
tmux display-message -p 'socket=#{socket_path}'
tmux list-panes -a -F $'#{session_name}:#{window_index}.#{pane_index}\t#{pane_id}\trole=#{@safeyolo_lab_role}\ttitle=#{pane_title}\tdead=#{pane_dead}\tpid=#{pane_pid}\tcmd=#{pane_current_command}'
```

If `TMUX_PANE` is absent, do not guess which pane belongs to the controller.
Establish or attach to the intended tmux session first. Keep the controller
tmux socket/server and pane ID in the pane registry and exclude that explicit
pane ID from bulk close operations.

A laptop can display the guest lab tmux directly. A remote host tmux can also
display the guest lab tmux through one of its panes. The second case is nested
only at the operator UI; the host and guest tmux servers remain separate.
Record each present layer (`host-operator`, `guest-lab`, or
`application-internal`) with its socket. Enumerate only the intended guest lab
server unless the operator explicitly places another layer in scope.

Pane titles are mutable presentation labels. Coding harnesses and terminal
escape sequences may overwrite them. Use the tmux socket/server plus pane ID as
operational identity, and keep the external pane registry as the durable
experiment record. A pane-local `@safeyolo_lab_role` option is a useful role
label while the pane exists:

```bash
tmux set-option -p -t "$TMUX_PANE" @safeyolo_lab_role controller
tmux select-pane -t "$TMUX_PANE" -T controller
```

## Start through the operator handoff

The controller process starts only after the operator has attached to the
SafeYolo agent and entered tmux. Read [bootstrap.md](bootstrap.md) for the exact
startup and reconnection sequence. The operator runs `safeyolo-lab` once from
the pre-lab guest shell. The launcher creates the persistent shell and injects
the controller runner. Do not require a second operator command inside tmux.
Do not make tmux configuration run `.safeyolo-command` automatically.

## Create persistent shells

Create a pane without supplying a command so tmux starts the user's ordinary
interactive shell:

```bash
lab_pane=$(tmux split-window -d -P -F '#{pane_id}' -c /workspace)
tmux set-option -p -t "$lab_pane" @safeyolo_lab_role worker-shell
tmux select-pane -t "$lab_pane" -T worker-shell
"/safeyolo/skills/safeyolo-lab-controller/scripts/adapt-layout.sh" \
  --session lab
```

Do not use forms such as `tmux split-window 'command'` for experiments. They
replace the persistent shell with the command and destroy the pane when it
finishes.

Record at least:

| Tmux layer | Socket/server | Pane ID | Lab role | Mutable title | Purpose | Attached service/agent | State |
| --- | --- | --- | --- | --- | --- | --- | --- |

Use titles based on purpose, not transient command names.

## Inject commands safely

For a short literal command:

```bash
tmux send-keys -t "$lab_pane" -l -- 'uname -a'
tmux send-keys -t "$lab_pane" Enter
```

For complex quoting, multiple lines, traps, or credential-sensitive logic,
write a reviewed script and inject only a literal invocation of that script.
This avoids controller-side interpolation, command substitution, and accidental
credential echo.

When the exit status matters, add a marker after a command that returns to the
parent shell:

```bash
tmux send-keys -t "$lab_pane" -l -- 'command_under_test; lab_rc=$?; printf "\n__LAB_RC__=%s\n" "$lab_rc"'
tmux send-keys -t "$lab_pane" Enter
```

If the command can run again in the same pane, add a unique per-run identifier
to the marker and wait for that exact value as a standalone output line. Match
the full anchored line. The shell can echo the marker text as part of the
injected command before execution finishes. Do not infer completion by counting
older markers in scrollback. Tmux history can move while a command runs, so a
count is not a stable run boundary.

Do not wrap a command when doing so would change the behavior under test. In
that case, collect status through the native harness or parent shell.

Never inject a command containing a resolved token, cookie, password, private
key, or OAuth/device code. Read a credential inside the target process at use
time and keep it out of argv, pane output, shell history, and archives.

## Adapt the layout to the terminal

Use `../assets/tmux-lab.conf` for both terminal paths. The guest prefix is
`C-a`, which avoids a common host `C-b` prefix. The status line shows concise
navigation and evidence controls. The profile changes UI and history behavior
only. It never launches a shell, harness, or provider.

The launcher registers `scripts/adapt-layout.sh`. The profile calls it after a
client resize, pane split, pane close, or client attach. The helper uses these
defaults:

| Visible panes | Available size | Layout |
| ---: | --- | --- |
| 1 | Any | Single pane |
| 2 | At least 120 columns and 20 rows | Controller left, experiment right |
| 2 | At least 80 columns and 34 rows | Controller top, experiment bottom |
| 3 or more | At least 150 columns and 28 rows | Controller left, support panes stacked right |
| 3 or more | At least 90 columns and 50 rows | Controller top, support panes below |
| 2 or more | Smaller than the above | Focus pane zoomed, with a status warning |

This is a responsive rule, not a one-time startup choice. If the operator
resizes the real terminal, tmux runs the helper again. Automatic zoom ends when
the terminal becomes large enough. A manual `C-a z` zoom remains unchanged.
The helper refreshes attached tmux clients after it changes the warning or
layout. Do not use a temporary `display-message` for the size warning: that
message layer can remain painted until the next terminal input. When a warning
is active, it replaces the left status content and suppresses the right status
content. This gives the warning priority when tmux has very few columns.

Run the helper directly after a batch of pane changes when an immediate,
inspectable result is useful:

```bash
layout_helper="/safeyolo/skills/safeyolo-lab-controller/scripts/adapt-layout.sh"
"$layout_helper" --session lab --report
```

If the screen is too small, tell the operator that only one pane is visible and
that the other panes are still alive. Do not ask them to resize unless the lab
step requires simultaneous comparison.

An expert can disable automatic layout for one window:

```bash
tmux set-option -w @safeyolo_lab_auto_layout off
```

Set it back to `on` and run the helper to restore responsive behavior.

## Keep the operator in the controller

After command injection or observation, select the controller pane. This keeps
a new tmux user at the place where they can ask questions and steer the lab:

```bash
tmux select-pane -t "$TMUX_PANE"
```

When the operator must type in an experimental pane, set the window focus
target first. Resize events will then keep that pane focused:

```bash
tmux set-option -w @safeyolo_lab_focus_target "$lab_pane"
tmux select-pane -t "$lab_pane"
```

After the interaction, restore the normal target and focus:

```bash
tmux set-option -w @safeyolo_lab_focus_target controller
tmux select-pane -t "$TMUX_PANE"
```

Do not change focus repeatedly while the operator is selecting text or using
copy mode. Return focus at a clear action boundary.

## Use one lesson pane for structured teaching

Tmux is the process substrate, not the learner's curriculum. When a lab has an
ordered teaching flow, show the controller and one dedicated lesson pane. Keep
worker, service, login, and diagnostic shells persistent, but do not make the
learner visit each pane to assemble the explanation.

The controller drives the lesson surface by default and returns focus to the
controller after each action. The learner can press `F12` once to enter the
lesson, use `Left` and `Right` to read at their own pace, and press `F12` once
to return to the controller with a question. Do not take focus while the
learner is reading. A new tmux user does not need to learn pane navigation or
marker navigation before they can learn the subject.

The unprefixed `F12` binding switches panes by their lab roles, not by mutable
titles or pane IDs. It changes the window focus target, so responsive zoom
keeps the chosen surface visible. If no lesson pane exists, it changes no
state and reports that no lesson is open. The status line shows the available
action. On a small screen, include the switch hint in the size warning.

### Offer contextual learner questions

A structured lesson can show short sample questions beneath the material that
they concern. Give each question a stable visible ID such as `[REQUEST_ID]`.
Keep the full ID-to-question mapping in the lesson's reviewed tab-separated
question registry. Set the registry path in the lesson pane option
`@safeyolo_lab_questions_file` while the renderer runs.

The learner presses `q` to open a native tmux menu. Accept lowercase `q` and
uppercase `Q`; do not make this control case-sensitive. Presenterm uses
lowercase `q` as a default exit key, so tmux must intercept it while a reviewed
question registry is active. Keep `C-c` as the deliberate Presenterm exit.
Outside a registered lesson, pass both keys to the active program. The question
helper captures only the current rendered page, finds its visible IDs, and
resolves those IDs through the registry. A selected question is recorded with
its ID and UTC time.

A passive tmux event does not resume a coding harness after its turn ends. To
continue the conversation, the helper submits a visible message of this form:

```text
Learner selected [REQUEST_ID] from the lesson: Why is the request ID useful?
```

Submit only while the controller runner's current process identity and start
time prove that the harness accepts input. If that proof is absent or stale,
retain the question ID and return focus to the controller without pressing
Enter. Never send selected text to an ordinary shell. Question text comes only
from the controller-reviewed registry; do not use captured pane text as the
submitted message.

Use a renderer that keeps the source as a readable artifact, such as a trusted
Markdown lesson. Use the renderer only for short bounded cells. Keep long-lived
or interactive commands in their own persistent panes, then bring selected
safe evidence into the lesson. Preserve the raw panes for inspection.

Use the annotation rail for one ad hoc evidence point. Do not use a sequence of
annotations as the primary navigation method for a structured lesson.

### Open a lesson's real source files

A lesson can register reviewed remote source files in
`LESSON.md.sources.tsv`. Each row contains a visible source ID, a short label,
an absolute path, a first line, and a last line, separated by tabs:

```text
SRC_EXAMPLE<TAB>Short label<TAB>/absolute/path/file.py<TAB>40<TAB>55
```

Put `[SRC_EXAMPLE]` on the page that shows the related code. The learner
presses unprefixed `o`. `lesson-sources.sh` resolves only IDs visible on the
current rendered page. It opens one source directly or offers a native tmux
menu when several are visible. The source opens read-only in a popup at the
registered first line. The learner presses `q` to close it.

This server-side viewer works when the guest is remote or tmux is nested. Do
not use `file://` links: the outer terminal can interpret them as paths on the
operator's device. Keep the source registry controller-reviewed and never
register a credential file.

## Annotate ad hoc evidence where it appears

Use an annotation to connect raw output to a plain-language explanation. Each
annotation has:

- a stable ID such as `A1`;
- the source pane ID;
- a state: `INFO`, `WATCH`, `EXPLAIN`, `PASS`, `WARN`, or `FAIL`;
- one short finding for the pane border;
- an exact, safe evidence fragment copied from the output when available;
- one explanation of why that fragment matters.

The pane border shows a short colour-coded strip. On a sufficiently large
screen, a second status row shows the current annotation, evidence fragment,
and explanation. The adaptive helper removes this row when the screen becomes
too small and restores it when space returns.

Before an action:

```bash
annotator="/safeyolo/skills/safeyolo-lab-controller/scripts/annotate-pane.sh"
"$annotator" --pane "$lab_pane" --state WATCH \
  --text 'Waiting for the destination response' \
  --evidence 'Request sent'
```

After observation:

```bash
"$annotator" --pane "$lab_pane" --state PASS \
  --text 'The website returned a successful response' \
  --evidence 'HTTP/2 200' \
  --explain 'The website generated this response after SafeYolo allowed the route.'
```

The helper prints the assigned annotation ID. Refer to that ID and pane from
the controller, for example: “`A2` in pane `%1` marks the destination response.
SafeYolo made its route decision before this line appeared.”

Use these operator controls:

| Keys | Result |
| --- | --- |
| `C-a q` | Show large pane numbers for three seconds. |
| `C-a e` | Mark the exact evidence fragment in its source pane. Press again to clear it. |
| `C-a E` | Open the current explanation in a popup. Press any key to close it. |

Evidence marking uses tmux copy mode in the source pane. It does not change
focus or rewrite output. It can pause the visible position of a pane while new
output continues behind it. Use it after a command stops or when the operator
deliberately asks to inspect a stable point. The clear action exits only a copy
mode that the lab itself opened. It does not take ownership of an operator's
existing copy mode.

The explanation popup is operator-triggered because a native tmux popup takes
keyboard focus until it closes. It shows only the annotation fields. It does
not scrape surrounding output automatically.

Clear a stale note before the pane changes purpose:

```bash
"$annotator" --pane "$lab_pane" --clear
```

The border and rail are concise pointers, not the full lesson. Put detailed
reasoning in the controller or the dedicated lesson pane. Pin the shortest
evidence fragment that uniquely identifies the observation. Never put
credential values or transient login material in an annotation.

When a command returns several related records, the rail cannot explain all of
them at once. Keep the raw records in the source pane and render a compact
teaching view immediately after them. Give each item an `observed` line and a
`meaning` line. Use the rail to mark only the item currently under discussion.

## Observe without replacing the shell

Inspect current and retained output with:

```bash
tmux capture-pane -p -t "$lab_pane" -S -
tmux display-message -p -t "$lab_pane" '#{pane_dead} #{pane_pid} #{pane_current_command} #{history_size}'
```

Do not use `pane_current_command` alone to decide whether a wrapped renderer is
alive. A cleanup helper can remain the foreground process-group leader, so
tmux reports `bash` while its Presenterm child is visibly active. Combine the
rendered screen, the process tree, pane-local lesson state, and an explicit run
marker as the experiment requires.

Long-running commands should remain in the target pane. Poll or capture them
briefly from the controller so the operator continues receiving progress
updates. Do not use an unrelated detached poller as a substitute for a tool
call that must return through the coding harness.

Continuous `pipe-pane` logging is useful only when the pane will not display
credential material. Start it after interactive login, or stop it before login
and restart it afterward.

## Close panes deliberately

Prefer a normal shell exit when the pane contains only an interactive shell:

```bash
tmux send-keys -t "$lab_pane" -l -- 'exit'
tmux send-keys -t "$lab_pane" Enter
```

Use `tmux kill-pane -t "$lab_pane"` only when teardown was authorized and a
normal exit is inappropriate or stuck. Resolve explicit pane IDs immediately
before bulk closure, exclude `TMUX_PANE`, and verify the survivors afterward.

Closing an observer or agent-shell pane may terminate that attachment while
the underlying worker or service continues. Report those as separate states.
