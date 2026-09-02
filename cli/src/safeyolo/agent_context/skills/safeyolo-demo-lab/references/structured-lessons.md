# Structured terminal lessons

Use a structured lesson when the learner must connect commands, output, and
meaning across an ordered sequence. The lesson is a teaching surface. Tmux
remains the process and recovery surface.

## Keep the learner with the controller

Show the controller and one lesson pane. Keep support shells alive, but do not
require the learner to navigate to them. The controller advances the lesson
and runs its actions by default. The learner can press `F12` to enter the
lesson, use `Left` and `Right` to read at their own pace, then press `F12` to
return to the controller. Do not take focus while the learner is reading. The
learner can steer with natural-language requests at any time.

Use this page pattern when it fits the topic:

1. State the question.
2. Show the command or action.
3. Show the observed result.
4. Explain what the result means.
5. State what the evidence does not prove.
6. Offer one useful next question.

Keep each page about one claim. Put raw values and their explanation on the
same page when possible. Use stable terms and short sentences.

## Let the learner inspect the implementation

Show a short relevant source snippet on most explanation pages when source is
available and the code materially explains the observed behavior. Do not add
code to an orientation, action, raw-result, or recap page only to satisfy a
template. Keep one idea on each page and prefer approximately 6 to 20 relevant
lines. Explain the important branch beneath the snippet.

Introduce each snippet with the owning product component or addon and the
function, class, command, or configuration section that it shows. Do not make
the learner infer ownership from a file path.

Use Presenterm's external `file` snippet so the lesson reads the real file
instead of copying code that can drift:

````markdown
```file
path: /absolute/path/to/source.py
language: python
start_line: 40
end_line: 55
```
````

Show the actual source range as `file.py:40-55` beside the snippet. Do not add
Presenterm's `+line_numbers` to a sliced file: version 0.16.1 restarts those
numbers at 1 instead of using the real file lines.

Source code explains implementation semantics. It does not prove that the live
request took that path. Correlate it with runtime evidence before making that
claim.

When the learner can benefit from the full file, create
`LESSON.md.sources.tsv`. Use one reviewed row per source:

```text
SRC_EXAMPLE<TAB>Short label<TAB>/absolute/path/file.py<TAB>40<TAB>55
```

Put `[SRC_EXAMPLE]` and the visible `file.py:40-55` reference on the relevant
page. The learner presses `o`. If one registered source is visible, tmux opens
it directly at the first line. If several are visible, tmux first shows a
source menu. The popup reads the remote guest file, so this works through SSH
and nested tmux. Press `q` to close the source viewer.

Presenterm 0.16.1 renders a Markdown link as label and URL text. It does not
retain an interactive target or emit an OSC 8 hyperlink. Do not promise click
or Enter navigation. A `file://` link would also refer to the operator's local
terminal environment, not reliably to the remote guest.

## Create the first draft quickly

Use the lesson helper to create the consistent shell:

```bash
lesson_helper="/safeyolo/skills/safeyolo-demo-lab/scripts/lesson-helper.sh"
"$lesson_helper" new LESSON.md "LESSON TITLE" "SHORT SUBTITLE"
```

The helper refuses to overwrite an existing lesson. Edit the Markdown to
answer the learner's real question. Revise the page during the conversation
when the question changes; the live renderer will reload it.

For a controller-driven lesson, show the real command in an ordinary code
block. Run it in a persistent shell, then show its observed result on the same
page or the next page. Name the actor and use past, present, or future tense so
the learner knows whether the action is complete. Do not expose an opaque lab
wrapper as the main command when the ordinary command can be shown clearly.
Explain non-obvious options, filenames, and output labels beside the command.
Explain only what the learner needs to connect the action to its result.

Do not add Presenterm `+exec` by default. Its execution-state text, such as
`Not started`, describes the renderer rather than the experiment. It can make
the learner think that they must start an action. Use `+exec` only for an
explicit hands-on exercise. In that case, say that the learner will run the
command, give the exact key, and state the expected result. Use “command” or
“exercise,” not the renderer term “cell.”

The helper also creates `LESSON.md.questions.tsv`. Add a short stable ID and
one reviewed question per line, separated by one tab. Put the corresponding ID
beneath the material in the lesson:

```markdown
**Questions you might ask**

- `[REQUEST_ID]` Why is the request ID useful?

Press `q` to choose a question.
```

Keep the visible prompt short. The registry supplies the exact message that
reaches the controller. Add sample questions only where they help the learner
connect the evidence to a useful next question.

Do not turn every chat answer into a page. Use the controller conversation for
dialogue, clarification, short answers, and steering. Create a page when
layout, sequence, comparison, or retained evidence will materially help.

## Use Presenterm as an optional renderer

Presenterm is a useful renderer for a trusted Markdown lesson. It is optional;
the lesson source must remain useful as plain Markdown. Run the helper in a
persistent interactive shell pane:

```bash
"$lesson_helper" install-renderer  # Run once when Presenterm is absent.
"$lesson_helper" run LESSON.md
```

The installer selects the pinned Presenterm 0.16.1 release for Linux ARM64 or
x86-64 and for glibc or musl. It verifies the published SHA-256 digest and
installs only to `$HOME/.local/bin`. It refuses to replace an existing file or
a different Presenterm on `PATH`. The download uses the normal SafeYolo proxy
and policy path. State that persistent user tool installation will occur before
you run it. Do not install the renderer when plain Markdown is sufficient.

Use `ascii-blocks` in remote or nested tmux. This avoids unreliable terminal
graphics detection. Validate the lesson at the current pane size. Fix an
overflow instead of relying on clipping. Presenterm reloads a changed Markdown
file while it runs.

Enable command execution only for a lesson source that the controller created
or reviewed. Use it only for a clearly labelled hands-on exercise. The learner
only needs the controls shown in the lab status line:
`Left` and `Right` for pages, `o` for a registered source file, `q` for
questions, and `F12` for the controller.
Give the lesson pane focus for its first render if terminal negotiation needs
it, then return focus to the controller.

## Keep process state in tmux

Use an inline executable command only for a short, bounded hands-on exercise.
Keep these actions in separate persistent shell panes:

- interactive login;
- a long wait or service;
- a fault target;
- a command whose parent shell or exact process state is evidence; and
- an action that can display credential material.

Bring selected safe evidence from those panes into the lesson page. Keep the
raw pane available for inspection. A renderer's `finished` label is not an
authoritative exit status. Record the command exit code or structured product
result when it matters.

## Preserve the lesson

Keep the Markdown, reviewed helper scripts, and selected evidence in the lab
workspace when the operator wants a reusable lesson. Record tool versions and
renderer options. Do not copy credentials into the page or its execution
state. Show ordinary website content, request identifiers, policy effects,
addon outcomes, and other relevant non-credential evidence in full.
