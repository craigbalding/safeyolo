# Build a tiny app with Demo

On a prepared Ubuntu host, run `safeyolo demo` as the ordinary account that
owns your SafeYolo installation. Complete the [installation and guest
prerequisites](native-policy.md#guest-prerequisites) first. The installed command
uses your default installation automatically. Demo uses Codex and its normal
model access; no new API key is required. Your policy must permit that model
access. Copying a login does not grant network or credential permission; see
[credential approval](native-credentials.md#authorization-binding-and-risk-approval)
if the proxy reports that prerequisite. Missing tools are installed through
the guest's existing mise path and network policy.

```sh
safeyolo demo
```

Choose **1: build and run a tiny web application**. Demo creates an empty
disposable workspace and its own guest. If your host has a configured Codex
login, Demo offers to copy that login privately into this guest. Accept only
if you want the Demo agent to use that account. The source login stays intact.
Alternatively, select an already authenticated, stopped guest with
`--agent NAME`, or use the offered device login. Demo checks actual login
status before starting the task. It does not adopt a running guest.

The agent writes and runs a small app that summarizes an owned JSON service.
Its first request needs network approval. Demo shows the real pending request,
the selected agent and host/port, and the retained traffic result when
available. The fixture has received no requests at that point.

At the decision prompt, enter `evidence` to read traffic, `approve` to allow
the request, `reject` to refuse it, or `cancel` to stop. These actions use the
normal operator approval owner. Approval permits reusable access by this
agent to the fixture's host and port until Demo removes that permission.
It does not grant permission to other agents or authorize credential use.

After approval, the agent retries. Demo independently reads the running app
through the existing guest transport and compares its result with the owned
fixture's request record. The expected response has `title: Demo tasks`,
`count: 3`, `total_minutes: 20`, and the same marker printed for this run.
The output labels these observations separately from their interpretation.
Enter to finish after reading the result. Lab, tmux and a public preview
are not needed.

Demo stops its guest, closes its fixture listener and removes the fixture
permission on success, cancellation and ordinary failure. The default also
removes the disposable files and a newly created guest home, including its
copied login. An existing selected guest keeps its home and prior workspace
setting. Other agents and a pre-existing proxy stay in place.

If you want to inspect the generated files afterwards, use
`safeyolo demo --keep` before starting. The guest still stops and its fixture
permission is removed. Demo prints the retained workspace and guest name. `--workspace PATH`
selects an empty directory you own; without `--keep`, Demo removes files
created there. Existing project files are refused and preserved.

For a provisioned account whose login file is elsewhere, use `--auth-file FILE`
to select that existing `auth.json` explicitly. Demo copies it only into
a stopped guest with no login, with private file permissions. It never prints
credential content or replaces an existing login. See `safeyolo demo --help`
for all options.

If a prerequisite or harness fails, Demo reports that failure and performs
owned cleanup. A cleanup ownership mismatch preserves the affected files and
prints their paths for diagnosis. Fix the named problem before a fresh retry.
Model narration, a saved configuration, or a successful process exit alone
does not establish the app result.
