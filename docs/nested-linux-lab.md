# SafeYolo-in-SafeYolo Linux Lab

Use the native Lab workflow to compare an owned request before and after a
change to an inner instance's policy. The outer SafeYolo remains the security
boundary. Lab retains the controller, experiment files and evidence when you
exit its viewer.

## Start the Lab

Run the following command on an Ubuntu host as the account that owns the
workspace. Use an [installed native instance](native-policy.md#install-and-start)
with its prepared Ubuntu rootfs, runsc and Lab assets. Select the supported
systrap runtime through the normal host setup. The Lab guest needs Bash, tmux,
flock, curl and mise. The workflow prepares Codex in that guest and checks its
own normal authentication before starting the controller.

In this example, `/srv/lab-outer` is that installed instance and
`/srv/experiment` is an existing workspace owned by your account. Lab reuses
the installed Linux CLI and proxy as inner inputs. These inputs do not share
writable state or authentication with the inner instance. Lab copies only those
two executables into its read-only guest share; it does not mount an outer
instance's tokens or policy.

```sh
/srv/lab-outer/bin/safeyolo --root /srv/lab-outer lab \
  --workspace /srv/experiment \
  --objective 'Compare the same owned request before and after a narrow policy change'
```

Lab provisions its owned agent and opens the persistent Codex controller.
Supply any missing normal Codex login outside the experiment panes. The
controller receives the objective and proposes the smallest experiment before
changing policy. No guest-shell command or pane discovery is needed to enter
the Lab. See the [Lab entry](../cli/README.md#lab) for retention, recovery and
teardown choices.

To select a different prepared Linux build, add `--nested-assets PATH`. That
directory must contain `bin/safeyolo` and `bin/safeyolo-proxy` for the guest's
architecture, at the same source commit and profile. A missing or mismatched
input reports failure and retains the Lab for repair.

## Inner instance and outer boundary

The selected request experiment uses a fresh, proxy-only native inner instance:

```text
owned Lab request -> inner agent Unix socket -> inner native SafeYolo
                  -> outer proxy at 127.0.0.1:8080 -> owned HTTP destination
```

The controller uses the staged `prepare-nested.sh` helper. It initializes a
private instance under `$HOME/.safeyolo/lab-inner`, with a new instance identity,
tokens, certificate authority and policy. It configures the `lab-client` Unix
socket and saves `policy-original.toml` before any experiment change. It refuses
to overwrite a retained instance. The helper checks native CLI/proxy identities,
the inherited outer proxy URL and readable `SSL_CERT_FILE` before preparation.

The inner `config.toml` selects `parent_proxy = "http://127.0.0.1:8080"` and
Admin port `19090`. The inner proxy has no TCP request listener that could shadow
the outer proxy. The controller starts it through the native inner CLI and
sends the owned request through the configured Unix socket. This experiment
needs no second model or inner sandbox. All external traffic still traverses
the outer proxy; keep inherited proxy and certificate trust settings intact.

Each proxy adds an instance-specific Via token. Another instance's token can
pass through; a request returning through the same instance receives a `508`
loop block. The default is selected when the proxy starts. An explicit
`via_token` in the inner native configuration selects a different test token.

Bind one owned HTTP destination and a marker before the experiment. Observe
delivery with the initial policy. Ask the operator to authorize a deny for
that destination in the inner policy, then observe that the same request does
not deliver. Apply changes with the inner CLI's normal `policy check`,
`policy apply` and `policy show` commands. Restore `policy-original.toml` and
observe marker delivery again. Independently inspect destination records and
responses. Keep the outer policy unchanged and verify an outer control request
throughout. Process status and the controller's explanation do not prove these
effects.

Exit the viewer with `Ctrl-a d`, then run the same outer instance's `lab`
command without creation options. Lab selects the existing controller and
evidence. You can intervene in its ordinary persistent shell panes. Before
teardown, stop the owned inner proxy with its native CLI and verify that its
socket and process are stopped. Restore reversible faults and preserve useful
evidence before removing any explicitly selected experiment files.

## Experiments that also need an inner sandbox

The request experiment above does not require a rootfs build. An experiment
that launches another runsc guest needs the additional native host runtime
inputs and an unpacked rootfs. Use a guest-local filesystem such as `/var/lib`
for those nested guest images, source and state. Outer host mounts can use
VirtioFS, which cannot preserve the subordinate UID/GID `100000` ownership
required by rootless runsc. Keep any rootfs builder output on the same
guest-local filesystem. See the [guest build reference](../guest/README.md)
for its package floor, including rsync and e2fsprogs.

The maintained native host operations select the instance with `--root`.
Use `agent create`, `agent sandbox-start`, `agent shell` and `agent stop` for
an owned inner guest. `sandbox-start` boots without starting a coding model.
`start` and `stop` control the inner proxy separately from the guest. Stop both
before deleting that instance. Do not delete a retained NATS pidfile or signal
an unverified process.

Without systemd and a usable user bus, the Linux launcher runs runsc directly.
It reports that inner `MemoryMax` and `CPUQuota` controls are unavailable. The
outer sandbox still bounds the complete experiment. With a usable user manager,
the existing `systemd-run --user --scope` path remains active.

The broader `tests/nested-linux/acceptance.sh` lane retains the nested guest,
Agent API, loop and Coord checks. Its Python test/bootstrap tooling is separate
from the native Lab entry and from this finite request experiment. A source
test or a prepared Lab is not the installed Codex demonstration.
