# Share a guest web service

Use this workflow when the operator wants to open an HTTP service running
inside an agent in their own browser, locally or through a tailnet. A guest
web server does not require a guest browser, Xvfb, VNC or noVNC.

## Preserve the actual target

Start from the requested app, guest port and audience. If you started the app
in this sandbox, treat it as your own service. Confirm an uncertain agent name
from `/safeyolo/agent-name`; read only needed identity/run fields from
`/safeyolo/host-launch-context.json`. Do not send the operator through a
peer-support grant to work on your own app.

Keep these addresses distinct:

| Address | What it reaches |
|---|---|
| `127.0.0.1:8765` from inside your guest | The app on guest port 8765 in this example. |
| `127.0.0.1:PORT` from the owning host | A listener on that host; it does not automatically reach the guest's loopback. |
| The published HTTPS tailnet URL | The route the operator needs from their tailnet device. It is not established by a successful guest-local request. |

Use the existing process, saved configuration and permitted local checks to
verify the app. Preserve the operator's requested audience and any known
sharing lifetime. Do not install a desktop, move the app to another agent,
replace its authentication or widen its listener just to obtain a preview.
Do not change an accepted audience to a narrower one merely because another
example uses it.

## Select a supported publication path

Check the installed capability and command vocabulary for sharing the selected
guest web port. Use an existing authorized route when it provides that effect.
If the owning host must act, prepare its actual supported command with the
known instance, your agent name, app port and audience. Discover host command
syntax on the owning host or from the matching installed documentation; the
guest need not have the host CLI.

Do not confuse these different facilities:

- `desktop.present` and host `agent present` expose the graphical desktop.
  The `desktop.present` action's `browser_url` opens a browser inside the guest.
  It does not select a web-server port to publish to the operator's browser.
- Peer support grants permit their selected inspection, guest administration
  and lifecycle work. They do not publish a web port to the operator.
- A sandbox service provider is a configured service-gateway backend. Its
  ability to connect to a guest port does not itself supply a browser URL.
- A host-to-guest stream function in source code is transport plumbing, not
  proof of an installed publishing command or authority to run a host forward.

### Current native gap

The native command implementation accompanying this reference exposes desktop
presentation with a fixed guest port of 6080. It has no general command or
typed operator action for publishing an arbitrary guest HTTP port. The earlier
Python `agent preview` workflow supported that use; the historical preview
design is not a current command reference. Check a newer installation's actual
help and schemas before claiming that this limitation still applies there.

When this gap blocks the task, say so as a specific product limitation. Report
what you verified locally, retain the app and its state, and identify the
missing host publication for the exact agent, port and audience. The corrective
work is tracked in [the CLI migration release blocker](https://github.com/craigbalding/safeyolo/issues/1716).
Do not prescribe the retired command, install graphical packages or label
desktop presentation as the requested web-service result. A configured,
separately authorized host-operation route may be used if it actually supplies
the requested publication; do not invent that capability or its command.

For example, if the current agent is `web-worker`, its app is verified on port
8765, and this native gap is confirmed, the useful handoff is:

> My app is running in this sandbox on port 8765. This SafeYolo build is missing
> direct web-port sharing. The remaining step is a host-owned route for
> web-worker:8765 to your tailnet. There is no published URL yet.

Include a concrete command when the installed version or an existing adopted
host operation supports one. Keep an unsupported command out of the handoff.

## Verify the operator's result

Once a supported route is active, distinguish local app health, host-to-guest
reachability and an actual request from the operator's device. Check the
application's login/navigation and WebSocket or streaming behavior when used.
Do not claim completion from a listening port, an approval receipt, a generated
URL or a guest-local health check alone. Preserve the route's existing access,
audit, expiry and cleanup behavior, including unrelated tailnet mappings.
