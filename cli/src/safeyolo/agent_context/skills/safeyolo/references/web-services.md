# Guest browsers and service access

Choose the workflow from who needs access and where their browser or client
runs. Reuse the operator's stated intent. A service can have several approved
consumers; the choices below can coexist.

## Contents

- [Choose the consumer and access path](#choose-the-consumer-and-access-path)
- [Preserve the actual target](#preserve-the-actual-target)
- [Share with other agents through the gateway](#share-with-other-agents-through-the-gateway)
- [Publish for the operator](#publish-for-the-operator)
- [Verify the intended use](#verify-the-intended-use)

## Choose the consumer and access path

| Intended use | Path |
|---|---|
| Run a browser inside the guest, including webapp security testing | Use the guest browser. Follow the [desktop guide](desktop.md) when a graphical session or operator interaction with that browser is needed. |
| Let other SafeYolo agents call a service hosted in a guest | Use the existing service gateway, a sandbox-hosted service definition and the consuming agents' service permissions. |
| Let the operator reach a guest service through the host's localhost | Publish the selected guest port to a host loopback listener. A remote operator can use an existing SSH connection to forward that host listener. |
| Let the operator use a guest service over the tailnet | Publish the selected guest port through the host's tailnet route. |

A guest browser is a supported tool, including for remote websites reached
through the normal proxy and certificate configuration. Its desktop can be
presented locally, through SSH or over the configured tailnet route.
`desktop.present` opens that graphical session; its `browser_url` navigates the
guest browser. Select it when the task calls for that browser, rather than
assuming that every web-service consumer needs a guest desktop.

## Preserve the actual target

Keep the app, provider agent, guest port and intended consumers together.
If you started the app in this sandbox, it is your own service. When identity
is unclear, read `/safeyolo/agent-name` and only needed identity/run fields from
`/safeyolo/host-launch-context.json`. Ordinary work on your own app needs no
peer-support grant. Calling another agent's service uses service access;
administering that agent uses the separate support interface.

Distinguish guest loopback, host loopback and the operator's computer.
`127.0.0.1:8765` inside the guest does not name a host listener. Another agent
uses its service-gateway hostname and port, not the provider's loopback address.
Retain the requested audience, lifetime, application authentication and running
process. Install or configure only the components needed for the chosen use.

## Share with other agents through the gateway

This path is implemented. Reuse an accepted service definition and existing
caller permissions when available. To prepare a new provider:

1. Run the service on its intended port inside the hosting agent.
2. Prepare a service definition whose `name` matches that configured agent's
   name. Choose its logical hostname, capabilities and route methods/paths for
   the agreed service. The request destination supplies the guest port; there
   is no separate `provider: {kind, agent, port}` configuration table.
3. Have the existing host owner adopt the definition in the selected instance's
   configured operator service directory. `services check FILE` validates the
   prepared definition; it does not install it. Read `services show NAME` to
   confirm the running catalogue accepted it. A policy proposal alone does not
   install a new service YAML file.
4. Prepare the logical host-to-service mapping and each consumer's selected
   capability through the existing authorization or policy owner. Preserve the
   agreed network port scope, contract bindings and other applicable controls.
5. From the intended consumer, discover current access, request missing offered
   access through the [gateway workflow](agent-api.md#service-gateway), and fetch
   that consumer's own current token after adoption. Call the service's logical
   hostname and guest port through the consumer's existing proxy.

For example, an agreed read-only item API on agent `web-worker`, port 8765,
can use this credential-free definition:

```yaml
schema_version: 1
name: web-worker
default_host: web-worker.safeyolo.internal
capabilities:
  reader:
    routes:
      - methods: [GET]
        path: /api/items
```

After this definition is adopted and the applicable network permission is in
place, the selected owning host can authorize the existing agent `consumer`:

```sh
safeyolo services authorize consumer web-worker \
  --capability reader --host web-worker.safeyolo.internal:8765
```

Use the selected installation's command prefix. This maps the hostname and
authorizes the named service capability; it does not itself grant network
permission. Do not silently append `--allow-host-network`, which makes a
separate host-wide egress choice.

The consumer requests `http://web-worker.safeyolo.internal:8765/api/items` with
its own scoped gateway token. Without an upstream `auth` block, use the
`Authorization: Bearer` header; no upstream credential is injected. Never share
the provider's or another consumer's token. Verify the actual consumer's call.
A stopped provider or closed port does not fall back to ordinary network delivery.

The [service schema](https://github.com/craigbalding/safeyolo/blob/master/docs/service-gateway-v2-yaml-spec.md)
and [service authorization guide](https://github.com/craigbalding/safeyolo/blob/master/docs/credentials.md#authorization-binding-and-risk-approval)
describe the existing definition, adoption and permission owners.

## Publish for the operator

Use the requested host-loopback or tailnet route. Check the installed command
and capability vocabulary, reuse existing authority, and prepare the supported
host action with the selected instance, agent and guest port. Publishing the
HTTP service itself does not require a guest browser or desktop.

For **host localhost**, preserve the host-owned publication and its access
controls. The operator can connect on the host or carry that listener over
SSH from another computer. For example, after a supported publication has
created a host loopback listener on port 18765, an operator with an existing
SSH alias `sy-host` can run this on their own computer. Local port 18765 must
be available:

```sh
ssh -N -L 127.0.0.1:18765:127.0.0.1:18765 sy-host
```

Use the publication's browser URL with the forwarded endpoint. Retain any
hostname and port required by its origin routing. The SSH forward carries an
existing host listener; it does not create the host-to-guest publication.

For **tailnet access**, publish the selected guest service through the host's
configured Tailscale route and return its actual URL. Preserve the requested
audience and existing access, audit, expiry and cleanup behavior, including
unrelated Tailscale mappings.

### Supported human and agent-assisted publication

On the selected SafeYolo host, use the running agent's name and app port:

```sh
safeyolo agent publish builder --port 3000 --audience local
safeyolo agent publications builder
safeyolo agent unpublish builder --port 3000 --audience local
```

Select `--audience tailnet` for the host's existing Tailscale Serve route;
`--tailnet-port PORT` selects a free tailnet listener explicitly. The command
returns a clean browser URL and a separate one-time unlock code. Keep the code
private. Enter it in the browser before using the app's own login. Publication
retains the selected agent run, port and audience; it starts no desktop and
grants no network or service access. Ports 8080 and 9090 are reserved SafeYolo
plumbing. The default lifetime is 900 seconds; use `--ttl SECONDS` to select
another positive lifetime in seconds.
Stop with the same agent, port, audience and optional tailnet port. Stop,
expiry or a changed agent run disconnects only that publication. Unrelated
publications and Tailscale mappings remain.

From the agent, discover `GET /operator-actions` and request `web.publish`
through `POST /operator-actions` with parameters such as
`{"guest_port":3000,"audience":"local","ttl_seconds":900}`. This uses the
existing operator-action approval owner and binds the requesting guest's
current run; no peer-support setup is needed for its own app. Agent responses
contain the canonical request/result status. The URL and unlock code belong
to the operator, who can open the publication through the supported command.
Read the canonical result after a lost reply before submitting another request.

Host localhost can be carried over the operator's existing SSH forward as
described above. Tailnet requires the selected host's actual Serve authority.
Linux/gVisor and macOS VZ use their existing verified guest-port transports;
another backend reports its capability gap rather than falling back to a
different agent or audience. A published URL still needs an actual consumer
check; a local health response does not establish remote reachability.

## Verify the intended use

Use the actual consumer: the guest browser for a browser task, the authorized
calling agent for gateway sharing, or the operator's browser through the
selected localhost/SSH/tailnet route. Check login, navigation, callbacks and
WebSocket or streaming behavior when used. Local app health, an approval,
adopted configuration or a generated URL alone does not prove that result.
Report each requested route separately when some work and others remain blocked.
