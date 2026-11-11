# Docker management

Configure a Docker Engine endpoint as a service, then use ordinary Docker and
Compose commands inside the agent. SafeYolo checks the current gateway capability
before forwarding each management request. Exec and attach switch only the
admitted operation to a raw input/output stream.

Whole-environment workload management preserves existing resource names and other
administrators. It permits supported operations across the selected daemon,
subject to the adopted host-file and privilege bounds. It does not grant
unrestricted daemon administration or project isolation. Configure a separate
service for each endpoint; workloads need no SafeYolo naming convention or label.

The external lifecycle witness passed with Docker CLI 29.1.3, Compose 2.40.3
and standalone Linux Engine 29.1.3, using Engine application programming
interface (API) 1.45 and classic builds. API request shapes derive from Moby
26.1.5 with the captured current-client defaults described below. That source
version does not establish external Engine 26.1.x qualification. The nested
runtime has separate Docker 26.1.5 and Compose 2.26.1 evidence in
[nested Docker](nested-docker.md). The
[nested provider Compose result](../contrib/docker/proof.md#nested-provider-compose-lifecycle)
records the gateway lifecycle and its continued recovery and teardown.
Independent transport and internal management acceptance remains tracked in
[#1437](https://github.com/craigbalding/safeyolo/issues/1437).

The [independent operator walkthrough](../contrib/docker/proof.md#independent-operator-walkthrough)
passed public onboarding, coadministration and the seeded host-consumer
mitigation with the same client and Engine versions. See the
[observed results and limits](../contrib/docker/proof.md#reuse-the-observed-result).
Lens accepted project support at
[#1439's recorded candidate and runtime limits](https://github.com/craigbalding/safeyolo/issues/1439#issuecomment-6723464950).
Route lists and Compose project names alone do not establish project isolation.

## Choose the execution authority

Before approving access, choose the environment the agent will control:

| Environment | Authority delegated |
|---|---|
| External Engine with `workloads` | Supported workloads and existing resources within the adopted bounds. Workloads, builds and daemon fetches use the remote environment's networking. They may reach the internet, private services or the SafeYolo host when reachable there, including services the requesting agent cannot reach directly. SafeYolo does not enforce the requesting agent's network policy on that execution. |
| Docker inside a SafeYolo sandbox | Workloads use the **hosting** sandbox's policy and network authority. Broad `sandbox_admin` access can reach its workspace, credentials, explicit host mounts and other inner workloads, including through privileged inner containers. It does not grant outer-host privilege or project isolation. See the demonstrated Linux/gVisor configuration in [nested Docker](nested-docker.md). |

A dedicated project sandbox is an option when its entire authority should match
the delegation. Existing external environments can stay in place. Review their
host-file consumers and network reach before granting access. Direct access to
other daemon sockets or network endpoints from a workload would bypass these
management-request checks; inspect those paths too.

## Operator setup

Start with an existing running SafeYolo instance, an agent such as `alice`, and
an operator-managed authenticated Engine endpoint. Inspect the environment using
the [read-only commands](#inspect-the-environment-before-approval) before choosing
host-file bounds. Keep that inventory with the operator.

For an external daemon, use an authenticated HTTPS endpoint with a certificate
that identifies the endpoint. One supported arrangement is an operator-managed
TLS reverse proxy with bearer authentication in front of the daemon's private
socket. Keep upstream administrative credentials and daemon client keys on the
operator side. Configure SafeYolo's
[upstream CA trust](TLS_CERTIFICATE.md#additional-upstream-trust) for a private CA;
do not disable certificate verification. Close unauthenticated alternative access
to that daemon at the endpoint.

The endpoint must preserve both directions of Docker's upgraded TCP streams.
Closing stdin must still permit remaining stdout and stderr. An HTTP 101
response alone does not establish this behavior for a TLS reverse proxy.

Prepare `docker-external.yaml` from the [service definition](../contrib/docker/service.yaml)
in an operator-owned directory outside the watched catalogue. Set its service
name, `default_host` and `docker.endpoint` to the selected endpoint. The endpoint
is an HTTPS origin without credentials, path or query. The default hostname and
authorized host mapping must equal its hostname. Retain
`docker.execution_boundary: external` for an external daemon.

The `workloads` capability uses `docker_access.mode: workloads`. Its default
`bind_mounts: []` permits no host-file bind mounts. To delegate a useful file
exception, the operator adds exact absolute sources and their write bounds to
the adopted capability. Service authorization shows those enforced bounds and
states that all supported creation arguments within the bounds remain available.
The authorization is broader than approval of one attempted payload. Routine
resource identifiers need no separate approval.

```yaml
docker_access:
  mode: workloads
  bind_mounts:
    - source: /srv/project-data
      read_only: true
```

The example permits that source with read-only access in both Docker mount
encodings. It does not permit another source or write access. Known daemon
socket and system paths, shared mount propagation and host security relabeling
are unsupported. The operator must inspect site-specific host consumers and
symlinks before authorizing a file source. The [host-consumer checks](#check-indirect-host-authority)
explain why an ordinary file mount can still delegate host authority.

In the operator terminal, the following commands use the default installed
instance at `$HOME/.safeyolo`, the prepared file in the current directory, and
the example agent `alice`. Substitute your instance, agent, service and credential
names. Copy only after `services check` succeeds; wait until `services show`
reports the adopted endpoint and bounds. The commands activate a definition,
store the endpoint bearer without terminal echo, and grant the capability.
Choose an unused credential name: adding the same name replaces its value.
`--allow-host-network` also permits host-wide network access to the endpoint
hostname; service authorization remains specific to the selected agent.
`services authorized` contains a gateway token; keep its output private. The
first secret write asks for local random-key or passphrase-protected storage.
For storage selection, unlocking and credential-policy approvals, use
[credentials and service access](credentials.md).

```sh
safeyolo services check docker-external.yaml
cp docker-external.yaml "$HOME/.safeyolo/data/services/docker-external.yaml"
safeyolo services show docker-external
safeyolo credentials add docker-endpoint
safeyolo services authorize alice docker-external --capability workloads --credential docker-endpoint --account operator --allow-host-network
safeyolo services authorized alice
```

For another catalogue layout, use its configured operator service directory.
After catalogue activation, the agent
fetches its own current token and verifies the client connection below.

For agent-initiated authorization, use the existing authenticated Agent API
`POST /gateway/request-access` with the chosen service, capability and reason.
The operator reads the canonical request with `approvals show` and
`approvals explain`, reviews its displayed Docker authority, then selects an
offered option. That approval covers every supported argument within the
adopted bounds. It does not approve only the example payload.

### Docker inside a hosting sandbox

Use the existing [sandbox-provider service route](credentials.md#authorization-binding-and-risk-approval).
The service name selects the hosting agent. Set `docker.endpoint` to that
provider's configured HTTP port and `docker.execution_boundary` to `sandbox`.
Omit `auth` when the provider needs no upstream credential. Bind the inner
Engine's HTTP listener, or a TCP-to-socket relay, to guest loopback. Authorize
the caller for the Docker capability through the existing service workflow.
The caller still connects to SafeYolo's proxy; the provider route opens the
selected port inside the hosting sandbox. The [internal management check](../contrib/docker/proof.md#internal-docker-management-connection)
remains separate from installed containment qualification.

For broad administration of an entire qualified inner Docker environment, the
operator may create a separate capability with `docker_access.mode: sandbox_admin`
and `docker.execution_boundary: sandbox`. This authority includes privileged
inner workloads, the provider workspace, credentials, explicit host mounts and
other inner workloads. The authorization displays that authority. Use a dedicated
project sandbox when its entire authority should match the delegation. A narrow
project route list does not narrow host-file authority in this administration
mode. Use the workload mode for narrower host authority. The loader refuses
`sandbox_admin` for an external execution boundary.
Request bodies and headers cannot change the adopted execution boundary. The
definition, adoption and service directory remain operator controlled.

## Select one project

Lens accepted project mode under
[#1439](https://github.com/craigbalding/safeyolo/issues/1439#issuecomment-6723464950),
including the supported lifecycle, cross-project refusals and management metadata.
The following configuration documents that behavior within the recorded limits.

On the operator host, use the existing authenticated Docker connection to inspect
resources before adopting the project capability. Select containers and networks
by their full `Id`, images by their full `sha256:` ID, and volumes by their
ordinary name and inspected `CreatedAt`. No rename or ownership label is required.
Include the selected containers' image, network and volume dependencies. Put a
dependency under `shared` when the agent may use it but may not remove it.

In the adopted service definition, replace the workload capability's
`docker_access` block with the following example. Replace every uppercase ID
placeholder and the example volume timestamp with the inspected values. The
project `name` identifies this delegation; it does not select Compose labels.
Use the same project name and selections for agents that share this delegation.
Keep the existing endpoint, routes, service adoption and authorization workflow.

```yaml
docker_access:
  mode: project
  name: nextcloud
  adoption: operator-selection-1
  bind_mounts: []
  selected:
    containers: [FULL_CONTAINER_ID]
    networks: [FULL_PROJECT_NETWORK_ID]
    volumes:
      existing-data: '2026-11-07T01:02:03Z'
    image_names:
      'nextcloud:production': 'sha256:FULL_IMAGE_ID'
  shared:
    networks: [FULL_SHARED_NETWORK_ID]
    images: ['sha256:FULL_SHARED_IMAGE_ID']
```

For a new project, omit `selected`. Approve any existing dependencies under
`shared`, then use the agent setup below. Compose may create project containers,
networks and volumes without separate identifier approvals. The gateway records
those creations before reporting success. Client names and Compose labels do not
establish membership. Mutable image references resolve to inspected content IDs
before container creation. To permit updates to an existing image tag, select
that reference and its current image ID under `selected.image_names`.

Project mode permits the supported container lifecycle, exec, file transfer,
explicit image pulls and Compose deployment with prepared images. It refuses
classic builds because a build context can refer to arbitrary daemon images.
Workload mode retains classic builds. Use an explicitly delegated entire
Docker environment when builds need that authority. Prune and unsupported
endpoints remain refused. Shared container references permit namespace or volume
use after their dependencies are checked. They do not permit direct container
management. Shared networks and volumes can be inspected for client compatibility; unrelated attachments and labels are removed. Shared
images can be used without granting image deletion or replacement of their tags.
Only project containers may be connected to or disconnected from a network.

After authorization, use `docker compose up -d` with the project's Compose file.
Inspect the project and read its logs. An unrelated container inspect receives
the same generic refusal as an unknown identifier. Lists and Docker-generated
management records contain project resources and selected compatibility facts.
Volume events are omitted because they identify volumes by reusable names.
Workload logs, copied files and exec output retain their ordinary content; they
are not sanitised for arbitrary external facts.

Container, network, image and returned exec identity checks survive gateway
restart. Created volumes have gateway-generated markers bound to recorded
creation effects. For selected existing volumes, the gateway checks `CreatedAt`
and continuity in retained daemon events. A missing event anchor or observed
replacement requires explicit re-adoption. This includes event-history eviction
or reset. To re-adopt, inspect the actual resources and any interrupted effects,
update the selected identities, choose a new `adoption` value, and adopt the
definition again. Superseded adoption values cannot re-adopt uncertain state.
Do not increment that value merely to retry an uncertain mutation.

An interrupted creation leaves a durable intent. The next dependent request
reconciles marked resources or the exec parent's current state without replaying
the operation. An uncertain image pull needs explicit operator re-adoption.
`GATEWAY_DOCKER_OUTCOME_UNKNOWN` and
`GATEWAY_DOCKER_RECONCILIATION_REQUIRED` do not mean rollback. Other lifecycle
operations inspect current resource state before each dependent request.

Docker cannot atomically inspect and mutate resource references. Another trusted
administrator can change a volume name or image tag during that interval.
This interface does not protect against a malicious trusted daemon administrator.
External execution and networking retain the boundary described above; nested
workloads retain the hosting sandbox's authority. Project membership does not
impose aggregate limits on processor use, memory or disk space. Resource use and
network reach still depend on the daemon and workload configuration. The
[project Engine/Compose witness](../contrib/docker/proof.md#reuse-the-observed-result)
has independent acceptance at
[#1439's recorded revision](https://github.com/craigbalding/safeyolo/issues/1439#issuecomment-6723464950).

## Agent setup

[Docker's exec/attach dialer](https://github.com/moby/moby/blob/v26.1.5/client/client.go#L390-L410)
bypasses `HTTP_PROXY`. Set `DOCKER_HOST` to the existing
plain HTTP proxy's host and port, using Docker's `tcp://` scheme. For example,
`HTTP_PROXY=http://10.0.2.2:3128` means `DOCKER_HOST=tcp://10.0.2.2:3128`.
Preserve the proxy and certificate environment. SafeYolo selects and verifies
the separately configured upstream endpoint.

Discover the agent's services through authenticated Agent API
`GET /gateway/services`. Read the returned `authorized` entry for the service
privately; its `token` is the scoped gateway token, not the daemon credential.
If the service is only `available`, request its capability through
`POST /gateway/request-access` and wait for the operator's decision. Follow the
[Agent API authentication instructions](../cli/src/safeyolo/agent_context/skills/safeyolo/references/agent-api.md).
Do not print tokens or put them in command arguments.

Prepare a private Docker configuration directory dedicated to this service
(directory mode 0700, file mode 0600). In its `config.json`, replace the service
name and gateway-token placeholder below. Fetch and replace the token after
catalogue activation or proxy restart; an old token may no longer work. Do not
reuse a registry-login configuration containing unrelated credentials.

```json
{
  "HttpHeaders": {
    "X-SafeYolo-Docker-Service": "docker-external",
    "Authorization": "Bearer CURRENT_GATEWAY_TOKEN"
  }
}
```

In the agent terminal, replace the directory and proxy address with those prepared
values. These settings affect Docker commands in this terminal. Select the
Engine's classic build API; BuildKit sessions and additional Buildx drivers are
unsupported. Clear conflicting Docker context and client TLS settings in this
terminal before selecting the gateway connection.

```sh
unset DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH
export DOCKER_CONFIG=/path/to/private-docker-config
export DOCKER_HOST=tcp://10.0.2.2:3128
export DOCKER_API_VERSION=1.45
export DOCKER_BUILDKIT=0
export COMPOSE_DOCKER_CLI_BUILD=0
docker version
docker compose version
```

`docker version` should identify the configured daemon and API 1.45. If access
fails, inspect the current token and permissions before making a mutation.

## Routine agent work

In the same agent terminal, enter the project directory containing the operator's
selected Compose file. Review its images, mounts, ports and external effects
before starting it. Use the project's existing Compose name and service names.
Replace `SERVICE` below with a service that provides `sh`. These commands may
fetch or build images, start remote workloads and change persistent daemon resources:

```sh
docker compose config --services
docker compose up -d
docker compose ps
docker compose logs --tail 30
docker compose exec SERVICE sh -c pwd
docker compose restart SERVICE
docker compose stop
docker compose start
docker compose down
```

Expect the declared services to run and communicate in the remote environment.
Named volumes survive `down`; `down --volumes` deliberately deletes the selected
project's volumes. Daemon-wide prune is unsupported.
Existing non-Compose containers can be inspected and managed by their unchanged names.
Other administrators retain their normal access. For a container that exceeds
the adopted bounds, ask the operator to inspect its configuration rather than
renaming or relabelling it to try to obtain access.

## An occasional build exception

The supplied broad workload capability already includes classic builds. An
operator may instead adopt routine routes that omit `POST /v1.45/build`. In that
configuration, an infrequent custom-image build can use the existing
[temporary route approval](service-route-approval.md). An explicit denial or a
Docker host-authority refusal cannot be overridden by that route grant.

When `docker build` returns `GATEWAY_ROUTE_CHALLENGE`, the build has not reached
the daemon. Read the recorded scope and assessment. Prefer an already available
image if it satisfies the task. If a custom build is necessary, explicitly
escalate that challenge with the task, source, reason and why the image alternative
is insufficient. The operator inspects the canonical approval before selecting
its finite `run` option; the agent then retries explicitly.

The grant covers that run, service, credential binding, method and literal path.
It is **not** approval of one Dockerfile, image tag, build context or set of build
arguments. Builds execute code and fetch inputs using remote network authority.
The adopted `workloads` checks, daemon-default checks and file bounds still apply;
the grant cannot enable host networking, privileged execution or a forbidden bind
source. The approval's Docker authority reports those enforced bounds.

Expiry or revocation prevents future uses of the exception. It does not remove
images, undo file writes, stop existing containers, erase volume data or cancel
an already admitted operation. Inspect the result before any retry or cleanup.

## Inspect the environment before approval

Run these read-only commands in the **operator's** Linux terminal with Docker,
GNU `xargs` and `jq`. Replace `EXISTING_CONTEXT` with an existing operator Docker
context for the selected daemon. The export selects that context only in this
terminal; it creates no context or resource. Keep output private: paths, volume
options, port mappings and credential locations can be sensitive. Do not hand a
project-limited agent the whole daemon inventory.

```sh
export DOCKER_CONTEXT=EXISTING_CONTEXT
docker context ls
docker context inspect "$DOCKER_CONTEXT"
docker version
docker info --format '{{json .}}' | jq '{OSType, DefaultRuntime, LoggingDriver, SecurityOptions}'
docker ps -aq | xargs -r docker container inspect | jq '.[] | {
  name: .Name, mounts: .Mounts, binds: .HostConfig.Binds,
  privileged: .HostConfig.Privileged, capabilities: .HostConfig.CapAdd,
  security_options: .HostConfig.SecurityOpt, runtime: .HostConfig.Runtime,
  devices: .HostConfig.Devices, device_requests: .HostConfig.DeviceRequests,
  network: .HostConfig.NetworkMode, pid: .HostConfig.PidMode,
  ipc: .HostConfig.IpcMode, uts: .HostConfig.UTSMode,
  userns: .HostConfig.UsernsMode, cgroupns: .HostConfig.CgroupnsMode,
  cgroup_parent: .HostConfig.CgroupParent, volumes_from: .HostConfig.VolumesFrom,
  ports: .NetworkSettings.Ports,
  environment_keys: [.Config.Env[]? | split("=")[0]]
}'
docker volume ls -q | xargs -r docker volume inspect | jq '.[] | {Name, Driver, Options, Mountpoint}'
```

The container output includes stopped containers and effective mount sources,
destinations and write modes. Follow named volumes into their driver/options
output; a `local` volume can itself expose a host path. Check socket mounts even
when the socket has an unusual name. Environment keys help locate relevant
credentials without printing their values. Inspect the selected containers'
secret files and application configuration privately as needed.

On the **daemon host**, use its existing operator account to inspect listening
sockets and endpoints. If that host uses the standard systemd Docker units and
`/etc/docker/daemon.json`, these additional reads show launch arguments, socket
configuration and TLS paths. A missing file/unit or a denied read leaves that
part of the inventory unknown; it is not a clean result.

```sh
ss -lntx
systemctl show docker.service -p ExecStart -p EnvironmentFiles
systemctl cat docker.socket
jq '{hosts, tls, tlsverify, tlscacert, tlscert, tlskey, authorization_plugins: ."authorization-plugins"}' /etc/docker/daemon.json
```

Check the actual reverse-proxy configuration and other daemon launch methods
when the site uses them. Confirm who can reach each socket/TCP endpoint, which
authentication it requires, and whether workloads can reach another daemon API.
Context inspection reports endpoint and client TLS paths, not every server-side
listener. For the operator's actual Docker client configuration file, the
following read shows registry names and credential-helper names without values.
The example uses `$HOME/.docker/config.json`; use the selected `DOCKER_CONFIG`
directory if different.

```sh
jq '{registries: ((.auths // {}) | keys), credsStore, credHelpers, header_names: ((.HttpHeaders // {}) | keys)}' "$HOME/.docker/config.json"
```

Review permissions and consumers of mounted credential files, TLS keys,
environment files and CI secrets. Keep upstream credentials outside agent-visible
paths. A registry list or environment-key list does not find every credential.

### Check indirect host authority

[Docker bind mounts refer to the daemon host](https://docs.docker.com/engine/storage/bind-mounts/),
and writable mounts can change files used by non-Docker host processes. For each
proposed source, resolve symlinks, check nested mounts and permissions, and ask
who reads, executes, imports or publishes its contents. Use the daemon host's
`namei -l`, `findmnt -T` and `stat` with the actual source path; inspect the
relevant scheduled jobs, service configuration, CI jobs and deployment steps.

| Indirect path | Operator check and practical mitigation |
|---|---|
| A writable script or configuration is executed/loaded by a host account | Find the host consumer and the identity it runs as. Keep its executable/configuration source outside the writable mount, or give the container read-only access. For generated output, require operator review before a separate copy becomes executable or active configuration. Changing an extension or container label does not remove the consumer. |
| A readable mount contains credentials or sensitive files | Check file contents and permissions privately, including hidden files and subdirectories. Exclude the sensitive files or provide a dedicated export containing only the intended data. Read-only mounting prevents writes, not disclosure or use of a credential's authority. |
| A host process parses, builds, deploys or publishes agent-controlled data | Check the actual consumer, including symlink traversal and code/configuration hooks. Keep consumption in a sandbox where possible, or review and copy the required data into a separate operator-controlled location before consumption. Removing a mount does not remove copies already consumed. |

The [Docker daemon security guidance](https://docs.docker.com/engine/security/)
explains the direct authority of raw daemon access. The gateway bounds known
direct Docker routes; it cannot discover arbitrary host consumers, hidden
credentials, future automation or every network privilege path. Inspection is a
point-in-time operator check. A clean inventory does not certify absence of a
host-privilege path. Repeat the affected check when a mount or consumer changes.

## Supported operations

The capability must permit each method and path in addition to transport support.
Unversioned discovery is limited to `/_ping` and `/version`. Other API versions
and unversioned management requests fail with `GATEWAY_DOCKER_OPERATION_UNSUPPORTED`.

| Operation | Transport |
|---|---|
| Compose create/up, update/recreate and down | Container, network and volume HTTP requests |
| Build and pull | Engine `/build` tar upload and `/images/create` response stream |
| Inspect, list, events, logs/follow, top and stats | HTTP response streams |
| Exec and interactive attach | HTTP 101 `Upgrade: tcp` on exec-start or container-attach |
| File copy | Container archive GET/HEAD/PUT with tar payloads |
| Start, stop, restart, pause, unpause, kill, wait, resize, rename and remove | Engine HTTP requests |
| Named-volume persistence | The selected daemon's volume storage and lifecycle |

Swarm, plugins, SSH transport, direct daemon mutual TLS from the agent, BuildKit
`/session`, arbitrary upgrades and opaque CONNECT to a configured Docker endpoint
are unsupported. They receive a refusal. Unrelated destinations retain their
existing network policy.

For a contract-bound archive/build operation, author `transport.body_format: opaque`
and explicit `transport.content_types`, such as `[application/x-tar]`. Header,
query, path and capability checks run before forwarding. Opaque mode does not
validate archive content; the loader rejects JSON-field rules on opaque bodies.
The default body format remains `json_object`. If a JSON contract or blocking
body scanner needs complete content beyond the existing 10 MiB capture limit,
the request fails before forwarding. Unavailable inspection does not grant access.
Exec/attach stream bytes are process input/output, not further Engine HTTP
requests or WebSocket messages.

## Request and resource checks

The [adoptable definition](../contrib/docker/service.yaml) records API operations,
effects, enforcement conditions, sources and gaps. Its
[request shapes](../contrib/docker/request-shapes.yaml) expand the referenced
Moby 26.1.5 request definitions and preserve defaults, required fields and integer
bounds. Docker-specific conditions run in the
[Docker checks](../proxy/src/services/docker/enforcement.rs). The reduced shapes
also retain accepted empty-string defaults from the Go client and the supported
`local` logging driver, which the published enum list omits. The captured
[Docker CLI payload](../proxy/tests/fixtures/docker/create-defaults.json) covers
those defaults. `MemorySwappiness` accepts `-1` as well as `0` through `100`.
The [CLI sends `-1` by default](https://github.com/docker/cli/blob/v26.1.5/cli/command/container/opts.go),
and [Engine normalizes `-1` to unset before validation](https://github.com/moby/moby/blob/v26.1.5/daemon/daemon.go).
This applies to create and update requests. Existing-container inspection may
report the normalized value as null. `Memory` remains nonnegative; its zero
default is distinct from the unlimited `MemorySwap`, `CpuQuota` and `PidsLimit`
sentinels. Engine still validates platform-specific resource limits.
The reduced shapes
are not a general OpenAPI interpreter. Moby's Apache 2.0 license is retained in
[MOBY-LICENSE](../contrib/docker/MOBY-LICENSE).

Workload creation rejects privileged mode, host namespaces, host devices,
capability additions, weakened security options, custom runtimes, cgroup parent
selection, unsupported network/volume/log drivers and local-volume driver options.
Both `Binds` and nested `Mounts` use the adopted file bounds. Namespace sharing,
volume sharing, named volumes and network references require inspection of their
effective authority. Unknown constrained fields, noncanonical field aliases and
duplicate JSON/query keys fail before a mutation. Supported omitted defaults,
null values and both supported mount encodings remain usable.

For container creation with an omitted, empty or `default` network mode,
[Moby resolves endpoint key `default` to Linux network `bridge`](https://github.com/moby/moby/blob/v26.1.5/api/server/router/container/container_routes.go#L474-L488).
SafeYolo inspects `bridge` for that endpoint. Explicit network names, endpoint
`NetworkID` values and network API paths retain their own identity. Project
access still requires the inspected bridge ID in the adopted project or shared
network selection.

Before defaulted creation or a classic build, SafeYolo checks the daemon's Linux
platform, default runtime, logging driver and actual default cgroup namespace.
Docker must report `name=cgroupns` in its `SecurityOptions` for an omitted
cgroup namespace or classic build. This reports a private default on the
qualified Moby implementation. When that default is unavailable, explicit
`CgroupnsMode: private` remains supported for container creation. The default runtime must be `runc`;
supported logging drivers are `json-file`, `local` and `none`.

Operations on existing containers and exec sessions inspect their effective
configuration before forwarding. Actual bind sources, write modes, local-volume
options and referenced workloads are checked. Confirmed absence at the requested
inspect endpoint returns HTTP 404 so Docker and Compose can discover resources
before creation. Missing dependencies and failed inspection refuse dispatch.
Existing names and resources created by other administrators remain supported;
no ownership label or naming convention is required. A primary container name
is resolved to its immutable ID before dispatch. Rename uses the same inspection
and, for project access, requires management authority over that container.
The new name does not grant access to another container. Docker rejects a name
already in use.

Docker provides no atomic inspect-and-mutate API. Trusted administrators can
change linked container names, volume references or network connections between
inspection and dispatch. SafeYolo
does not lock out those administrators or claim protection from a malicious
daemon administrator. Operators must account for this upstream concurrency limit.
These prerequisite reads do not authorize extra mutation routes or implement
generic contract response validation.

Network permission, credential permission, route permissions, contract checks and
risky-route approval still apply. Narrow the example capability when necessary.
Routine requests within that authority need no separate transport approval.

## Failure and evidence

If a command fails, use the response status, diagnostic code and
`X-Blocked-By` header to identify the boundary before retrying:

| Result | Next action |
|---|---|
| No authorized service, or a stale token | Discover/request the service through the Agent API. Fetch the current token after activation or restart. |
| Credential or risky-route approval needed | Use the existing [credential and risk approvals](credentials.md#authorization-binding-and-risk-approval). A risk grant does not widen the capability. |
| `GATEWAY_ROUTE_CHALLENGE` | Reconsider the operation and alternatives, then explicitly escalate if needed. |
| Docker argument/resource refusal | Ask the operator to compare the inspected resource with the adopted bounds. A route approval cannot remove those bounds. |
| `GATEWAY_DOCKER_OPERATION_UNSUPPORTED` | Check API 1.45, classic-build settings and the supported operation list. Do not switch to a raw daemon connection. |
| TLS, endpoint or provider failure | Ask the operator to check the configured endpoint identity, CA, credential and provider state. An unavailable provider has no network fallback. |

Use `X-SafeYolo-Request-Id` with the existing Agent API `/explain` and retained flow
lookup. Canonical audit records `gateway.docker_stream.start` and `.end` for
exec/attach. End records distinguish completion, I/O error, interruption, upgrade failure,
shutdown and idle timeout. For an I/O error, `details.error` identifies the
upload or download direction, read/write/shutdown operation, error kind and
optional operating system error code. Error records omit arbitrary peer error
messages. Stream closure does not prove command success; inspect the exec or
container state.

An interrupted mutation response records `gateway.docker_request` with
`mutation_outcome: unknown`. The proxy never automatically repeats a request
or claims rollback. Before retrying a failed create, build, update or exec-start,
inspect daemon state and correlate the original request. The daemon may have
completed the operation without delivering a complete response.

Independent acceptance must name the candidate, real client and daemon versions,
external authentication and endpoint identity, and the multi-service lifecycle.
Reuse that lifecycle for companion request-enforcement and project-scope work
when their candidate bindings permit it.
