# Docker management

Configure a Docker Engine endpoint as a service, then use ordinary Docker and
Compose commands inside the agent. SafeYolo checks the current gateway capability
before forwarding each management request. Exec and attach switch only the
admitted operation to a raw input/output stream.

The adopted Docker capability bounds workload arguments and relevant existing
resources before forwarding. The `project` mode also checks project membership
and filters management responses. External network policy remains a separate concern. External workloads, builds and daemon image fetches use the
external network. Review the execution authority with the
[service-authoring workflow](service-authoring.md) before authorization.

## Operator setup

On the operator host, copy the [service definition](../contrib/docker/service.yaml)
into the instance's configured service directory. Replace its service name,
`default_host` and `docker.endpoint` with the actual service and endpoint.
The endpoint is an HTTP or HTTPS origin without credentials, path or query.
The default hostname and authorized host mapping must equal its hostname.
Use one Docker definition per endpoint.

For an external daemon, use an authenticated HTTPS endpoint with a certificate
that identifies the endpoint. One supported arrangement is an operator-managed
TLS reverse proxy with bearer authentication in front of the daemon's private
socket. Store its bearer credential through
[credentials and service access](credentials.md), then authorize the agent for
`workloads`. Keep upstream administrative credentials and daemon client keys
on the operator side. Configure the proxy's
[upstream CA trust](TLS_CERTIFICATE.md#additional-upstream-trust) for a private CA;
do not disable certificate verification. Close unauthenticated alternative access
to that daemon at the endpoint.

For Docker inside a sandbox, use the existing
[sandbox-provider service route](credentials.md#authorization-binding-and-risk-approval).
The service name must select the hosting agent. Use its configured provider port
in `docker.endpoint`. Use HTTP for that local provider route and omit `auth`
when the provider needs no upstream credential. Workloads use the hosting
sandbox's authority. Installed nested-Docker runtime qualification is a separate
prerequisite.

Set `docker.execution_boundary` in the operator-adopted definition to `external`
or `sandbox`. Request bodies and headers cannot change that boundary. Do not
describe an external daemon as a sandbox to obtain inner privilege treatment.
The definition, adoption and service directory remain operator controlled.

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
symlinks before authorizing a file source. An approved directory may contain
files used by other host processes; SafeYolo does not inspect those consumers.

For broad administration of an entire qualified inner Docker environment, the
operator may create a separate capability with `docker_access.mode: sandbox_admin`
and `docker.execution_boundary: sandbox`. This authority includes privileged
inner workloads, the provider workspace, credentials, explicit host mounts and
other inner workloads. The authorization displays that authority. Use a dedicated
project sandbox when its entire authority should match the delegation. A narrow
project route list does not narrow host-file authority in this administration
mode. Use the workload mode for narrower host authority. The loader refuses
`sandbox_admin` for an external execution boundary.

## Select one project

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
workloads retain the hosting sandbox's authority. The project implementation's
real Engine/Compose qualification remains pending in
[#1439](https://github.com/craigbalding/safeyolo/issues/1439).

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
is resolved to its immutable ID before dispatch.

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

## Agent setup

The initial client target is Docker 26.1.5, Compose 2.26.1, standalone Engine
26.1.x and Engine application programming interface (API) 1.45. Real-daemon
qualification of this candidate remains pending in [#1437](https://github.com/craigbalding/safeyolo/issues/1437).
Proxy wire tests do not establish the full Docker lifecycle.

[Docker's exec/attach dialer](https://github.com/moby/moby/blob/v26.1.5/client/client.go#L390-L410)
bypasses `HTTP_PROXY`. Set `DOCKER_HOST` to the existing
plain HTTP proxy's host and port, using Docker's `tcp://` scheme. For example,
`HTTP_PROXY=http://10.0.2.2:3128` means `DOCKER_HOST=tcp://10.0.2.2:3128`.
Preserve the proxy and certificate environment. SafeYolo selects and verifies
the separately configured upstream endpoint.

Prepare a private Docker configuration directory dedicated to this service.
In its `config.json`, replace the service name and gateway-token placeholder
below. Obtain the current scoped token from `GET /gateway/services` on the
authenticated Agent API. This is the gateway token, not the daemon credential.
Protect the configuration file like a credential.

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
| Start, stop, restart, pause, unpause, kill, wait, resize and remove | Engine HTTP requests |
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

## Failure and evidence

Use `X-SafeYolo-Request-Id` with the existing Agent API `/explain` and retained flow
lookup. Canonical audit records `gateway.docker_stream.start` and `.end` for
exec/attach. End records distinguish completion, interruption, upgrade failure,
shutdown and idle timeout. Stream closure does not prove command success;
inspect the exec or container state.

An interrupted mutation response records `gateway.docker_request` with
`mutation_outcome: unknown`. The proxy never automatically repeats a request
or claims rollback. Before retrying a failed create, build, update or exec-start,
inspect daemon state and correlate the original request. The daemon may have
completed the operation without delivering a complete response.

Independent acceptance must name the candidate, real client and daemon versions,
external authentication and endpoint identity, and the multi-service lifecycle.
Reuse that lifecycle for companion request-enforcement and project-scope work
when their candidate bindings permit it.
