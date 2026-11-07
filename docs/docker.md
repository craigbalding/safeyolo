# Docker client transport

Configure a Docker Engine endpoint as a service, then use ordinary Docker and
Compose commands inside the agent. SafeYolo checks the current gateway capability
before forwarding each management request. Exec and attach switch only the
admitted operation to a raw input/output stream.

This transport does not provide project isolation or enforce Docker host-resource
constraints. A whole-environment grant delegates the daemon's execution authority,
including its networking, mounts and other workloads. Review that authority with
the [service-authoring workflow](service-authoring.md) before authorization.
External workloads, builds and daemon image fetches use the external network.

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
`full_environment`. Keep upstream administrative credentials and daemon client keys
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
