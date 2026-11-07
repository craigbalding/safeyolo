# Docker inside a Linux sandbox

This recipe describes the Linux/gVisor configuration exercised under
[#1436](https://github.com/craigbalding/safeyolo/issues/1436). Installed systrap
runs demonstrated a two-service Compose application, build, persistence,
sandbox restart, outbound controls and application sharing. The image pull
used an explicitly approved registry token; automatic-token CLI pulls remain
unproved. See the issue for independent acceptance.
Do not infer support on macOS or for other Docker configurations from this recipe.

Nested Docker executes inside the hosting sandbox. Its daemon, builds and
applications use that sandbox's outbound policy. An application caller does
not supply the workload's policy. Approving an application that can execute
commands can therefore delegate the hosting sandbox's network authority.

Application access and Docker administration grant different access. Broad
inner Docker administration can read or change the hosting sandbox's workspace,
credentials, explicit host mounts and other inner workloads. Guest root and
inner privileged containers still run inside gVisor; they do not become root
on the physical host. A dedicated project sandbox is an option when the
hosting sandbox's authority should match the delegation. It is not required.

## Prepare the hosting sandbox

On the operator's Linux host, select an existing agent named `notes`. Stop that
agent before restarting it with the new setting. The setting adds guest
`CAP_SYS_ADMIN`, permits guest namespace creation and mounts gVisor's virtual
cgroup filesystem. It adds no host filesystem share or network interface.
The default setting is `false`; changing it affects the next sandbox start.

```sh
safeyolo agent stop notes
safeyolo agent configure notes --nested-docker true
safeyolo agent start notes --sandbox-only
safeyolo agent shell notes
```

Inside that sandbox, the following Debian recipe installs Docker Engine and
Compose through the existing proxy. The preflight used Docker 26.1.5 and
Compose 2.26.1. The default sandbox failed daemon startup because the devices
cgroup was absent. With the opt-in configuration, the daemon answered Engine
requests and a container ran. The public CA must be readable by package users
such as `_apt`. Initialization creates that certificate with mode `0644`;
the CA private key and instance tokens remain `0600`.

```sh
sudo -n apt-get update
sudo -n apt-get install -y --no-install-recommends docker.io docker-cli docker-compose python3
```

In this guest shell, start one daemon in the foreground. Keep the existing
proxy and certificate authority (CA) environment. The daemon stores images,
containers and named volumes in persistent guest home. Its socket and running
processes are disposable. These flags select `vfs` storage and disable the
inner bridge and packet forwarding. Containers use the guest's host network;
that network is the sandbox's loopback, not the physical host's network.

```sh
sudo -n mkdir -p /run/safeyolo-nested-docker
sudo -n dockerd --host=unix:///run/safeyolo-nested-docker/docker.sock --data-root=/home/agent/.local/share/docker --exec-root=/run/safeyolo-nested-docker/exec --pidfile=/run/safeyolo-nested-docker/dockerd.pid --storage-driver=vfs --iptables=false --ip6tables=false --bridge=none --ip-forward=false --ip-masq=false --exec-opt native.cgroupdriver=cgroupfs
```

## Operate the example application

Use a second shell in the same guest. This qualification example requires a
SafeYolo checkout at `/workspace`. Copy its fixture to a new working directory.
The copied CA is public trust material. It does not contain a private key.
The hosting policy must allow the selected registry's actual authentication,
manifest and blob destinations, plus `example.com` for the build/application
probe and the Debian repositories used to install Python during the build.
The preflight observed `production.cloudfront.docker.com` as a blob destination.
The hosting policy must deny `denied.invalid`. An unexpected proxy refusal needs its
normal policy decision; changing the Docker flags does not grant network access.

```sh
mkdir /home/agent/nested-notes
cp /workspace/tests/blackbox/fixtures/nested-docker/compose.yaml /workspace/tests/blackbox/fixtures/nested-docker/Dockerfile /workspace/tests/blackbox/fixtures/nested-docker/notes.py /workspace/tests/blackbox/fixtures/nested-docker/network_probe.py /home/agent/nested-notes/
install -m 0644 /usr/local/share/ca-certificates/safeyolo.crt /home/agent/nested-notes/safeyolo.crt
cd /home/agent/nested-notes
unset DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH
```

Before building, retrieve `debian:trixie-slim` into this inner daemon. The
demonstrated pull used the Engine API with one fixed, short-lived registry
token. The ordinary CLI can acquire a different anonymous token after a refused
pull, so retrying the CLI does not establish that the replacement is approved.

In the same guest directory, use `curl` and Python 3 to save the token and its
encoded header in private files. The token request uses the existing proxy.
The image request uses only the daemon's local Unix socket. The
[Engine API](https://docs.docker.com/reference/api/engine/version/v1.45/)
accepts a base64url-encoded authentication configuration in `X-Registry-Auth`;
its [`registrytoken` field](https://github.com/moby/moby/blob/v26.1.5/api/types/registry/authconfig.go)
supplies the fixed bearer to the registry.

```sh
umask 077
curl --fail --silent --show-error --output registry-token.json 'https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/debian:pull'
python3 -c 'import base64,json; token=json.load(open("registry-token.json"))["token"]; auth=base64.urlsafe_b64encode(json.dumps({"registrytoken":token}).encode()).decode(); print("X-Registry-Auth: " + auth)' > registry-header.txt
sudo -n curl --silent --show-error --unix-socket /run/safeyolo-nested-docker/docker.sock --request POST --header @registry-header.txt 'http://localhost/v1.45/images/create?fromImage=debian&tag=trixie-slim'
```

If the progress stream reports an error, stop before building. For an unknown
credential refusal, the operator checks the reported agent, destination and
fingerprint through the existing [credential approval workflow](credentials.md).
Approve only that fingerprint at `registry-1.docker.io`, wait for the policy
to become active, then repeat only the local image request with the same saved
header. An expired or replaced token needs its own approval. Network refusals
still need their normal policy decision. Keep tokens out of command arguments,
logs and shared files. If you abandon the pull, remove both private files.

After the pull completes, verify that the image exists, then remove both secret
files before building. The qualification retrieved manifest digest
`sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2`;
the mutable tag can later select another image.

```sh
sudo -n docker --host=unix:///run/safeyolo-nested-docker/docker.sock image inspect debian:trixie-slim
rm registry-token.json registry-header.txt
sudo -n env DOCKER_BUILDKIT=0 docker --host=unix:///run/safeyolo-nested-docker/docker.sock compose up --build -d
curl --fail --retry 10 --retry-connrefused --retry-all-errors http://127.0.0.1:8088/api/v1/notes
```

The initial response should be `[]`. The API container forwards requests to
a separate SQLite store container on guest loopback port 8090.

```sh
curl --fail -H 'Content-Type: application/json' --data '{"text":"keep this note"}' http://127.0.0.1:8088/api/v1/notes
sudo -n docker --host=unix:///run/safeyolo-nested-docker/docker.sock compose ps
sudo -n docker --host=unix:///run/safeyolo-nested-docker/docker.sock inspect nested-notes-api-1
sudo -n docker --host=unix:///run/safeyolo-nested-docker/docker.sock compose logs
sudo -n docker --host=unix:///run/safeyolo-nested-docker/docker.sock compose exec api python3 /app/network_probe.py
sudo -n docker --host=unix:///run/safeyolo-nested-docker/docker.sock compose restart
sudo -n docker --host=unix:///run/safeyolo-nested-docker/docker.sock compose down
sudo -n docker --host=unix:///run/safeyolo-nested-docker/docker.sock compose up -d
curl --fail --retry 10 --retry-connrefused --retry-all-errors http://127.0.0.1:8088/api/v1/notes
```

The final response should still contain `keep this note`. Container removal
does not request volume deletion. To delete this application's stored notes
explicitly, run `compose down --volumes` with the same Docker host and project.

## Resume after a sandbox restart

Stopping the hosting sandbox stops Docker and every inner workload. Guest
home and workspace persist. Linux/gVisor rootfs changes, including installed
OS packages, are discarded. After the operator starts the hosting sandbox,
reinstall the packages or use a prepared guest image that contains them. Start
the daemon with the same data root and flags. Return to the application directory
and run `compose up -d` against its local socket. Named volumes must remain in
that data root. A Docker socket or saved container entry alone does not show
that the daemon or application has resumed.
Use a fresh execution directory when restarting the daemon. A retained
containerd PID file can refer to a different process after a sandbox restart.
The qualification driver keeps its socket, PID file and execution directory
under `/run`, separately from the persistent Docker data root.

## Share only the application

Use the existing [service authoring workflow](service-authoring.md) and
[provider-service route](assurance-map.toml). On the operator host, put this
definition in the instance's `services/notes.yaml`. The service name selects
the configured hosting agent `notes`.

```yaml
schema_version: 1
name: notes
default_host: notes.safeyolo.internal
capabilities:
  reader:
    routes:
      - methods: [GET]
        path: /api/v1/notes
```

In that instance's `policy.toml`, bind the provider host to the service and
allow port 8088. Preserve the rest of the operator policy.

```toml
[hosts."notes.safeyolo.internal"]
service = "notes"
egress = "deny"
[hosts."notes.safeyolo.internal:8088"]
egress = "allow"
```

For an existing caller named `caller`, grant the reader capability:

```sh
safeyolo services authorize caller notes --capability reader
```

The caller obtains its own gateway token through `/gateway/services` and calls
the approved application route. It receives no Docker socket or daemon access.
The application port, capability and outbound policy are separate decisions.
Revoke the reader capability through the existing service controls. A stopped
hosting sandbox or closed port fails through the provider route without
ordinary-network fallback. Installed controls observed approved access,
refusal before approval and after revocation, route/port refusals, canonical
caller headers, and closed-port/stopped-provider failures. A live fallback
observer accepted no provider connections and passed its positive control.

The [installed qualification driver](../tests/blackbox/installed_docker_preflight.py)
keeps the small preflight and adds `--journey` for the complete Compose,
sandbox recovery and application-provider controls. On the owned test host,
`--reuse-root` continues a stopped fixture with its current policy and approved
registry inputs. Supply its actual guest Docker data root with `--docker-data`
to reuse the inspected image. The driver preserves each operation's output and
stops the fixture on failure. Its local observer controls do not establish
installed support or independent acceptance.

The installed journey used CLI revision `90545121`, source-equivalent proxy
revision `f8d1037f`, guest helper revision `0d3332e6` and runsc
`release-20261005.0-safeyolo.1`. The observer reused the retained image/data and
fresh initialization result, and staged the public CA outside a private
workspace for `_apt`. The original journey stopped at its Compose log parser;
the remaining provider failure controls ran separately. The origin and audit
results were derived from retained logs after correcting terminal-prefix
handling and joining request IDs to the guard's sandbox identity. These results
are not a successful unmodified-driver run. Root and inner privileged execution
were exercised inside the outer sandbox: direct external and unapproved host
connections failed, and an unshared host file remained absent. This does not
qualify bridge networking, another storage driver or macOS.
