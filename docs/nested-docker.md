# Docker inside a Linux sandbox

This configuration is being qualified for Linux/gVisor under [#1436](https://github.com/craigbalding/safeyolo/issues/1436).
The installed Compose, restart and application-sharing results are still pending.
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
Compose through the existing proxy. The initial probe used Docker 26.1.5 and
Compose 2.26.1. The default sandbox failed daemon startup because the devices
cgroup was absent. Qualification of the opt-in configuration remains pending.

```sh
sudo -n apt-get update
sudo -n apt-get install -y --no-install-recommends docker.io docker-cli docker-compose
```

In this guest shell, start one daemon in the foreground. Keep the existing
proxy and certificate authority (CA) environment. The daemon stores images,
containers and named volumes in persistent guest home. Its socket and running
processes are disposable. These flags select `vfs` storage and disable the
inner bridge and packet forwarding. Containers use the guest's host network;
that network is the sandbox's loopback, not the physical host's network.

```sh
sudo -n dockerd --host=unix:///var/run/docker.sock --data-root=/home/agent/.local/share/docker --storage-driver=vfs --iptables=false --ip6tables=false --bridge=none --ip-forward=false --ip-masq=false --exec-opt native.cgroupdriver=cgroupfs
```

## Operate the example application

Use a second shell in the same guest. This qualification example requires a
SafeYolo checkout at `/workspace`. Copy its fixture to a new working directory.
The copied CA is public trust material. It does not contain a private key.
The hosting policy must allow the selected registry's actual authentication,
manifest and blob destinations, plus `example.com` for the build/application
probe. It must deny `denied.invalid`. An unexpected proxy refusal needs its
normal policy decision; changing the Docker flags does not grant network access.

```sh
mkdir /home/agent/nested-notes
cp /workspace/tests/blackbox/fixtures/nested-docker/compose.yaml /workspace/tests/blackbox/fixtures/nested-docker/Dockerfile /workspace/tests/blackbox/fixtures/nested-docker/notes.py /workspace/tests/blackbox/fixtures/nested-docker/network_probe.py /home/agent/nested-notes/
cp /usr/local/share/ca-certificates/safeyolo.crt /home/agent/nested-notes/safeyolo.crt
cd /home/agent/nested-notes
sudo -n env DOCKER_BUILDKIT=0 docker --host=unix:///var/run/docker.sock compose up --build -d
curl --fail --retry 10 --retry-connrefused --retry-all-errors http://127.0.0.1:8088/api/v1/notes
```

The initial response should be `[]`. The API container forwards requests to
a separate SQLite store container on guest loopback port 8090.

```sh
curl --fail -H 'Content-Type: application/json' --data '{"text":"keep this note"}' http://127.0.0.1:8088/api/v1/notes
sudo -n docker --host=unix:///var/run/docker.sock compose ps
sudo -n docker --host=unix:///var/run/docker.sock inspect nested-notes-api-1
sudo -n docker --host=unix:///var/run/docker.sock compose logs
sudo -n docker --host=unix:///var/run/docker.sock compose exec api python3 /app/network_probe.py
sudo -n docker --host=unix:///var/run/docker.sock compose restart
sudo -n docker --host=unix:///var/run/docker.sock compose down
sudo -n docker --host=unix:///var/run/docker.sock compose up -d
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
hosting sandbox or closed port must fail through the provider route without
ordinary-network fallback. Existing provider controls remain applicable;
their binding to this nested application still needs installed proof.
