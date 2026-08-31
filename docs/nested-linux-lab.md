# SafeYolo-in-SafeYolo Linux lab

SafeYolo can run inside an outer Linux SafeYolo agent as a disposable,
proxy-only integration lab. This uses the normal Linux rootfs, UDS ingress,
runsc launcher, Agent API, and coord MCP. It does not require a separate
orchestrator or direct network access.

## Required topology

The outer agent supplies the only network path:

```text
nested agent -> nested per-agent UDS -> nested SafeYolo
             -> outer proxy at 127.0.0.1:8080 -> Internet
```

Use a guest-local filesystem for the nested source and state. The outer
agent's `/home/agent` and host checkout mounts use VirtioFS, which cannot
preserve the UID/GID 100000 ownership required by rootless runsc. `/var/lib`
is the conventional disposable location.

Install the package floor needed to prepare and build the lab, including
`rsync` and `e2fsprogs`:

```bash
sudo -n apt-get update
sudo -n apt-get install -y \
  skopeo umoci mmdebstrap debootstrap acl jq rsync e2fsprogs tmux curl
```

Then prepare a lab root as the outer agent user:

```bash
sudo -n install -d -m 0755 -o "$(id -u)" -g "$(id -g)" \
  /var/lib/nested-safeyolo-lab \
  /var/lib/nested-safeyolo-lab/source \
  /var/lib/nested-safeyolo-lab/state

rsync -a --delete --exclude .git --exclude .venv --exclude guest/out \
  /path/to/mounted/safeyolo/ /var/lib/nested-safeyolo-lab/source/

export SAFEYOLO_CONFIG_DIR=/var/lib/nested-safeyolo-lab/state
export SAFEYOLO_COORD_DATA_DIR=/var/lib/nested-safeyolo-lab/state/coord
export SAFEYOLO_UPSTREAM_PROXY=http://127.0.0.1:8080
export SAFEYOLO_RUNSC_PLATFORM=systrap
```

Both state variables are required. `SAFEYOLO_CONFIG_DIR` does not implicitly
relocate coord data. A source snapshot under `/var/lib` also keeps the
builder's `guest/out/rootfs-tree` on a filesystem that preserves subordinate
ownership. Alternatively, set `OUTPUT_DIR` to a dedicated guest-local path.

Bootstrap from the relocated source:

```bash
cd /var/lib/nested-safeyolo-lab/source
uv sync
uv run safeyolo bootstrap
```

The build uses the inherited outer proxy and stages the readable
`SSL_CERT_FILE` at the same absolute path inside the temporary chroot. TLS
verification remains enabled. The builder removes that outer CA and any
copied host resolver before it emits the rootfs artifacts.

Choose ports that do not shadow the inherited outer proxy endpoint. For
example, set `proxy.port` to `18080`, `proxy.admin_port` to `19090`, and
`proxy.web_port` to `18081` in the nested `config.yaml`, then start normally:

```bash
uv run safeyolo start --dev
```

The nested traffic master uses mitmproxy's upstream HTTP-proxy layer for each
per-agent UDS connection. UDS-derived peer attribution is unchanged. Each
SafeYolo process also uses a stable instance-specific Via pseudonym derived
from its coord instance ID. Set `SAFEYOLO_VIA_TOKEN` or `proxy.via_token` only
when a lab needs an explicit pseudonym. The default unprefixed instance ID is
also compatible with older outer releases that matched their fixed Via token
as a substring. Another instance's token is allowed; a request returning
through the same instance remains a 508 loop block.

When PID 1 is not systemd and no user bus is available, the Linux launcher
runs runsc directly. It warns that inner `MemoryMax` and `CPUQuota` controls
are unavailable. The outer SafeYolo sandbox still bounds the complete lab.
The normal `systemd-run --user --scope` path remains active on hosts with a
usable user manager.

Detached startup keeps its existing contract. `agent add --no-run` followed
by `agent run --detach` does not execute `.safeyolo-command`. If the test needs
the staged coding harness and bundled coord MCP dependencies, invoke a bounded
command explicitly:

```bash
uv run safeyolo agent shell nested-worker \
  -c '/home/agent/.safeyolo-command --version'
```

Subscription login inside the nested agent is supported; no API key is
required. Nested shutdown also keeps the conservative NATS ownership checks.
Do not delete a retained NATS pidfile or send an unverified SIGKILL.

## Full acceptance lane

Run the real topology from an outer Linux SafeYolo agent. The lane copies the
current checkout into `/var/lib`, installs guest packages, builds the standard
rootfs, starts a nested runsc agent without systemd, proves both Agent APIs and
both proxy layers, checks nested flow attribution, creates a genuine inner
self-loop, and handshakes with the bundled coord MCP:

```bash
cd /path/to/mounted/safeyolo
SAFEYOLO_NESTED_ACCEPT=1 tests/nested-linux/acceptance.sh
```

The lane leaves the nested instance running with its normal outer upstream so
the operator can inspect it. Remove the dedicated lab directory only after
stopping the nested instance and preserving any evidence that is needed.
