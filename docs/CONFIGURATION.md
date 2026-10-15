# Configuration

Select the installed instance with `safeyolo --root ROOT COMMAND`, or set
`SAFEYOLO_CONFIG_DIR`. The default root is `$HOME/.safeyolo`. SafeYolo
reads `config.toml` and `policy.toml`. Paths resolve relative to the selected
configuration or policy file. It does not search for project-local configuration,
convert old state, read `config.yaml`/`addons.yaml` or select a Python fallback.

## Directory structure

```text
ROOT/
├── config.toml          # Runtime settings
├── policy.toml          # Hosts, agents, grants, budgets, lists and controls
├── bin/                 # Host executables
├── libexec/ and lib/    # Private tmux runtime and non-system libraries
├── assets/              # Helpers, guest scripts, skills, launchers and services
├── share/               # Prepared platform images or Linux rootfs-tree
├── agents/              # Persistent homes, overlays and owned run metadata
├── certs/               # Public CA and private signing key
├── data/                # Private tokens, instance identity and durable state
└── logs/                # Audit, runtime diagnostics and flow storage
```

The [settings reference](settings.md#runtime-settings) gives every
retained key, default and consumer. Paths such as `data_dir`,
`audit_log_path`, `event_log` and `flow_store_db_path` belong to this root by
default; the earlier Python XDG log selection is not a runtime setting.
Keep private tokens, signing keys and service credentials on the host.

## Runtime settings

Check a saved configuration before starting it:

```sh
safeyolo config check "$SAFEYOLO_CONFIG_DIR/config.toml"
safeyolo start
safeyolo status
```

The Admin API defaults to IPv4 loopback port 9090 and requires the selected
`admin_api_token_file`. Port zero requests an ephemeral Admin port, reported
in readiness. Agent listeners are Unix sockets with host-owned identity;
request headers cannot change that identity. Agent lifecycle stages their
listeners and the agent discovery map from the same policy/runtime state.

To use an explicit parent or additional CA trust, set the keys:

```toml
parent_proxy = "https://parent.example:8443"
upstream_ca_file = "certs/additional-trust.pem"
ignore_hosts = ["pinned-app.example:443"]
```

Parent proxy URLs must be HTTP(S) authorities with no credentials, path, query
or fragment. Upstream trust still checks certificate validity, signature and
hostname; TLS failure cannot choose uninspected fallback. For an exact
operator-selected TLS passthrough, use `ignore_hosts`. See
[TLS trust and passthrough](TLS_CERTIFICATE.md).

To send selected agents through one shared parent, add the following top-level
keys to the host's `config.toml`. The operator-provided parent must be listening
on host port 18080. Restart SafeYolo to apply the saved settings:

```toml
parent_proxy = "http://127.0.0.1:18080"
parent_proxy_agents = ["zx"]
```

Agent `zx` uses the parent. Other agents use SafeYolo's direct upstream
connection. Every agent still sends traffic through SafeYolo. Names match the
host-assigned listener identity; request headers cannot select the route.
An omitted or empty `parent_proxy_agents` list preserves global parent use.
Removing the last name restores global use. Without `parent_proxy`, the list
has no effect. If a selected parent fails or refuses CONNECT, the request fails
without a direct fallback.

To send only selected destinations through the parent, also set
`parent_proxy_hosts`. Use exact Domain Name System (DNS) hostnames, without a
URL or port:

```toml
parent_proxy_hosts = ["auth-a.example.test", "auth-b.example.test"]
```

With this host list and the agent list in the previous example, agent `zx`
uses the parent for those two hosts. Its requests to other hosts use direct
upstream connections. Other agents also use direct connections.

An omitted or empty host list applies no destination filter. An omitted or
empty agent list applies no agent filter. If both lists contain entries, both
must match. Without `parent_proxy`, neither list changes routing.

Host matching ignores ASCII case and treats one final DNS root dot as
equivalent. The loader applies the existing hostname and Internationalized
Domain Names in Applications (IDNA) validation rules. Invalid entries are
rejected. IP addresses, wildcards, domain suffixes, URL paths and port filters
are not supported. A listed host does not include its subdomains or redirect
destinations. Selection uses the logical request destination and trusted
listener identity. Request headers and resolved addresses cannot select the
parent. CONNECT retains its admitted authority for inner requests. A selected
parent connection, TLS or CONNECT failure does not fall back to direct egress.

Runtime listeners, audit, trace and capture settings take effect on restart.
Policy apply updates policy controls without restarting. Existing capture
limits, queue modes and trace/storage retention are unchanged; use the exact
values and zero/negative handling in [settings](settings.md).

## Workspace and memory

An agent's saved `folder` is exposed as `/workspace`. `memory_mb` defaults to 4096 MiB in the host. Extra `mounts` retain their specified access;
`HOST:GUEST:ro` is read-only. Choose owned workspaces and review trusted host
scripts before executing them.

```sh
safeyolo agent configure work --workspace "$HOME/new-project" --memory 2048
safeyolo agent configure work --mount "$HOME/reference:/reference:ro"
safeyolo agent stop work
safeyolo agent start work
```

Saved changes apply at the next sandbox start. Existing live runs keep their
bound inputs. The explicit `--dangerously-allow-unowned` option retains the
host's existing ownership override; it is not required for an owned
project. A launcher can be `tmux-window`, `tmux-pane`, `supervisor` or a trusted
script. [Agent launchers](agent-launchers.md) describe selection and attach.

On Linux, new sandbox starts attach extra directories before guest setup and
workloads start. If an attachment fails, startup fails and cleans up that attempt.
This route requires runsc filesystem mount control;
`release-20261005.0` is the tested runtime input.
This backend support does not add a live add/remove command or change saved
configuration. Existing running sandboxes with startup Open Container
Initiative (OCI) binds cannot safely remove those shares live. The host must
report that limit and leave the sandbox running. An operator can explicitly
stop and start the sandbox to use the new route. Safe backend removal refuses
busy mounts, including open files, working directories and memory mappings.
It does not erase files copied into the guest or bytes already read into memory.

`desktop.size` retains `auto` or an explicit `WIDTHxHEIGHT` preference;
`desktop.present_host_port` selects the permitted loopback presentation port.
Use `safeyolo agent present work` for the running desktop. Web and Commander
listener/share settings stay in the same config. Their authenticated
Admin owners and Commander make the existing operator changes; the retired
Python desktop/web/command-centre wrappers are not installed.

## Shared working folder (optional)

Use an ordinary writable directory mount at `/dropbox` for drafts and selected
outputs that the operator and agent edit in turn. An agent dropbox is a shared
working folder, unrelated to the Dropbox service. The files stay on the
SafeYolo host. Local use needs no Tailscale setup. Remote access through
Taildrive exposes those files; it does not create an independent copy or keep
them available when the serving host is unreachable.

### Set up and inspect the local mount

Run the following commands on either a Linux or macOS SafeYolo host, as the
account that owns the instance. Select that instance with `--root` or
`SAFEYOLO_CONFIG_DIR` as described at the start of this guide. The example uses
an existing agent named `dropbox-trial` and an instance directory name of
`work-instance`. For a new agent, first follow [agent setup](installation.md#configure-and-use-an-agent).
Use a different instance directory name for each instance on the same host.

Keep the output parent outside disposable runtime state and every agent
workspace. Mount only the agent's child directory. A workspace or another
mount of the parent would also expose sibling files. Before adding a
mount, inspect the saved configuration:

```sh
safeyolo agent status dropbox-trial
```

`next_start_configuration.mounts` lists the saved mounts. Each `--mount`
appends an entry. If `/dropbox` is already configured, inspect that entry rather
than adding it again. With no existing `/dropbox` entry, create the dedicated
directory, add the mount, and restart only this agent. Stop if a command fails:

```sh
mkdir -p "$HOME/agent-dropboxes/work-instance/dropbox-trial"
safeyolo agent configure dropbox-trial --mount "$HOME/agent-dropboxes/work-instance/dropbox-trial:/dropbox"
safeyolo agent stop dropbox-trial
safeyolo agent start dropbox-trial --sandbox-only
safeyolo agent status dropbox-trial
```

The status result must show the running source directory and
`read_only: false` in `effective_configuration.extra_shares`. Check that the
workspace, other mounts and their access modes are unchanged. Saved changes
apply at the next sandbox start; they do not change an existing run.

From the host terminal, open a guest shell:

```sh
safeyolo agent shell dropbox-trial
```

In that guest shell, check the supplied mount information before saving:

```sh
cat /safeyolo/host-mounts
findmnt --mountpoint /dropbox
```

The supplied list must include a destination of `/dropbox`, and `findmnt` must
show that mount as writable. Directory existence alone does not establish a
host-backed mount. Configuration and startup reject missing sources
and sources that are not directories. A valid directory can still refuse a
file operation. If the selected mount is absent, read-only or unusable, report
the selected path and failure. Do not create a guest-local replacement or
silently save elsewhere. With no shared folder selected, keep the existing
workspace workflow.

For local-only use, the operator opens files directly in
`$HOME/agent-dropboxes/work-instance/dropbox-trial` on this host. Continue with
[sequential editing](#edit-the-same-file-in-turn).

### Optional remote access from a Mac

The SafeYolo host and the operator Mac must already belong to the same
Tailscale network, called a tailnet. Tailscale runs on those hosts. The guest
receives only its local directory mount. It needs no Tailscale credentials,
daemon socket or additional network route. [Taildrive](https://tailscale.com/docs/features/taildrive)
is alpha and requires Tailscale 1.64.0 or later. Retain originals.

An authorised tailnet administrator enables `drive:share` for the serving
host and `drive:access` for the operator Mac. The administrator grants only
the intended operator identity or devices read/write access to `agent_dropbox`
using `tailscale.com/cap/drive`, `shares: ["agent_dropbox"]` and
`access: "rw"`. Preserve unrelated policy entries. For a tagged host, use its
existing tag as `dst` and the intended operator identity or devices as `src`;
[`autogroup:self`](https://tailscale.com/docs/reference/syntax/policy-file)
does not select a tagged host. Use the existing host/share namespace to
distinguish hosts, then the instance and agent child directories.

**Linux serving host:** with those permissions in place, run as the account
that owns the output directory:

```sh
tailscale drive list
```

Check that `agent_dropbox` is unused or already names this output parent. If
the share is unused, add it and check the list again:

```sh
tailscale drive share agent_dropbox "$HOME/agent-dropboxes"
tailscale drive list
```

The list must show the selected parent and sharing account.

**macOS serving host:** use the Tailscale app's Settings → File Sharing →
Choose Shared Folders. If File Sharing is hidden, follow
[Tailscale's macOS enablement instructions](https://tailscale.com/docs/features/taildrive?tab=macos)
for the installed app variant, then close and reopen that app. Select only
`$HOME/agent-dropboxes`, and name its share `agent_dropbox`. Inspect existing
shares before adding one; retain their names and folders. Tailscale permissions
are required in addition to this app setting. The guest mount setup is the same
as on Linux. A Mac used only as an editor client needs `drive:access`, without
exporting a folder of its own.

**Operator Mac:** keep Tailscale connected. In Finder, choose Go → Connect to
Server, enter `http://100.100.100.100:8080`, and connect as Guest. Browse the
tailnet, serving host, `agent_dropbox` share, `work-instance` and `dropbox-trial`.
This is the actual shared directory. Open and save its files directly.

### Edit the same file in turn

Use one writer at a time. Ask the existing client-comms skill to save its
working draft at a clearly named path such as
`/dropbox/client-followup-2026-10-14.txt`. The agent confirms the save and
reports that path immediately, even while the draft is unfinished. A failed
write must be reported as a failed save.

The operator opens that file, edits it and saves at the same path. Confirm the
saved content from the host and the agent before handing editing back. Before
each later revision, the agent rereads the shared file and preserves the
operator's changes. Keep revisions at that same path; a separate workspace
copy could overwrite an intervening edit. No publication step is needed to
read a saved working draft.

The other party must reread, reopen or refresh after a save. In the Mac trial,
stock vi saved two edits that the agent retained in its next revision. A plain
vi reopen returned cached earlier bytes. Disconnecting and reconnecting only
the owned WebDAV mount let read-only vi see the new revision and both edits.
Close or preserve unsaved buffers before reconnecting. If the editor still
shows stale content, eject that owned Finder mount, reconnect to the same
share, and reopen the file. If the editor reports a changed file, reread that
file and coordinate the next save. Simultaneous saves can conflict. Editors
that replace an existing file by renaming a temporary file can fail on this
share; confirm each save rather than assuming that all editors behave like vi.

Agent edits through the local mount continue while operator sharing is
disconnected. After reconnecting, refresh the mount and check the saved change.

### Optional dated copy to the operator Mac

This optional copy is independent of the remote working files. Store it
outside all agent mounts. Select the requested files and pause their writers;
saved work in progress can be copied. The following guest-shell example
archives only `client-followup-2026-10-14.txt`. Use an unused dated filename
for each copy. Replace the date and selected filename for your task.

```sh
tar -czf /dropbox/selected-2026-10-14-01.tar.gz.part -C /dropbox client-followup-2026-10-14.txt
```

If archive creation fails, report the incomplete `.part` file and stop. Do not
rename or collect it as a completed archive. Only after `tar` exits zero, rename
within that same directory and record the source checksum:

```sh
mv /dropbox/selected-2026-10-14-01.tar.gz.part /dropbox/selected-2026-10-14-01.tar.gz
sha256sum /dropbox/selected-2026-10-14-01.tar.gz
```

On the operator Mac, the next example uses the Taildrive namespace
`example.ts.net/linux-host/agent_dropbox/work-instance/dropbox-trial`.
Replace the tailnet and host with the names shown by Finder, including the
host name in the destination path. Percent-encode spaces and special
characters in URL path segments. Use the actual archive filename and an unused
dated destination directory. Stop if any command fails,
including `mkdir` when that dated directory already exists:

```sh
mkdir -p "$HOME/agent-backups/linux-host/work-instance/dropbox-trial"
mkdir "$HOME/agent-backups/linux-host/work-instance/dropbox-trial/2026-10-14-01"
curl --fail --show-error --output "$HOME/agent-backups/linux-host/work-instance/dropbox-trial/2026-10-14-01/selected.tar.gz.part" "http://100.100.100.100:8080/example.ts.net/linux-host/agent_dropbox/work-instance/dropbox-trial/selected-2026-10-14-01.tar.gz"
shasum -a 256 "$HOME/agent-backups/linux-host/work-instance/dropbox-trial/2026-10-14-01/selected.tar.gz.part"
tar -tzf "$HOME/agent-backups/linux-host/work-instance/dropbox-trial/2026-10-14-01/selected.tar.gz.part"
tar -xOzf "$HOME/agent-backups/linux-host/work-instance/dropbox-trial/2026-10-14-01/selected.tar.gz.part" client-followup-2026-10-14.txt
```

The SHA-256 checksum must match the source, and the archive must contain only
the selected files. Inspect their contents before reporting success. If the
copy, checksum comparison or inspection fails, report that failure, leave any
partial copy uncollected, and retain the source for retry. A successful local
save does not establish a successful off-host copy. After verification,
rename the Mac copy:

```sh
mv "$HOME/agent-backups/linux-host/work-instance/dropbox-trial/2026-10-14-01/selected.tar.gz.part" "$HOME/agent-backups/linux-host/work-instance/dropbox-trial/2026-10-14-01/selected.tar.gz"
```

Report "copied off host" with the retained Mac path only after these checks
pass. For a later version, use a new dated directory and archive filename.
Keep earlier copies. This HTTP download copies one selected archive and does
not propagate source deletion. No synchronizer, backup service or scheduler
is required.

### Stop sharing and retain files

Sharing, the guest mount and the agent configuration are separate choices.
Disabling any of them preserves the operator-owned output directory.

To disable only remote sharing on a Linux serving host, first inspect
`tailscale drive list` and confirm that `agent_dropbox` names the owned output
parent. Then run:

```sh
tailscale drive unshare agent_dropbox
tailscale drive list
```

On a macOS serving host, remove only `agent_dropbox` in Tailscale's Choose
Shared Folders list. Keep unrelated shares and grants. The local agent mount
and files remain available.

To disable the guest mount, run on the SafeYolo host:

```sh
safeyolo agent stop dropbox-trial
```

Wait for a successful stop. Remove only the entry whose destination is
`/dropbox` from this agent's `mounts` array in the selected `policy.toml`.
Preserve its other entries and `:ro` suffixes. Then start and inspect the agent:

```sh
safeyolo agent start dropbox-trial --sandbox-only
safeyolo agent status dropbox-trial
```

The running shares must no longer include the removed source. The host output
files must still be readable at their original path. A directory left inside
the guest is not evidence of a remaining host mount.

For removal of a disposable agent, stop it successfully, then run the existing
cleanup command before removing its configuration:

```sh
safeyolo agent cleanup dropbox-trial
```

Remove only that agent's entry from the selected `policy.toml`. Agent
creation can write an inline entry such as `agents = { dropbox-trial = { ... } }`;
remove that entry while preserving the other agents. If the file uses
`[agents.dropbox-trial]` tables instead, remove that table and its child tables.
Use `safeyolo status` to confirm that the agent is no longer configured.
Cleanup clears stopped runtime records and retains the persistent home. Keep
the separate output directory and any retained copies. Deleting those files
is a separate explicit operator action.

## Protected host directories

Run these commands on the host as the account that owns the instance. They use
the default instance at `$HOME/.safeyolo`; use `--root ROOT` for another instance.
To require read-only extra mounts of `$HOME/reference` and its descendants:

```sh
safeyolo mount protect "$HOME/reference"
safeyolo mount list
```

The output lists the resolved protected directory. Designation persists in
`config.toml`, including when the directory does not exist yet. Command paths
are relative to the host's current directory. Existing symlinks resolve to
their targets.

If the directory exists and agent `work` is already configured, add an explicit
read-only extra mount:

```sh
safeyolo agent configure work --mount "$HOME/reference:/reference:ro"
```

Writable extra mounts of a protected directory or descendant are refused
before configuration is saved and before guest startup. The error names the
resolved source and protection and gives an explicit `:ro` remedy. Unrelated
sibling directories keep their requested access. If an agent already has a
saved writable mount of a newly protected directory, add `:ro` to that entry
in its `mounts` array in `policy.toml`, or remove the entry, before starting it.
Rejected mount configuration is not saved.

Protection affects extra mounts. It does not change workspace sharing or
access in an already running sandbox. Stop and start that sandbox after
correcting its saved mounts to apply the new access.

To remove a designation:

```sh
safeyolo mount unprotect "$HOME/reference"
```

The setting is the top-level `protected_host_directories` path array
in `config.toml`; it defaults to `[]`. The commands save resolved absolute
paths. If you edit the array directly, relative paths resolve from the selected
configuration file's directory.

## Policy

The host policy file contains hosts, agent settings, named lists, scoped
credential/service grants, budgets and named controls. There is no addon model.
[Policy guidance](installation.md#policy-and-runtime-settings) explains
precedence, expiration, show and apply with examples.

```toml
version = "2.0"

[hosts."*"]
egress = "allow"

[hosts."blocked.example"]
egress = "deny"

[agents.work]
folder = "/home/operator/code"
memory_mb = 2048

[agents.work.hosts."api.example"]
egress = "allow"

[controls.credentials]
enabled = true
action = "block"

[controls.patterns]
enabled = true
action = "warn"
```

Validate a complete candidate before applying it. List paths belong to the
policy's directory; unreadable or invalid updates do not replace active policy.

```sh
safeyolo policy check "$HOME/reviewed-policy.toml"
safeyolo policy apply "$HOME/reviewed-policy.toml"
safeyolo policy show
```

Network permission and credential permission remain separate. Service bindings
retain route/method, capability, risk and credential scope through the existing
gateway. The #819 source/prerequisite and installed credential proofs
remain in the [responsibility map](settings.md#operator-entry-responsibilities);
removing Python does not accept them or invent a replacement credential store.

## Restart and persistence

The current product retains initialized identity, policy, service/vault state,
Coord data and agent homes under their existing owners. Runtime/process receipts
are observations with birth identity, not permission to signal an arbitrary PID.
Do not remove a private token or key to make a failed start appear successful.
Stop each agent separately, then stop the proxy before changing runtime inputs.

```sh
safeyolo agent stop work
safeyolo stop
safeyolo start
safeyolo agent start work
```

Use `doctor`, `agent diagnostics NAME` and the named logs to diagnose failure.
The [operator guide](operator-guide.md) covers scoped evidence and
approvals. Historical Python/addon descriptions remain in [ADDONS.md](ADDONS.md)
for interpreting retained tests and older records; they are not install guidance.
