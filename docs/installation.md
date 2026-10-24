# Install and configure SafeYolo

Install SafeYolo on your host, create an agent for an owned workspace, and
choose its access policy. The installed `safeyolo` command starts and stops the
proxy and agents, opens terminals, and reads traffic and access requests. For
an inspect and approval walkthrough, use the [operator guide](operator-guide.md).

Use [operator communication](coord-operations.md) for scripted sends,
draft-safe chat and room/harness-event observation.

For the tested Ubuntu AMD64 two-command route, use the [README quick
start](../README.md#quick-start). Everything below is optional reference:
installation alternatives, earlier bundles, host preparation, builds and recovery.
The [tested scope](#tested-onboarding-scope) separates installed proof from
current-source capabilities and remaining platform work.

## Install and start

This manual alternative retains the earlier `host-7a38` bundle instructions.
Use your ordinary host account on Ubuntu 24.04 or Apple Silicon macOS 26.0
or later. Download a production archive for your host from that earlier
[release](https://github.com/craigbalding/safeyolo/releases/tag/host-7a38dff14e7e4eacb4095da732ffe06d7c7c5796).
It supplies `linux-amd64`, `linux-arm64` and `darwin-arm64` bundles from host
source `7a38dff14e7e4eacb4095da732ffe06d7c7c5796`. Use that explicit release
for this manual alternative. The README uses the current host release instead.
This guide also covers newer source builds. Check the source commit in your bundle: newer
source features are absent from the linked older release.
Source builds are an [alternative](#build-a-bundle).
Existing wheel downloads belong to the earlier Python CLI.
A bundle's `package-info` records its source, profile, platform and actual
minimum glibc or macOS version. A production bundle contains release Rust
executables; a debug bundle contains dev executables. The macOS development
helper has the `get-task-allow`
entitlement for authorized debugging.
Those archives require glibc 2.39 on Linux and macOS 26.0 on Apple Silicon.
Unpacking and installation need Bash, tar and
the host's SHA-256 tool. They need no compiler, Python, wheel, virtual
environment or uv tool installation.

This Ubuntu example uses an arm64 production archive in your current directory.
On x86_64 Ubuntu, use `linux-amd64`; on Apple Silicon macOS, use `darwin-arm64`.
For this linked release, prepare the [host runtime](#guest-prerequisites) before installation.
The tested newer release and current source use [automatic Linux host preparation](#linux-host-preparation-in-new-source-bundles).
For an optional archive integrity check, save `SHA256SUMS` beside the archive
and run `sha256sum --ignore-missing --check SHA256SUMS` on Ubuntu, or
`shasum -a 256 --ignore-missing --check SHA256SUMS` on macOS. An `OK` result
checks the archive against that release's manifest; it does not independently
authenticate the publisher. The installer still verifies the unpacked bundle
internally.
The published bundle obtains the compatible default guest anonymously from
GitHub Container Registry (GHCR), using its guest discovery metadata. The initial
guest release, `guest-2026-10-12.1`, is public. Prepared assets remain an explicit
[offline or contributor alternative](#guest-prerequisites).
Choose a root with no existing instance configuration. This example uses the
CLI default `$HOME/.safeyolo`.
If it is already in use, preserve it and follow the
[custom-instance reference](#other-installation-paths). There is no old-state conversion.
Installation checks bundle checksums and executable identities, obtains and
verifies the default guest, then creates
configuration, trust, private tokens and runtime directories internally.
There is no separate init, build or setup command after unpacking.

The installer creates the `safeyolo` command in `$HOME/.local/bin` when that
directory is already on your normal PATH. Otherwise it uses `/usr/local/bin`
on Linux and Mac. Creating the command directory and link uses sudo only when
the nearest existing parent is not writable by your account. Linux guest
acquisition uses sudo to extract the guest with its mapped owners and access
permissions. The configuration remains owned by your account. New host
terminals can run `safeyolo` without selecting a root or changing PATH.
An unrelated existing command is preserved and reported with its recovery.

```sh
tar -xzf safeyolo-linux-arm64-production.tar.gz
./safeyolo-linux-arm64-production/install.sh --root "$HOME/.safeyolo"
```

The installer prints the full source commit and build profile. Host executables
are in `bin`, with the private tmux executable in `libexec` and its non-system
libraries in `lib`. Guest helpers and boot scripts are in `assets/guest`;
launchers, skills, host scripts and service definitions are under `assets`.
macOS bundles also contain the signed VM helper, metadata and symbols, and the
Linux terminal helper. This package/install/start path uses no first-party
Python execution. Remaining helper and workflow dependencies are listed in the
[entry responsibility map](settings.md#operator-entry-responsibilities).

Before startup, make curl and tar available and permit the configured network
route to acquire the pinned NATS runtime. Coord verifies the archive,
binary and instance ownership. Its existing `coord start --binary PATH` option
can supply the same pinned executable when acquisition is unavailable.

The generated policy retains the existing wildcard network allowance,
credential approval prompt, global budget of 12,000 requests per minute and
host rate of 600. Edit `policy.toml` to select policy for your agent listeners.

If you need different endpoints, edit `config.toml` before startup. Relative
paths belong to this configuration directory. The administrative application programming interface
(Admin API) defaults to IPv4 loopback port 9090 and requires `data/admin_token`. Keep that token on the host.
An ordinary agent start creates its trusted listener; you do not need to add
example listeners to inspect that agent.

From a host terminal, check the configuration and start the selected instance:

```sh
safeyolo config check "$HOME/.safeyolo/config.toml"
safeyolo start
safeyolo status
safeyolo doctor
safeyolo --version
```

Startup runs the proxy in the background. Status reports `proxy_state` as
`running`; version prints the installed source and profile. Status and doctor
report the proxy process separately from each agent's runtime, control, command
and terminal state. These observations remain available when the Admin API is
down. An occupied endpoint or unreadable input fails startup and points to
`logs/proxy.log`. Resolve that named cause before repeating start.

When you finish using the instance, stop its proxy and owned Coord runtime.
Stop each agent separately; the top-level command leaves its sandbox intact.

```sh
safeyolo stop
```

## Public bootstrap availability

The [README quick start](../README.md#quick-start) downloads the official
release's `install-safeyolo.sh` through GitHub's Latest link. On 19 October 2026,
Latest selects the published production host
`host-c5ce76019b6c997e282ab05cea0212b492e945d2`. The downloaded installer binds
that host release internally; users do not need to type its source commit.
The [publication correction](https://github.com/craigbalding/safeyolo/issues/1053#issuecomment-6264370042)
records the channel change and verified installer identity.
The bootstrap downloads the host package and compatible public guest, prepares
missing Linux helpers and invokes the installed `agent launch` operation.
Current source retains this composition; a source capability alone does not
prove a clean installed journey on every platform.

The default instance is `$HOME/.safeyolo`. `SAFEYOLO_CONFIG_DIR` or
`SAFEYOLO_HOME` can select another root. The installer exposes `safeyolo` in
`$HOME/.local/bin` or `/usr/local/bin` when that directory is already on PATH.
It preserves unrelated commands and reports collisions. It can request sudo
for the host operations described in [Linux host preparation](#linux-host-preparation-in-new-source-bundles).
The command directory and link use sudo only if their nearest existing parent
is unwritable by your account. Configuration remains owned by your account;
the Linux guest tree has mapped sandbox owners.

The published `host-c5ce76019b6c997e282ab05cea0212b492e945d2` bundle says
“Only these command-entry operations require sudo.” This is misleading:
Linux host preparation and guest acquisition also use sudo.
Current source corrects the message. It does not change installation actions,
consent or privileges, and does not update an already published bundle.

Put installer options before `--launch`. Arguments after it go to the existing
`agent launch` command. Omitting `--launch` installs only. `--yes` accepts
listed host changes; setup, workspace access and optional authentication copying
still require their own host choices. The command entry works in the same
terminal after installation. A failed download must stop the procedure: do
not run a previous file left at the download name.

In a release that includes Codex launch support, use `safeyolo agent launch .
--harness codex` to select the shipped Codex setup and native package. The
default harness remains Claude. Codex uses authentication and settings in the
agent's persistent home; setup does not copy the host's `~/.codex`. For login
and explicit adoption of selected authentication, see
[First Codex login](../contrib/HOST_SCRIPT_GUIDE.md#first-codex-login).
Repeating the command reuses the matching agent, home, workspace and launcher.
The same tmux detach and host approval controls apply to both harnesses.
Earlier packages that report “available: claude” need an explicit update to a
release with this support. A source change alone does not update an installation.

Trust comes from HTTPS delivery by the official
`github.com/craigbalding/safeyolo` publisher. A checksum from the same release
checks integrity; it does not independently authenticate that publisher.
The bootstrap does not use a remote shell pipe or a package-manager install.
The release producer also writes a release-bound `install-safeyolo.sh` beside
the host archive and `SHA256SUMS`; the earlier `host-7a38` release lacks that
bootstrap asset.

New host packages also include a `-guest-download.tar.gz` release asset.
It contains the same compiled command and `package-info` as the complete host archive.
The producer receipt and same-release checksums bind these bytes to that archive;
they do not add an independent trust source. When this asset is available, the
bootstrap verifies it and downloads the compatible guest while the host archive
arrives. It passes the selected immutable OCI index to the normal installer.
Guest extraction, Linux host preparation and activation retain their existing
checks. An interruption removes partial transfers and retains verified blobs for
retry. Earlier immutable releases use the existing serial acquisition path.
The overlap does not establish the complete cold onboarding time; bandwidth
contention, extraction, setup and coding-client readiness still contribute.

When the verified early command supports `host-package gunzip`, the bootstrap
uses the command's bundled gzip decoder and pipes its output to the host's
existing tar extractor. The complete host archive must pass its release
checksum before decoding. A gzip or tar failure stops installation and removes
the private extraction. The ordinary package verifier still checks the complete
payload before activation. This uses the same `.tar.gz` assets and needs no
additional host tool. Earlier commands and paths without an early command use
tar's gzip extraction. Local retained-archive measurements do not establish a
cold onboarding saving.

### Tested onboarding scope

The [independent connected journey](https://github.com/craigbalding/safeyolo/issues/1050#issuecomment-6263430260)
used bootstrap source `45d8853a202c04c9f5f8ca772df410ae8ced1844`, explicit host
release `host-c5ce76019b6c997e282ab05cea0212b492e945d2`, workspace `.`, name
`first`, harness `claude` and launcher `tmux-window`. It completed the first task
on fresh Ubuntu 24.04.4 AMD64, ordinary
UID 1000, with an existing authorized Claude account in its normal host
locations. Bash, curl, tar, Git, system Python, tmux and suitable subordinate ranges
were present. Product/runtime/vendor caches, helpers and build tools were absent;
SafeYolo prepared missing helpers and its runtime. No new-account sign-in is
proved. Account transport and the observer were test preparation, not new user
commands. Their preparation is not an exhaustive shell-command count.

The shorter README commands use the release-bound public installer and launch
defaults: current directory, Claude, a workspace-derived name and, in a fresh
instance, `tmux-window`. Entry and default checks establish equivalence to the
accepted operations; they do not record another installed onboarding run.

The selected guest was `guest-2026-10-16.1082`, `linux/amd64`, compatibility
`v1`. The linked result records all package and guest identities. One task
produced matching Write/result events and a 627-byte host `index.html`.
That HTML task remains historical engineering evidence, separate from the
README's public example.
One task-free repeat returned to the same live runtime, launch and conversation
in 3.086 seconds. This is selected-state evidence, not a whole-home guarantee.
Earlier release, upgrade, refusal and retry proof retains its original scope.

Setup explains host changes before privilege and asks before workspace access
or selected authentication/settings copying. Claude and guest tools can read
copied authentication. Declining setup leaves saved agents/services unchanged.
Declining authentication copy uses Claude's supported `/login` route, without
proving a fresh sign-in here. Claude's own tool prompts are disabled;
SafeYolo's policy still applies.

The same-terminal host controls remain available after Ctrl-b then d in tmux.
Use `a`, choose a displayed request number, read its effect and enter `approve`,
`reject`, or Enter to leave it unchanged. Enter backs out of request review;
Enter at the host controls returns to Claude. `q` exits the client and retains
state. Stop agents separately when finished. See [agent launchers](agent-launchers.md)
for other supported terminals and [the operator guide](operator-guide.md) for
explicit inspection/recovery controls. Credential approval persistently allows
the selected fingerprints to the displayed destination for all current and
future agents in this instance, subject to network policy. The tested
destination was `api.anthropic.com`. Network approval instead grants reusable
access for the selected agent to the displayed host and port. Reject or leave
a request unchanged to keep it blocked.

The run records two cold product commands, 15 control interactions and seven
material decisions. The 4725 displayed words include logs, repeated screens
and observer/operator rework; they do not measure required reading. Read the
host's consent and approval effects before deciding. A required reference
detour or equally long wizard would fail #1053’s short-path outcome.

Cold product start to task Enter took 574.618 seconds; observed success took
585.095 seconds. These include operator handling and waits. Disjoint
human/provider/observer waits and measured reading remain unknown.
The 15-second goal is unmet, with no decision to accept or defer it.
A short README and warm timing do not complete that goal.

Clean Ubuntu ARM64 first-task onboarding remains unproved: the unknown
native-start failure and public-route limits remain open under #1050.
Clean Apple Silicon macOS onboarding also remains open. Accepted prepared
platform/release results retain their limits. The published ARM64 repair at
`8405786bb9d6f68d972cb3a1dd29cbfad6b1efcd` and current-source capabilities do
not establish those clean-platform journeys. #1050/#237 retain remaining
platform/accounting/timing work; #1053 supplies the short tested documentation.

## Repeat and retry with the current installer

The tested `host-c5ce7601` route and current source retain these behaviors.
The earlier `host-7a38` manual alternative still requires a fresh root.

A matching installation made with the current installer can be repeated.
Repeat retains its host, policy, credentials, identity, agent state and selected
guest without checking Latest or upgrading. An older or conflicting installation
is preserved; use its installed command or choose a separate `--root` and
`--command-dir`. A download failure leaves verified cache inputs available for
retry. Partial downloads are not activated. An interrupted final file move can
leave incomplete files; the next invocation reports them and preserves them.

## Upgrade host and guest components

Use a host release that contains `safeyolo upgrade`. For an older installed
host, download and unpack a release that provides this command. Set `BUNDLE`
to its absolute bundle directory and `ROOT` to the existing instance directory.
Then run the new command against that instance:

```sh
"$BUNDLE/bin/safeyolo" --root "$ROOT" upgrade --bundle "$BUNDLE"
```

The command selects the new host and retains the installed guest if compatible.
Do not run the fresh-instance installer to replace an existing host.

In your host terminal, inspect the selected host and guest before choosing a
target. The following commands use the default instance. For another instance,
put `--root ROOT` before `upgrade` and replace `ROOT` with its directory.

```sh
safeyolo upgrade status
```

The result shows the host source, build profile and package checksum identity.
It also shows the guest version, compatibility identifier and separate Open
Container Initiative (OCI) index, child-manifest and archive digests. A retained
previous pair appears after the first component change.

For a host-only upgrade, choose an official `host-COMMIT` release from the
[release list](https://github.com/craigbalding/safeyolo/releases). Replace
`COMMIT` below with that release's full 40-character commit. The command
downloads the changed host package. It retains the selected guest if the target
host is compatible. It does not discover, download or extract another guest.
The host package includes its own guest-side command helpers. Those helpers
must match the target host's source and profile, independently of guest-base
compatibility.

Use a maintenance window to stop the proxy, change the selected host and start
the proxy. Running agents keep their existing guest inputs. Stop and start an
agent when you want that agent to use the new selection.

```sh
safeyolo stop
safeyolo upgrade --release host-COMMIT
safeyolo start
safeyolo upgrade status
```

To select a host and guest together, add `--guest-index sha256:DIGEST` to the
upgrade command. Replace `DIGEST` with the complete immutable guest index
digest. The target index must declare the compatibility identifier required by
the target host. A host that requires another identifier is refused unless you
explicitly select its compatible guest. Guest-only upgrades retain their
existing [guest upgrade and rollback commands](guest-oci.md).

For an already unpacked target, use `upgrade --bundle UNPACKED_DIRECTORY`
instead of `--release`. Replace `UNPACKED_DIRECTORY` with the verified host
bundle directory. Both paths check complete package hashes, source/profile
identities, platform requirements, guest compatibility and the existing
configuration before activation. Repeating the same target retains the current
selection and reuses verified cached host archives and guest inputs.

The first host upgrade retains a separate `safeyolo-upgrade` executable in the
instance directory. It keeps recovery available after selecting an older host
that has no `upgrade` command. If the new host cannot start, use this executable
to restore the previous complete host/guest pair, then start the proxy. For the
default instance:

```sh
"$HOME/.safeyolo/safeyolo-upgrade" rollback
safeyolo start
```

For a custom instance, run its `safeyolo-upgrade` with `--root ROOT` before
`rollback`. Rollback makes no network request. Configuration, policy,
credentials, audit/log data and agent homes stay in the instance throughout
upgrade and rollback. Rollback does not undo user-state changes made while the
new pair was selected.

Activation changes one directory link after staging the complete pair. The
initial adoption requires a filesystem with atomic directory exchange, such as
the supported native Linux and macOS filesystems. A failed check, interrupted
download or unsupported exchange leaves the prior pair selected. Retry the same
upgrade command to finish interrupted staging or adoption. Keep the instance's
`versions`, `host-packages` and `upgrade-tools` directories and the persistent
guest store: current and rollback selections use their files.

## Other installation paths

The ordinary commands use `$HOME/.safeyolo`. To install a separate instance,
choose a fresh directory with `install.sh --root PATH` and select it with
`safeyolo --root PATH COMMAND`. For example, `safeyolo --root /path/to/instance status`
reads that instance; replace the path with the directory you installed. These
options do not move or convert existing state. Commands that edit files also
need the matching paths inside that instance.

Multiple instances are optional. To select an already installed second
instance at `$HOME/.safeyolo-other` for commands in the current terminal, use:

```sh
export SAFEYOLO_CONFIG_DIR="$HOME/.safeyolo-other"
safeyolo status
```

`SAFEYOLO_CONFIG_DIR` takes precedence over `SAFEYOLO_HOME`.
`SAFEYOLO_NATIVE_CONFIG_PATH` selects a TOML configuration file and takes
precedence over either directory variable. Explicit `--root PATH` or
`--config FILE` overrides environment selection. Relative paths in a selected
configuration belong to its directory. The ordinary default installation
requires none of these settings.

For a different command location, the installer accepts `--command-dir DIRECTORY`.
Select a directory already on your normal shell PATH. Disposable test instances
can use an owned command directory without replacing the host's command.
If a `safeyolo` command already occupies the chosen location, the installer
preserves it and reports the path before creating instance configuration.
Move or rename that command only if you intend to replace it, or choose
another command directory. An earlier command on PATH is also reported if
it prevents discovery; the new instance files remain available for recovery.

## Guest prerequisites

The tested release prepares its missing Linux prerequisites automatically.
The manual instructions below serve the earlier bundle and prepared/offline
alternatives.

### Manual Ubuntu preparation for the earlier bundle

The following instructions apply only to the earlier `host-7a38` manual
alternative, not the README quick start. Use your ordinary Ubuntu host account.

On Ubuntu 24.04, these commands install gVisor and its host tools, add the signed
gVisor package repository, and permit your account's required user namespaces.
They need host sudo and change package sources, your subordinate user/group
ID ranges and the AppArmor profile. That earlier installer does not perform this setup.
First read your account identity and both allocation files:

```sh
id
cat /etc/subuid
cat /etc/subgid
```

Each row is `account:first-ID:count`; its last ID is `first-ID + count - 1`.
Your account's name or numeric user ID from `id` needs a range covering
100000–165535 in both files, for example `your-login:100000:65536`.
If another account owns any part of that range, stop: that earlier release cannot
select a different range. Use a host where the range is available;
do not overlap another account's allocation. If your account already has a
covering range, keep it. Only when a file lacks your range and the range is free,
run its corresponding command:

```sh
sudo usermod --add-subuids 100000-165535 "$USER"
sudo usermod --add-subgids 100000-165535 "$USER"
```

Then install the host tools and gVisor, and load the namespace profile:

```sh
sudo apt-get update
sudo apt-get install -y curl ca-certificates gnupg uidmap acl iproute2 util-linux apparmor-utils
curl -fL -o gvisor-archive.key https://gvisor.dev/archive.key
sudo gpg --dearmor --yes -o /usr/share/keyrings/gvisor-archive-keyring.gpg gvisor-archive.key
echo 'deb [signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main' | sudo tee /etc/apt/sources.list.d/gvisor.list
sudo apt-get update
sudo apt-get install -y runsc
curl -fL -o apparmor-safeyolo-runsc https://raw.githubusercontent.com/craigbalding/safeyolo/7a38dff14e7e4eacb4095da732ffe06d7c7c5796/cli/src/safeyolo/templates/apparmor-safeyolo-runsc
sed 's|/usr/local/bin/runsc|/usr/bin/runsc|' apparmor-safeyolo-runsc > safeyolo-runsc
sudo install -m 0644 safeyolo-runsc /etc/apparmor.d/safeyolo-runsc
sudo apparmor_parser -r /etc/apparmor.d/safeyolo-runsc
```

### Prepared guests and offline inputs

The earlier `host-7a38` bundle requires the manual preparation above. Its
[retained runsc profile](../cli/src/safeyolo/templates/apparmor-safeyolo-runsc)
permits user namespaces for `/usr/local/bin/runsc`. For another runtime path,
adjust the profile before loading it; the Ubuntu package example above uses
`/usr/bin/runsc`.

For the Kernel-based Virtual Machine (KVM) platform, the host administrator
grants the operator and subordinate UID 100000 read/write access to `/dev/kvm`.
These steps preserve the existing namespace and hardware isolation setup.

Automatic acquisition uses the [OCI guest contract](guest-oci.md) and the registry client. No registry account, Docker, ORAS or local guest build is
needed. The installer stores verified blobs and prepared trees in
`$HOME/.local/share/safeyolo/guests`. Blobs use their archive digest; new Linux
source builds also distinguish prepared trees by their UID/GID mapping.
Keep that directory: installed Linux instances reference its trees.
`share/guest-selection.json` records the version, repository, compatibility,
consumer platform and selected index, child-manifest and archive descriptors.
Normal startup and restart use that selection without advancing a tag.
A failed pull, verification or extraction stops installation before initialization.
Use `safeyolo guest upgrade` to explicitly select a newer compatible default
guest, and `safeyolo guest rollback` to restore its previous selection. See the
[guest upgrade workflow](guest-oci.md#upgrade-or-roll-back-the-installed-default-guest)
for effects on running agents, pinned targets and recovery.

For explicit offline or contributor inputs, obtain prepared assets from the bundle supplier, or use the
[guest build instructions](../guest/README.md) to produce them separately.
Ubuntu uses `rootfs-tree`; macOS uses `Image`, `initramfs.cpio.gz` and
`rootfs-base.ext4`. The installer places them under the instance's `share/`.
Ubuntu needs the runsc and user-namespace setup described above.
macOS needs the installed `bin/safeyolo-vm` and `bin/vsock-term` helpers.
Supply their directory with `install.sh --root ROOT --platform-assets DIRECTORY`
at the fresh installation step. macOS copies the three image files with
Apple File System (APFS) clones. Ubuntu links the prepared `rootfs-tree`, preserving its sandbox ownership;
keep that shared tree available and immutable for the instance's lifetime.
Use `--no-guest-download` for a contributor or proxy-only installation that
will receive guest assets separately. That option preserves already prepared
inputs. It does not build a guest or fall back after a failed pull.

## Alpine host packages

Alpine host qualification and package publication are tracked in
[#370](https://github.com/craigbalding/safeyolo/issues/370).
The older Linux release archives linked above require glibc and do not run on
Alpine. Use a qualified prebuilt musl package from your bundle supplier.
The AMD64 package is named `safeyolo-linux-amd64-musl-production.tar.gz`.
Its `package-info` keeps `platform=linux-amd64` for guest selection and records
`libc=musl` and the required musl version. The installer checks the libc family
and version before it creates an instance.

On Alpine, use an ordinary account with sudo. Before running the public
bootstrap or unpacked installer, install Bash, curl, tar and the GCC runtime
library. These are runtime prerequisites; installation uses prebuilt product
executables and needs no compiler or Rust toolchain.

```sh
sudo apk add bash curl tar libgcc
```

Use the supplied package's ordinary `install.sh`. Host preparation installs
missing rootless tools with APK and uses shadow's locked allocator for missing
subordinate IDs. The guest remains the package's compatible OCI selection.
Alpine host qualification is separate from the accepted Alpine guest images.

## Linux host preparation in new source bundles

The tested newer Linux release and current source bundles include the complete
gVisor `release-20261005.0` payload for the bundle's architecture. The installer checks its checksums,
architecture, executable files and version. It uses that private runtime;
it does not replace a system `runsc` or add a package repository.
The earlier `host-7a38` manual alternative still needs its manual prerequisites.

The host-package producer downloads and verifies the pinned upstream runtime.
The public installer downloads the host archive with that runtime already
inside it. Selecting the bundled runtime needs no separate gVisor download.

Run the bundle's ordinary `install.sh` as your host account. Before changing
Ubuntu or Alpine, it lists missing packages, subordinate account ranges, file permissions
and the AppArmor profile, then asks for consent. `--yes` accepts those listed changes
for an unattended installation. The proxy and agents run without host root
privilege. Guest root maps to subordinate host user and group IDs, not host root.

Host preparation uses sudo to run `apt-get` on Ubuntu or `apk` on Alpine for missing packages, allocate
missing unused user ID (UID) and group ID (GID) ranges, and install or load the
required AppArmor profile. Runtime access uses `setfacl` to grant the selected
sandbox IDs traversal through private parent directories and read/execute
access to the selected runtime. This uses sudo only for paths your account
does not own. Activation uses the same access helper for the installed path.
The selected KVM backend also needs device access for its sandbox IDs, as
described below.

Linux guest acquisition separately uses sudo to extract the selected guest
files with numeric owners and access control lists (ACLs), inspect those owners
and ACLs, and remap them to your account's selected sandbox mapping when needed.
These operations prepare the rootless guest filesystem. They do not give the
agent host root privilege. If ordinary cleanup cannot remove a failed extraction
stage because of its mapped owners, cleanup uses `sudo -n` for that newly
created stage only. Completed host preparation remains if guest acquisition
fails; retry reuses valid inputs.

Preparation installs missing host tools from the host's existing package sources.
Alpine uses `shadow-subids`, `shadow-libs` and `util-linux-misc` for the
corresponding rootless tools and allocator. Ubuntu package names stay unchanged.
Guest acquisition needs tar's owner, ACL and extended-attribute options and
find's numeric owner predicates. Shared-directory startup needs unshare's
child-cleanup option. Alpine preparation installs `tar`, `findutils` or
`util-linux-misc` when the existing command lacks the required options,
including BusyBox variants.
It reuses suitable subordinate UID and GID ranges independently. If either
range is missing, shadow's locked account allocator selects an unused range.
Another account's allocation at 100000–165535 does not prevent installation.
Preparation preserves that allocation and uses different bases when needed.
It never renumbers existing accounts or changes a live guest tree.

Where Ubuntu restricts unprivileged user namespaces, preparation installs and
loads a separate AppArmor profile for this runtime's actual path. It grants
only the selected mapped root UID needed access through private runtime
directories. It preserves other users' and groups' effective file permissions.
It keeps AppArmor enabled and checks global namespace settings without changing
them. For an explicitly selected KVM backend, set
`SAFEYOLO_RUNSC_PLATFORM=kvm` when installing or preparing the host. Preparation
requires `/dev/kvm` and grants the mapped root GID required read/write access.
It repairs a selected root UID denial if required and preserves other ACL
permissions. The group grant remains when named-user ACL entries are reset.
If the device or its group permissions reset, run preparation again before
creating another sandbox. An already running KVM sandbox retains its open
virtual machine descriptor. `SAFEYOLO_RUNSC_PLATFORM=systrap` needs no KVM device.

To check or retry an installed source bundle after a host change, use the
commands for the backend you selected. For the default backend selection, run:

```sh
safeyolo host prepare
safeyolo doctor
```

For an explicitly selected KVM backend, run:

```sh
SAFEYOLO_RUNSC_PLATFORM=kvm safeyolo host prepare
SAFEYOLO_RUNSC_PLATFORM=kvm safeyolo doctor
```

Doctor's `linux` result gives the selected runtime path, version and origin,
the host UID/GID, the subordinate bases and the AppArmor profile. It also checks
required host tools and rootless namespaces. A failed host check keeps the
known runtime identity and gives a recovery action. The same
identity appears in the existing agent run metadata. A missing or invalid
selected payload stops startup with a repair action; it does not select
another runtime silently.

An explicit `--system-runsc /absolute/path/to/runsc` installer or host-prepare
option selects a system installation of the same tested release. It must have
the complete payload beside that executable, including `gvisor-bin`. Its
administrator remains responsible for those bytes and security updates.
Selecting a system runtime does not remove the bundled payload from the host
archive or the installed package.
A cold system comparison must count that common package cost and the separate
runtime download, verification and administrator setup.
Bundled runtime fixes arrive through normal SafeYolo host-package updates;
there is no separate runtime updater. SafeYolo ships `runsc` and its five
companion executables. It omits the separate containerd shim, which its launcher
does not call. `package-info` records the bundled
version, source and origin. `assets/licenses` contains the gVisor and dependency
notices.

Linux production bundles omit gVisor source-level debug information. Debug
bundles and the original pinned upstream archives retain that information.
Production bundles keep runtime metadata and function symbols.

The verified upstream tar is about 121 MB compressed for ARM64 and 130 MB for
AMD64; the ARM64 payload is about 268 MB unpacked. The host package includes
those runtime files. Its compressed size also includes the SafeYolo host
executables and assets; the upstream tar size is not the increase in the host
archive size. Bundling avoids an extra package source, changes to an unrelated
system runtime and system-package version drift. A system installation can
share its runtime across SafeYolo instances, but its package updates and
installation remain host administration. See the upstream
[distribution instructions](https://gvisor.dev/docs/user_guide/install/).

SafeYolo keeps the private pinned payload as its default. It avoids separate
runtime acquisition and administrator installation. The cold observations below
support that choice for the shipped package. The explicit system override remains
useful when an administrator needs to own or share the runtime.

Cold acquisition and setup were measured on 18 October 2026 on Ubuntu 24.04.4
AMD64 and Debian 13 ARM64. Both used the
[production host package at `c9ecb66b`](https://github.com/craigbalding/safeyolo/releases/tag/host-c9ecb66b462c2ba0c499f2322f6cfc5c142012da)
and the [public bootstrap at `85da60cf`](https://github.com/craigbalding/safeyolo/blob/85da60cf0da03a6356f9617d01e0e69abebdeb23/install.sh).
The package installer and executables were from `c9ecb66b`.
Each host used systrap as account UID/GID 1000, with prepared host tools,
subordinate bases 100000 and the same prepared guest tree for both controls.
Each control used new download, installation and command destinations with a
separate empty local cache. The system control downloaded and verified the same
pinned upstream payload. Its administrator installed all six executables and
notices under a new root-owned directory before selecting its absolute `runsc`
path with `--system-runsc`.

| Phase (seconds) | Ubuntu bundled | Ubuntu system | Debian bundled | Debian system |
| --- | ---: | ---: | ---: | ---: |
| Bootstrap download | 0.328 | 0.116 | 0.423 | 0.219 |
| Host archive acquisition and checksum | 2.590 | 4.362 | 14.533 | 13.488 |
| Host unpack and package verification | 5.856 | 7.554 | 1.930 | 1.958 |
| Separate upstream runtime download | — | 10.536 | — | 11.102 |
| Upstream checksum, unpack, payload check and administrator install | — | 10.472 | — | 0.521 |
| Installer package recheck and setup | 0.575 | 1.104 | 0.236 | 0.896 |
| Linux host preparation and file staging | 1.841 | 8.251 | 0.377 | 0.138 |
| Configuration, trust and activation | 0.658 | 0.691 | 0.310 | 0.202 |
| Doctor | 0.266 | 0.119 | 0.170 | 0.019 |
| Total from before acquisition through doctor | 12.317 | 43.445 | 18.099 | 28.683 |

Both controls acquired the full host archive: 190,882,862 bytes on AMD64 and
176,869,006 bytes on ARM64. The system control also acquired 129,604,888 upstream
runtime bytes on AMD64 and 120,770,227 on ARM64. Archive byte counts exclude the
bootstrap, checksum text and protocol overhead. All 18 observed commands on each
host exited successfully. All four doctor results reported Linux ready,
`release-20261005.0`, and the expected selected path and bundled or system origin.
Ubuntu installed a profile for each selected executable path. The bundled
controls also needed private runtime access grants; the administrator-owned
system payload needed no such grant. Debian needed no AppArmor profile.

These are single paired observations on prepared hosts. Required packages,
account allocations and guest assets were already available; their initial
setup is outside these totals. Host preparation still checked those inputs and
applied the path-specific profile and access changes above. File staging links
the prepared guest tree and copies host files. The Ubuntu guest fixture occupied
16 KiB; the Debian fixture occupied 719,436 KiB. These different fixtures do not
support an architecture performance comparison.

Upstream and content delivery network caches and operating system page caches
were not controlled. Phase times use a monotonic clock and sampled command
output. The phase rows omit some command and observation overhead; the total
includes that overhead. The system total was 31.128 seconds longer on Ubuntu and
10.584 seconds longer on Debian. The separate runtime download and setup cost
was 21.007 seconds on Ubuntu and 11.623 seconds on Debian. The common host-package
phases also varied, so the total differences cannot be attributed to runtime
distribution alone. These observations support avoiding the extra download and
setup; they do not establish a general speed ratio.

Both system totals include the bundled host archive. These results do not
measure a runtime-free host package or use of an already installed runtime.
Guest acquisition, proxy and guest startup, and first-task work were outside
this measurement. The approximately 15-second first-task target remains
unchanged. The full observations and accepted startup and isolation results
are recorded in [#240](https://github.com/craigbalding/safeyolo/issues/240).

A declined consent prompt makes no host changes. If sudo, allocation, namespace
or profile setup fails, the command reports the failed operation and any
completed changes. Keep those results. Repair the named prerequisite and retry;
valid prerequisites are reused. If no unused range exists, the administrator
must supply one within the host's allocation limits. Do not overlap another
account's range. If the host disables rootless namespaces, use a supported
host configuration; SafeYolo does not disable AppArmor or start agents as host
root to compensate.

Explicit `--platform-assets` inputs must already use a valid mapping for your
account. Preparation checks and retains that mapping. It preserves shared
prepared trees and refuses a conflicting saved mapping. Omit this option to
acquire a separate tree for the selected account mapping. `--no-guest-download`
retains contributor and proxy-only installation without host preparation,
unless you explicitly select `--system-runsc`.

## Configure and use an agent

Run these commands on the host as the account that owns the workspace and
instance. They use your default installation at `$HOME/.safeyolo`. The installed platform assets and host runtime must be ready.

In this example, `$HOME/work` is an existing directory owned by your account.
The commands create a new agent named `work` and run an interactive shell in
its guest, using your current terminal. For an existing agent, use its actual
name from `safeyolo status` and skip `agent create`:

```sh
safeyolo agent create work --workspace "$HOME/work" --memory 4096
safeyolo agent start work --foreground
```

Keep this guest shell open and use a second host terminal for
[inspection and approval](operator-guide.md#start-with-an-installed-instance).
The setup assigns a durable agent ID; you do not need to invent one.

To start a persistent background command, set `--command` when creating or
configuring the agent, then use `agent start work` without `--foreground`.
The shipped tmux-window launcher survives viewer loss. `agent attach work`
reopens the recorded session. Attach reports absence when the command is stopped;
it does not launch a replacement. `agent shell work` opens an independent shell.

Use `agent configure work --workspace PATH --memory MB` to change settings.
The output identifies next-start scope. The current sandbox keeps its existing
workspace and memory until one `agent stop work` / `agent start work` cycle.
For explicit shares, the host source must be a directory. Symlinks to directories
are accepted. Repeat `--mount HOST:GUEST[:ro]` to add shares. To share a file, put
it in a dedicated directory and mount that directory. Agent creation,
configuration and startup reject non-directory sources. Read-only shares reject
guest writes. An unowned workspace requires the existing explicit
`--dangerously-allow-unowned` override.

Use `mount protect PATH` to persist read-only protection for extra mounts of a
host directory and its descendants. Designation can precede directory creation.
`mount list` shows the resolved paths; `mount unprotect PATH` removes a selection.
See [protected host directories](CONFIGURATION.md#protected-host-directories)
for the explicit `:ro` mount and handling of saved writable mounts.

If a shell fails, run `agent diagnostics work`. The result names runtime and
control failures independently of proxy availability. On macOS it also checks
the private helper control and the SSH banner. A connection without a banner
reports the failed shell hop after the existing three-second deadline.
`agent recover work` uses the independent shared-home/PID-1 command probe;
it requires a running guest and idle command supervision, without SSH or a model.
If control recovery is unavailable, `agent stop work` still uses verified backend
identity. It does not signal an unrelated PID from a stale record.

Commander discovers the installed executable from its authenticated
instance endpoint. Named launch and status use the Admin API. Remote terminal
operations require the configured SSH route separately; the admin token supplies
no SSH access. Closing a terminal or Commander does not stop the background run.

## Check, show and apply

Open another terminal on the same host and account. The commands use the
default installation, as in the [operator guide](operator-guide.md#start-with-an-installed-instance).
Check the installed policy and read the effective policy from the running process:

```sh
safeyolo policy check "$HOME/.safeyolo/policy.toml"
safeyolo policy show
```

Check validates without writing the saved policy or evaluating live requests.
Show reads the active values and their source. Neither command spends quotas.
Show reports `active` when the saved source matches the active source.
Activation also prepares the runtime detectors. A policy-model check does not
guarantee that the running process can activate every detector configuration.

Prepare a separate TOML candidate before applying it. Copy your current policy
so the candidate retains agent identities, runtime settings and existing grants.
For example, the following entries allow the configured `work` agent one
host-owned HTTP origin at `127.0.0.1:8081` and deny other network destinations.
Replace the host, port and agent name for your environment. Merge these entries
into the candidate's existing tables; the fragment is not a complete policy.
This fragment uses an expanded agent table. Fresh creation instead writes
`agents = { work = { ... } }`. For that form, insert
`hosts = { "127.0.0.1:8081" = { egress = "allow" } }` inside `work`'s braces,
with a comma after the previous field. Keep its generated identity and other
settings. Appending a dotted table cannot extend an inline entry.

```toml
budget = 12000

[hosts]
"*" = { egress = "deny", unknown_creds = "prompt" }

[agents.work.hosts]
"127.0.0.1:8081" = { egress = "allow" }
```

Save the candidate as `candidate.toml` in your current directory. Apply it and
read the process state back:

```sh
safeyolo policy apply candidate.toml
safeyolo policy show
```

Apply validates the candidate, saves it atomically, and activates through the
authenticated Admin API. Exit zero and `status: active` confirm activation.
Persistence or activation failure returns nonzero. The existing transaction
restores the previous saved source after a failed activation. The allowed and
denied controls in the active policy remain effective.
If the saved policy was already inactive, rollback restores those saved bytes
and retains the actual pre-apply live generation. The saved/live mismatch
remains visible until you apply or restore the intended inputs.

When an external edit is invalid or activation cannot complete, show reports
`saved_differs` or `saved_unreadable`, preserves the active values in `effective`,
and names a repair action. Correct the input or filesystem access, then apply a
valid candidate. A whole replacement can repair an invalid saved document
without restarting the process. If the Admin API connection fails, the CLI
reports that activation is unconfirmed and tells you to restore that connection
before reading the active policy.

## Optional explicit agent listeners

Edit the selected instance's `config.toml` on the host only when you need these
additional listeners. Relative socket paths belong to that configuration root.

The following configuration illustrates two host-owned test listeners.
Ordinary agent lifecycle creates its own trusted listeners; these declarations
are for separately managed protocol clients. Here their names are `alice` and
`bob`. An agent name supplies trusted identity; a request header cannot replace it.

```toml
admin_port = 9090

[[listeners]]
agent_id = "alice"
socket_path = "data/alice.sock"
source_id = "10.0.0.2"

[[listeners]]
agent_id = "bob"
socket_path = "data/bob.sock"
source_id = "10.0.0.3"
```

The `source_id` values are host-owned declaration slots for these test listeners.
Restart the proxy after changing runtime listener configuration.

## Format and declare test context

In a host terminal, format context or atomically replace a file watched by your
test client. `run` and `agent` are required annotations. Values use
`[A-Za-z0-9_.:-]`; duplicate keys or more than 20 pairs are rejected. Named fields
are `run`, `agent`, `role`, `suite`, `subject`, `step`, `test`, `intent` and
`expect`. Repeat `--field KEY=VALUE` for additional safe fields. `--header` prints
the complete `X-SafeYolo-Test-Context` header line.

```sh
safeyolo test-context --run local-proof --agent alice --step one --write "$HOME/.safeyolo/context"
```

The file and stdout contain `run=local-proof;agent=alice;step=one`. A watcher
sees a complete old or new value. Validation or replacement failure returns
nonzero and preserves the previous file. Context is annotation; the listener
still supplies the trusted agent identity and evidence owner.

For declarations, use the private `data/agent_token` created by init,
and the chosen agent socket. This token has Agent API scope and cannot replace
the operator token. The following commands declare context on Alice's listener,
read it back, then clear it:

```sh
safeyolo test-context declare --socket "$HOME/.safeyolo/data/alice.sock" --token-file "$HOME/.safeyolo/data/agent_token" --run local-proof --agent alice --ttl 60
safeyolo test-context current --socket "$HOME/.safeyolo/data/alice.sock" --token-file "$HOME/.safeyolo/data/agent_token"
safeyolo test-context clear --socket "$HOME/.safeyolo/data/alice.sock" --token-file "$HOME/.safeyolo/data/agent_token"
```

Each command returns its Agent API JSON result. Declarations are process-local,
belong to the trusted source/agent pair, and expire at their granted TTL. The
policy caps TTL at `controls.test_context.declared_ttl`, default 900 seconds.
Declaring context does not itself enable injection. Select injection and target
hosts in your policy candidate, then apply it:

```toml
[controls.test_context]
action = "block"
inject_declared = true
declared_ttl = 900
target_hosts = ["origin.example"]
```

Replace `origin.example` with your intended host. Matching requests without valid
context return 428 under `block`; this response does not create a network approval.
An explicit valid header takes precedence over declared context. Clearing or
expiry removes the declaration from later requests. Bob cannot inherit Alice's
declaration or read Alice's trace or stored flows. Explanations also belong to
their agent unless the operator selects the limited peer read described below. The supported
Agent API readback paths are `/trace`, `/explain`, and `/api/flows/*`, with the
same bearer authentication and evidence scope.

## Selected evidence and network approvals

An operator can let Helper read one Worker's network approval and its diagnostic.
Helper can prepare that fixed action for a human decision. Approval grants
reusable network access for Worker at the recorded host and port until explicitly
removed. Rejection records a terminal disposition and leaves permissions unchanged.

This is the optional shared-approval protocol described in the
[Helper setup](operator-guide.md#optional-ask-another-agent-for-help). Worker
means the requesting agent; Helper means a separate assisting agent. The
examples here use configured names `worker` and `helper`; replace them with
your agents' names from `safeyolo status`. `agent create` assigns each durable
`agent_id` in the policy metadata. Keep those identities when editing policy.
Helper uses its normal Agent API token. Keep `data/admin_token` on the host.

First, read Worker's pending request with the operator client:

```sh
safeyolo approvals list --agent worker
```

A network prompt records a host-owned `approval_id`, its traffic `request_id`
and `details.network_action`. Equivalent retries retain the approval ID while
each attempt has its own traffic ID. The action binds Worker's durable identity,
the host, the port and the relevant network-policy revision. The pending record
also binds the method and resource. Inspection leaves the record pending.
See [pending approvals](operator-guide.md#inspect-a-pending-approval) for the
decision, expiry and restart behavior. Historical prompts remain readable.
Assisted decisions require a new durable request. Explicit policy controls
remain available.

Replace `REQUEST_ID` with the selected pending request and grant Helper its
diagnostic and approval reads:

```sh
safeyolo approvals share REQUEST_ID --agent worker --helper helper
```

The existing policy operation records only those selected reads. It
retains the rest of the policy and does not grant network permission. See the
[Helper commands](operator-guide.md#optional-ask-another-agent-for-help) to read the evidence,
prepare the exact action, and return it to the human decision.

For operators editing policy directly, the saved schema remains available. This
example is illustrative: replace both durable identities and `request_id` with
the host-owned identities and pending request you selected. Retain the rest of
your current policy.

```toml
[agents.worker]
agent_id = "ag-11111111111111111111111111111111"

[agents.helper]
agent_id = "ag-22222222222222222222222222222222"
evidence_reads = [{reader_id="ag-22222222222222222222222222222222", agent="worker", agent_id="ag-11111111111111111111111111111111", request_id="req-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", reads=["diagnostic", "approval"]}]
```

To use the policy-editing path, save the candidate as `selected-policy.toml` on
the host and apply it through the existing command:

```sh
safeyolo policy apply selected-policy.toml
```

The result reports `active`. Adding selected reads does not invalidate Worker's
network action. Removing a selected read or changing either agent identity
withdraws Helper's access. These reads return the fixed diagnostic and approval
projection. They do not expose captured bodies, headers, raw audit rows, other
requests or the untrusted preparation reason.

The shared operations use the following authenticated routes. Replace `ID` with
the selected request ID. Agent routes use the plain-HTTP internal Agent API
through Helper's configured proxy; operator routes use the host Admin API.

| Caller | Request | Result |
| --- | --- | --- |
| Helper | `GET /explain?request_id=ID` | Selected network diagnostic, action and trusted effect. |
| Helper | `GET /approvals/ID` | Canonical action and disposition. |
| Helper | `POST /approvals/ID/prepare` with `{"action":ACTION,"reason":"literal explanation"}` | Pending preparation of the exact action returned by the read; no policy change. |
| Operator | `GET /admin/approvals/ID` | Canonical action, actual reusable effect and separately labelled `untrusted_reason_text`, when retained. |
| Operator | `POST /admin/approvals/ID/readers` with `{"helper":"helper","helper_id":"CURRENT_DURABLE_ID"}` | Idempotent selected diagnostic and approval reads; no network grant. |
| Operator | `POST /admin/approvals/ID` with `{"decision":"approve"}` or `{"decision":"reject"}` | Canonical terminal disposition and exact action; the resolver does not accept caller-supplied scope. |

CLI and Commander use the common resolver for canonical network, credential
and gateway approvals. Repeat or concurrent decisions return the first terminal
result. A relevant policy or service change, or a recreated Worker, supersedes
a pending approval. Resolution returns 409 and needs a new request and human
decision. A changed action cannot be substituted during preparation. Helper
cannot call the operator mutation or grant itself evidence reads.

If the resolution response is lost, read `GET /admin/approvals/ID` before taking
another action. The host saves a decision receipt with its policy or grant
effect. The pending record and receipt let the resolver recover its result if
the audit write fails. Missing canonical state fails closed; logs cannot replace
it. Direct operator policy commands remain usable.
Raw audit files and separately authorised flow reads and exports retain their
existing access; selected Helper reads do not redact that operator evidence.

## Policy and runtime settings

`config.toml` owns paths, listeners and runtime settings. `policy.toml` owns
network and credential decisions, named lists, agent overrides, budgets,
advanced host rules, service policy and named controls. The fresh loader does
not read `addons.yaml`. Replaced fields, such as `addons`, `required`, `bypass`
and `global_budget`, produce named validation errors.

The [settings reference](settings.md) lists retained keys, defaults,
precedence, consumers and remaining host/helper owners. Capture, trace and audit
storage settings use their runtime tables in `config.toml`. Scanner, circuit and
test-context settings use named controls in `policy.toml`. Help, effective
policy, API reports and audit envelopes use these control names.

Check resolves named list files relative to the checked policy. Apply records
those file references as absolute paths so saving the candidate under the
instance root does not change which list the process loads.
Show displays the loaded members in `effective.lists`, their file paths in
`sources`, and each referenced file's current status in `list_files`. A changed
or unreadable list produces a saved/live mismatch, including changes that retain
the original file timestamp. The displayed members remain those used by the
active compiler until a valid policy reload or apply succeeds.

For example, network enforcement and credential enforcement have separate
actions. These explicit values retain the default blocking behavior:

```toml
[controls.network]
enabled = true
action = "block"
homoglyph = true

[controls.credentials]
enabled = true
action = "block"
```

The alternative `warn` action records a finding while permitting forwarding.
Networking permission does not grant credential permission. An approved
credential remains scoped to its destination and fingerprint; show includes
the actual saved grant in the effective host entry. Existing service and
approval operations retain their separate owners.

## Build a bundle

From a clean committed checkout on the target host, use Bash and the Rust
toolchain pinned in `proxy/rust-toolchain.toml`. Linux also needs readelf and
ldd, curl and a tar with zstd support for the pinned gVisor payload. GNU Linux
build hosts need musl-tools; Alpine build hosts need build-base and musl-dev. The
assembler verifies the downloaded archive and reuses its checked cache.
On the Linux build host, install the Rust musl target for its architecture:
`x86_64-unknown-linux-musl` on AMD64 or `aarch64-unknown-linux-musl` on ARM64,
using `rustup target add TARGET`. The default builder links the two guest
helpers statically with musl so Alpine guests need no glibc compatibility
package. GNU host executables keep their existing target. On native musl build
hosts, the assembler links host executables dynamically so host preparation can
load shadow's allocator. Those host executables require Alpine's `libgcc` runtime.
Guest helpers remain static. The guest compiler is `musl-gcc` on GNU hosts and
`cc` on native musl hosts; target-specific Cargo linker and C compiler overrides remain
available. An explicit `SAFEYOLO_GUEST_TARGET` keeps the configured cross-build
target and its target-specific artifact directory.
macOS needs Command Line Tools and a signed VM helper build. Prepared
runtime inputs contain the `tmux` executable for this host. The assembler
copies its resolved non-system libraries. This Ubuntu example selects
`/usr/bin/tmux`, so `/usr/bin` is the runtime input directory.
For prepared runtime inputs, keep their required notices in a `licenses`
directory alongside `tmux`. The assembler includes those notices and the
project's license in the bundle.

```sh
./scripts/build_host_packages.sh --output "$HOME/safeyolo-packages" --runtime-artifacts /usr/bin
```

The command builds the three host executables and matching Linux guest helpers,
then writes one production archive. Use `--profile debug` for the debug profile.
If matching binaries already exist, supply `--artifacts HOST_DIRECTORY` and
`--guest-artifacts LINUX_DIRECTORY`. Each guest executable requires its
`.version` and `.sha256` receipt from `scripts/build_guest_command.sh`.
Host and guest source/profile identities must match the clean checkout.

On macOS, also supply `--vm-artifacts DIRECTORY`. Build the signed helper with
`make -C vm build`, then stage `safeyolo-vm`, `safeyolo-vm.dSYM` and
`safeyolo-vm.build-info.json` in that directory. The production metadata comes
from `vm/.build/build-info.json`. For a debug bundle, use `make -C vm debug`
and the matching helper, symbols and metadata under `vm/.build/development`.
Also stage the prepared Linux `vsock-term` executable there. The terminal
helper's `.version` receipt is `vsock-term commit=FULL_SOURCE_COMMIT`; its
`.sha256` receipt contains the built executable's SHA-256. Supply matching
arm64 Linux guest artifacts with `--guest-artifacts`; cross-building their
Rust target needs an explicitly prepared Linux cross toolchain. The assembler
verifies the helper's signing posture and source before packaging. Artifact
rebuilding is a developer operation, separate from ordinary installation.

Source installation runs the same assembler and installer without retaining an
archive. It requires another fresh root if you already installed the bundle.
On Ubuntu with the inputs above and prepared guest assets at
`$HOME/safeyolo-platform` (replace that path with your directory):

```sh
./install.sh --root "$HOME/.safeyolo" --runtime-artifacts /usr/bin --platform-assets "$HOME/safeyolo-platform"
```
