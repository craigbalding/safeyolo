# Contained SSH development on macOS

Give a coding agent a macOS shell for builds, tests, PTYs, and tmux. The Seatbelt
profile permits home-directory writes and home Unix sockets; it denies IP
networking and access to other users' homes.

Seatbelt gives native Mac tools and their child processes operating-system
restrictions. Apple uses Seatbelt policies in WebKit, and OpenAI Codex and
Anthropic Claude Code use Seatbelt for macOS sandboxing. The `sandbox-exec`
launcher is deprecated; this custom profile remains defense in depth, with
incomplete process visibility. See [why we use Seatbelt](REFERENCE.md#why-seatbelt)
for the rationale and sources, and the [tested limits](VALIDATION.md#measured-limitations).

## Before you start

- First try the setup on a disposable Mac VM. SafeYolo setup does not install it.
- On the target Mac, enable Remote Login and have Command Line Tools and a
  SafeYolo checkout available.
- Create or reuse the Standard account `sy-agent`, home `/Users/sy-agent`, with
  no sudo grants, admin membership, personal credentials, or agent-controlled
  login path outside this entry. Keep its password with the operator.
- Save work and end existing coding shells and tmux servers under that account.
  Keep your separate administrator terminal open throughout installation.
- These commands use `/opt/homebrew` as the toolchain root. For another account
  or toolchain, [set the build options first](REFERENCE.md#account-and-toolchain-customization).
- The SafeYolo operator must [authorize the SSH route](REFERENCE.md#approved-ssh-route)
  and give the client its destination host and port. The client needs Python 3.9 or newer,
  OpenSSH, and this checkout. The Mac and proxy can be on different machines.

## 1. Create the client key

**Run inside the client agent, as its normal user, from any directory. Do not
use sudo.** This creates an unattended SSH key in its persistent home and reuses
an existing complete pair. Give only the printed public-key line and fingerprint
to the Mac operator. The private key stays with the client.

```sh
(
  set -eu
  umask 077
  mkdir -p "$HOME/.ssh"
  key="$HOME/.ssh/id_ed25519_sy_agent"
  if [ ! -e "$key" ] && [ ! -e "$key.pub" ]; then
    ssh-keygen -q -t ed25519 -N '' -C 'safeyolo-seatbelt-client' -f "$key"
  fi
  derived=$(ssh-keygen -y -P '' -f "$key")
  derived=$(printf '%s\n' "$derived" | awk '{print $1, $2}')
  recorded=$(awk '{print $1, $2}' "$key.pub")
  [ "$derived" = "$recorded" ] || {
    printf 'Existing client key pair does not match; keep it and resolve the mismatch first.\n' >&2
    exit 1
  }
  ssh-keygen -lf "$key.pub"
  cat "$key.pub"
)
```

## 2. Install the Mac entry

**Run on the target Mac, in an administrator or root terminal, from the checkout's
`contrib/macos-seatbelt-agent` directory.** Paste the public-key line from step 1
and its `SHA256:…` fingerprint when prompted. A mismatch stops installation.
The block replaces installed entry files and authorized keys;
it stops on failure. It leaves the account's login shell unchanged at this stage.

```sh
(
  set -eu
  entry=/Library/PrivilegedHelperTools/seatbelt-agent
  staging=$(mktemp -d)
  trap 'rm -rf "$staging"' EXIT
  printf 'Paste the client public-key line, then press Return: '
  IFS= read -r public_key
  printf '%s\n' "$public_key" > "$staging/authorized_keys"
  key_info=$(ssh-keygen -lf "$staging/authorized_keys")
  fingerprint=$(printf '%s\n' "$key_info" | awk '{print $2}')
  printf 'Client fingerprint from step 1 (SHA256:…): '
  IFS= read -r expected
  [ "$fingerprint" = "$expected" ] || {
    printf 'Client fingerprint does not match; nothing installed.\n' >&2
    exit 1
  }
  xcrun clang -Wall -Wextra -Werror -O2 agent-entry.c -o "$staging/agent-entry"
  codesign --force --sign - --options runtime --timestamp=none "$staging/agent-entry"
  codesign --verify --strict "$staging/agent-entry"
  sudo install -d -o root -g wheel -m 755 "$entry"
  sudo install -o root -g wheel -m 755 "$staging/agent-entry" agent-session "$entry/"
  sudo install -o root -g wheel -m 644 agent-dev.sb "$staging/authorized_keys" "$entry/"
)
```

## 3. Enable SSH entry

**Still on the Mac, in the same administrator terminal and contribution directory.**
The helper checks the account, entry permissions and ACLs, signature, profile,
and SSH settings. It then changes
both the login shell and SSH admission: public-key authentication is required and
forwarding is disabled. It backs up both previous states and restores them on
failure; see [recovery and its scope](REFERENCE.md#setup-recovery).
Give the printed UID and **Mac host public key** to the client alongside the
approved host and port. This key identifies the server; it is different from step 1's key.

```sh
(
  set -e
  sudo ./configure-ssh
  cat /etc/ssh/ssh_host_ed25519_key.pub
)
```

## 4. Configure the client and test a fresh login

**Inside the client agent, as its normal user, in this checkout's
`contrib/macos-seatbelt-agent` directory.** Run the helper and enter the host,
port, and Mac host public key supplied by the operator. It writes a dedicated
configuration under `~/.ssh/seatbelt-agent/`, preserving previous files as
`.before` backups on repeat runs. Keep the Mac administrator terminal open.
The test uses the existing SafeYolo proxy and pins the supplied server key.

```sh
(
  set -e
  ./configure-client
  ssh -F "$HOME/.ssh/seatbelt-agent/config" seatbelt-mac id
)
```

Compare `uid=` with the UID printed in step 3; the profile can prevent macOS
from displaying its account name. A successful login checks entry plumbing;
use the [disposable boundary probes](REFERENCE.md#validation-and-adaptation) to
check confinement. For interactive work, omit `id`. A 428 response requires operator approval in
`safeyolo watch` or Commander before retrying; a 403 is a policy denial.

See the reference for [tmux and file transfer](REFERENCE.md#daily-work-and-tmux),
[optional network access](REFERENCE.md#optional-network-access), and
[custom SSH configurations](REFERENCE.md#custom-ssh-configurations).
