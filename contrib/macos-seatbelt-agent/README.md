# Contained SSH development on macOS

Give a coding agent a macOS shell for builds, tests, PTYs, and tmux. The Seatbelt
profile permits home-directory writes and home Unix sockets; it denies IP
networking and access to other users' homes. Seatbelt is defense in depth:
`sandbox-exec` is deprecated, and process visibility is incomplete. See the
[tested limits](VALIDATION.md#measured-limitations).

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
- The client needs an SSH destination configured through its approved proxy
  transport. This contribution installs the Mac endpoint, not that route.

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
  test -r "$key"
  ssh-keygen -lf "$key.pub"
  cat "$key.pub"
)
```

## 2. Install the Mac entry

**Run on the target Mac, in an administrator or root terminal, from the checkout's
`contrib/macos-seatbelt-agent` directory.** Paste the public-key line from step 1
when prompted. The block replaces installed entry files and authorized keys;
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
  ssh-keygen -lf "$staging/authorized_keys"
  xcrun clang -Wall -Wextra -Werror -O2 agent-entry.c -o "$staging/agent-entry"
  codesign --force --sign - --options runtime --timestamp=none "$staging/agent-entry"
  codesign --verify --strict "$staging/agent-entry"
  sudo install -d -o root -g wheel -m 755 "$entry"
  sudo install -o root -g wheel -m 755 "$staging/agent-entry" agent-session "$entry/"
  sudo install -o root -g wheel -m 644 agent-dev.sb "$staging/authorized_keys" "$entry/"
)
```

## 3. Enable SSH entry

**Still on the Mac, in the administrator/root terminal and the same contribution
directory.** Before running this block, match the printed fingerprint to step 1
and [verify entry ownership and ACLs](REFERENCE.md#entry-ownership).
The compiled entry must become the login shell before SSH rules are installed.
`configure-ssh` backs up and validates SSH configuration and restores it on failure.

```sh
(
  set -e
  sudo dscl . -create /Users/sy-agent UserShell \
    /Library/PrivilegedHelperTools/seatbelt-agent/agent-entry
  sudo ./configure-ssh
)
```

## 4. Test a fresh login

**Run inside the client agent, as its normal user, from any directory.** Enter
the SSH destination or alias whose approved proxy transport you configured.
Keep the Mac administrator terminal open while testing.

```sh
(
  set -e
  printf 'Configured SSH destination or alias: '
  IFS= read -r destination
  ssh -i "$HOME/.ssh/id_ed25519_sy_agent" -l sy-agent -- "$destination" id
)
```

The output should identify `sy-agent`. A successful login checks entry plumbing;
use the [disposable boundary probes](REFERENCE.md#validation-and-adaptation) to
check confinement. For interactive work, omit the final `id` argument.

See the reference for [tmux and file transfer](REFERENCE.md#daily-work-and-tmux),
[optional network access](REFERENCE.md#optional-network-access), and
[custom SSH configurations](REFERENCE.md#custom-ssh-configurations).
