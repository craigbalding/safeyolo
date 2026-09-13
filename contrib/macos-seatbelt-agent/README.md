# Contained SSH development on macOS

Give your SafeYolo agent a shell on a physical Mac when a VM won't do.
Seatbelt allows writes in the dedicated account's home and denies IP networking
and access to other users' homes. The `sandbox-exec` interface is deprecated; see
[why we use Seatbelt](REFERENCE.md#why-seatbelt) and its
[tested limits](VALIDATION.md#measured-limitations).

[Residual process visibility is an accepted risk](REFERENCE.md#process-visibility-and-accepted-risk).
Use a dedicated account; host commands run as that user may be visible to the agent.

## 1. Ask your agent for an SSH key

The client needs OpenSSH and `socat`, both included in the standard SafeYolo
image. Paste this into your client agent:

```text
Prepare an SSH key for access to my Mac, as your normal user without sudo.
Keep existing key files. If neither ~/.ssh/id_ed25519_sy_agent nor its .pub
file exists, create the key with:

mkdir -p -m 700 ~/.ssh
ssh-keygen -t ed25519 -N '' -C safeyolo-seatbelt-client -f ~/.ssh/id_ed25519_sy_agent

Return the public-key line from:
ssh-keygen -y -P '' -f ~/.ssh/id_ed25519_sy_agent

Keep the private key inside this agent. If a command fails, report the error.
```

## 2. Set up the Mac

On the Mac, use your existing administrator account for this section. You need
Command Line Tools and a SafeYolo checkout. These commands assume
`/Users/sy-agent` and `/opt/homebrew`;
[customize these first](REFERENCE.md#account-and-toolchain-customization) if your
account or toolchain differs.

### Create the account

From any directory, create a **Standard account with the short name `sy-agent`**
and home `/Users/sy-agent`. The command prompts for the new account's password;
keep that password outside the agent. The agent can read and change everything
in its home. If the account already exists, skip creation and follow the
[existing-account checks](REFERENCE.md#reuse-an-existing-account).

```sh
sudo sysadminctl -addUser sy-agent -fullName "SafeYolo Agent" -password -
```

Stop if creation reports an error. The account must have no sudo grants;
`configure-ssh` checks this before changing its login shell.

### Enable Remote Login and allow the account

From the same administrator terminal, enable the Mac's SSH service (Remote
Login). The terminal needs Full Disk Access to change this
setting; see [Remote Login troubleshooting](REFERENCE.md#remote-login-troubleshooting)
if it is not already granted.

```sh
sudo systemsetup -setremotelogin on
```

Stop on an error. After enabling the service, inspect its allowed-user group:

```sh
dseditgroup -o read com.apple.access_ssh
```

If the group exists, add `sy-agent` with the following command. It preserves
the group's existing members. If the read reports that the group does not
exist, follow the [missing-group guidance](REFERENCE.md#remote-login-troubleshooting)
before continuing. Stop on any other error.

```sh
sudo dseditgroup -o edit -a sy-agent -t user com.apple.access_ssh
```

### Install and configure the confined login

From the checkout root, run these commands individually, stopping on any error.
Replace `CLIENT_PUBLIC_KEY` with the line your agent returned. The commands
replace the installed launcher files and append the key, preserving other agents'
access. `sudo` writes to the
protected system directory and may prompt for your password.

```sh
cd contrib/macos-seatbelt-agent
xcrun clang -Wall -Wextra -Werror -O2 agent-shell-launcher.c -o agent-shell-launcher
codesign --force --sign - --options runtime --timestamp=none agent-shell-launcher
sudo install -d -o root -g wheel -m 755 /Library/PrivilegedHelperTools/seatbelt-agent
sudo install -o root -g wheel -m 755 agent-shell-launcher agent-session /Library/PrivilegedHelperTools/seatbelt-agent/
sudo install -o root -g wheel -m 644 agent-dev.sb /Library/PrivilegedHelperTools/seatbelt-agent/
printf '\n%s\n' 'CLIENT_PUBLIC_KEY' | sudo tee -a /Library/PrivilegedHelperTools/seatbelt-agent/authorized_keys > /dev/null
sudo chmod 644 /Library/PrivilegedHelperTools/seatbelt-agent/authorized_keys
```

[Authorize the SSH route](REFERENCE.md#approved-ssh-route) on the SafeYolo host.
Replace `mac.example.net` and `22` below with the approved destination as seen
by the proxy.

`configure-ssh` requires the existing account and Remote Login access prepared
above. It does not create the account, enable the SSH service, or change the
allowed-user group. The command sets `agent-shell-launcher` as the account's
login shell, requires public-key authentication, and disables forwarding.
It checks the installation
and backs up the previous SSH configuration and login shell for
[recovery](REFERENCE.md#setup-recovery). If connected to the Mac over SSH,
keep that connection open until the agent's login works.

From the same directory on your Mac, run:

```sh
sudo ./configure-ssh --host mac.example.net --port 22
```

## 3. Give the connection instructions to your agent

The generated instructions use the default HTTP proxy at `127.0.0.1:8080`;
see [other proxies](REFERENCE.md#client-proxy-options) if yours differs.
Paste the client instructions printed by `configure-ssh` into your agent.
It configures SSH through its proxy, installs your Mac's public host key, and
reports whether the login succeeded with the expected account UID.

See the reference for [interactive use and file transfer](REFERENCE.md#daily-work-and-tmux)
and [optional profile testing](REFERENCE.md#validation-and-adaptation).
