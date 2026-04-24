# SafeYolo Security Audit (pre-v1)

**Auditor:** Claude (red-team analyst role)
**Date:** 2026-04-24
**Branch audited:** `master` @ 826db59 (PR #196 tip)
**Audit branch:** `claude/security-audit-safeyolo-BdT1N`

## Scope

Per operator direction:

- **A** Host-side privileged operations (sudo, setuid, capabilities)
- **B** Sandbox escape surface (gVisor OCI spec, userns, caps, mounts, AppArmor, macOS VZ entitlements)
- **D** Supply chain (build scripts, host scripts, rootfs hooks, dependency pinning)
- **Out of scope:** (C) Proxy/PDP logic (credential detection, policy eval, admin API auth correctness) — except where it touches A/B/D

**Threat model:** honest operator + malicious agent inside the sandbox. Focus: undocumented gaps and regressions; pre-v1 design-level issues flagged but not weighted.

## Method

1. Enumerate every privileged operation on the host (grep for sudo/setuid/cap/chmod/chown).
2. Read each path end-to-end; assess blast radius.
3. Diff against recent PRs (#187, #190, #194, #195, #196) for regressions.
4. PoC only when the path "looks safe but isn't" or is too complex to assess by inspection.

## Status

| Section | Status |
|---------|--------|
| 1. Privileged-op catalog (A) | **done** |
| 2. `safeyolo setup` review (A) | **done** |
| 3. Linux sandbox: userns/OCI/caps/mounts (B) | **done** |
| 4. Proxy bridge / identity attribution (B) | **done** |
| 5. macOS VM helper + entitlements (B) | **done** |
| 6. Guest-init and config share (B) | **done** |
| 7. Supply chain: builds, host scripts, rootfs hooks (D) | **done** |
| 8. Dependency pinning (D) | **done** |
| 9. Regression diff: #187, #190, #194, #195, #196 | **done** |
| 10. Findings summary | **done** |

## Privileged-op catalog (Section 1)

Host-side sudo/privileged surface, as of master @ 826db59:

### 1.1 Interactive sudo (operator-prompted, one-time)

| Path | Effect | Source |
|------|--------|--------|
| `safeyolo setup` → `_install_apparmor_profile()` | `sudo tee` AppArmor profile → `/etc/apparmor.d/safeyolo-runsc`, `sudo chmod 0644`, `sudo apparmor_parser -r` | `cli/src/safeyolo/commands/setup.py:34-80` |
| `safeyolo setup` → `_apply_kvm_udev_rule()` | `sudo tee` udev rule → `/etc/udev/rules.d/99-safeyolo-kvm.rules`, `sudo setfacl -m u:100000:rw /dev/kvm` | `cli/src/safeyolo/commands/setup.py:83-108` |
| `safeyolo setup sudoers` (opt-in subcommand) | `sudo tee` → `/etc/sudoers.d/safeyolo` with Linux mount/umount/cp/chown fallback for rootfs extraction; `sudo chmod 0440`; `sudo visudo -c` | `cli/src/safeyolo/commands/setup.py:390-472`, `cli/src/safeyolo/templates/safeyolo-linux.sudoers` |

### 1.2 Runtime — operator uid only (no sudo)

| Operation | Uses |
|-----------|------|
| `_start_userns()` | `unshare -Un sleep 86400`, `newuidmap`, `newgidmap` (setuid helpers, not sudo) | `cli/src/safeyolo/platform/linux.py:257-312` |
| `setfacl -m u:100000:rwx <runsc_root>` | `setfacl` on a user-owned directory — no sudo | `cli/src/safeyolo/platform/linux.py:551-566` |
| `runsc create/start/exec/delete/kill/state` | via `nsenter --user --net --target` into the userns; rootless | `cli/src/safeyolo/platform/linux.py:583-826` |
| `systemd-run --user --scope` | cgroup limits via user delegation | `cli/src/safeyolo/platform/linux.py:350-366` |

### 1.3 Build-time sudo (developer machine, not runtime)

| Script | sudo operations |
|--------|-----------------|
| `guest/build-rootfs.sh` | `sudo umoci unpack`, `sudo mv`, `sudo mkdir`, `sudo tee`, `sudo cp`, `sudo chroot`, `sudo rm -rf` | `guest/build-rootfs.sh:209-259, 133, 201` |
| `cli/src/safeyolo/vm.py` (macOS Lima shell) | `sudo -E bash -c` inside Lima VM (Lima user has NOPASSWD) | `cli/src/safeyolo/vm.py:515-522` |
| `contrib/kali-pentest/build-kali-rootfs.sh`, `contrib/alpine-minimal/build-alpine-rootfs.sh` | Run as VM-root via the build pipeline; install NOPASSWD sudo inside the rootfs for agent-user apt/apk commands | `contrib/*/build-*.sh` |

### 1.4 In-guest setuid drop

| Path | Mechanism | Notes |
|------|-----------|-------|
| `vsock-term.c` (macOS VZ guest) | `setgid(gid); initgroups("agent", gid); setuid(uid);` → `execvp` the agent | `guest/vsock-term.c:211-216` — see Finding L-01 |
| `guest-init-per-run.sh` → `runsc exec --user 1000:1000` | runsc-driven uid switch; host CLI invokes as uid 1000 | `cli/src/safeyolo/platform/linux.py:758-790` |
| `su agent -l` | Invoked inside guest init; drops host-uid to container uid 1000 | `cli/src/safeyolo/guest-init-per-run.sh:147` |

### 1.5 macOS (build-time + one-time install)

- `vm/Makefile install` — signs + installs Swift helper to `/usr/local/bin/safeyolo-vm`. Needs codesign + VZ entitlement; requires sudo to write `/usr/local/bin/`. (Not yet read in detail — pending.)

## Findings (in progress)

Severity scale: **Critical / High / Medium / Low / Informational**.

### H-01 — mitmproxy listens on `0.0.0.0`, PROXY-v2 agent identity is auto-trusted from any TCP source (High)

**Files**
- `cli/src/safeyolo/proxy.py:354` — `cmd = [mitmdump, "--listen-host", "0.0.0.0", "-p", str(proxy_port)]`
- `addons/proxy_protocol.py:105-151` — `ProxyProtocolAddon.next_layer` unconditionally parses a PROXY-v2 header from any inbound TCP stream and rewrites `context.client.peername` with the header's `src_ip`, logging the (attacker-controlled) `agent_name`.

**Stated hardening that this contradicts**
- `SECURITY.md:§Minimize trust`: "Admin API binds to localhost only and requires token auth."
- `docs/security-verification.md:§Proxy Hardening`: "Bind address | Loopback by default; listen host configurable".
- `SECURITY.md:§Network and transport controls`: "Identity is stamped by the host-side bridge … so a compromised agent cannot forge another agent's identity."

The last claim holds *for agents in the sandbox* (they have no external interface). It does not hold for any non-agent attacker who can reach the proxy TCP port — and by default that is every host on every network the operator's laptop is attached to.

**Exploit path (non-PoC — inspection only, since the proxy isn't running in this container)**

1. Operator runs `safeyolo start` on a laptop attached to e.g. an airport wifi. Port 8080 is open on every network interface.
2. Any LAN peer opens `tcp:<operator-lan-ip>:8080`.
3. Peer sends a synthetic PROXY-v2 header with `src_ip=10.200.0.0` (some agent's attribution IP) and `agent_name="boris"`, followed by `CONNECT api.anthropic.com:443 HTTP/1.1`.
4. `proxy_protocol.ProxyProtocolAddon.next_layer` accepts the header and rewrites `peername`. All downstream addons (`service_discovery`, `network_guard`, `credential_guard`, `service_gateway`) now treat the flow as originating from agent `boris`.
5. Any operator-approved credential injection for `boris` → `api.anthropic.com` fires, because all the gates key on the (now-spoofed) agent identity.

**Why I'm not filing this as Critical**
- Under the strict threat model (honest operator + malicious agent inside sandbox only), the agent has no path to the TCP port in the first place, so the exposure is defence-in-depth rather than sandbox escape.
- The admin API (port 9090) is bearer-token auth with `secrets.compare_digest` (`addons/admin_api.py:56-101`), so it is not wide-open.

**Recommendation**
- Default `--listen-host 127.0.0.1`. Gate any non-loopback bind behind an explicit config flag + startup warning.
- In `proxy_protocol.py`, require the source IP of the inbound TCP to match a known trust list (127.0.0.0/8 at minimum; ideally only the UDS bridge peer). Alternatively, peek at `client.peername` pre-rewrite and only honour the PROXY-v2 header when it arrives from the bridge.
- Same hardening for `admin_api.py` (`HTTPServer(("0.0.0.0", port), …)` at lines 1354 and 1377) — bind to `127.0.0.1` by default.

### M-01 — admin_api binds `0.0.0.0:9090` by default; SECURITY.md claims loopback-only (Medium)

**Files**
- `addons/admin_api.py:1354, 1377` — `self.server = HTTPServer(("0.0.0.0", port), AdminRequestHandler)`

Auth is correctly implemented (bearer token via file, constant-time compare, per-request auth gate), so this is not immediately exploitable. But:
- The stated model in `SECURITY.md` is "binds to localhost only"; that is not what the code does.
- On a laptop on a hostile LAN, a bad actor on the LAN can grind the bearer token (mitigated by entropy of the randomly generated token, but not rate-limited), brute-force probes leak via the auth-failure event stream, and any token leak (e.g. into a shell history uploaded to a backup, into a workflow log, into a copy-paste) becomes a remote compromise path rather than a local one.

**Recommendation**
- Bind to `127.0.0.1` by default. Provide an explicit env/config knob if someone actually needs the remote-admin case.
- Add a startup warning if the bind host is not loopback.

### L-01 — `vsock-term.c`: unchecked setgid/setuid return values (Low)

**Files**
- `guest/vsock-term.c:211-216`

```c
setgid(gid);
initgroups("agent", gid);
setuid(uid);

execvp(argv[cmd_start], &argv[cmd_start]);
```

None of the privilege-drop calls' return values are checked. If any one of them fails (e.g. the bounding set is changed in a future refactor, or an unusual invocation path leaves the caller in a state without `CAP_SETGID`), the process continues with partially-dropped privileges and execs the agent binary. Worst case: `setgid` fails, `setuid` succeeds — agent runs as uid 1000 with gid 0 (root's supplementary groups retained via the silently-failed `initgroups`).

Under the current init path (`vsock-term` is launched by `guest-init-per-run.sh` inside the guest, as PID 1 with full caps), the calls don't fail in practice. But this is a classic CWE-252 footgun that shouldn't survive code review — it'd be caught by almost any C linter, and it becomes a live bug the moment the calling context changes.

**Recommendation**
- Check return values; `_exit(1)` on failure. Consider also adding a `getuid() != 0 || getgid() != 0` sanity check before `execvp`.

### I-01 — OCI capability set is materially wider than documented (Informational)

**Files**
- `cli/src/safeyolo/platform/linux.py:1006-1015`:
  ```
  CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FOWNER, CAP_FSETID,
  CAP_KILL, CAP_SETGID, CAP_SETUID, CAP_SETPCAP,
  CAP_NET_BIND_SERVICE, CAP_SYS_CHROOT,
  CAP_NET_ADMIN,
  CAP_MKNOD, CAP_AUDIT_WRITE, CAP_SETFCAP
  ```
- `docs/linux-port-design.md:§OCI Config`: "only what init needs (CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_NET_ADMIN to configure loopback, CAP_SETUID, CAP_SETGID) — no CAP_NET_RAW, no CAP_SYS_ADMIN"
- `docs/security-verification.md:§Sandbox Hardening`: "CAP_CHOWN / CAP_DAC_OVERRIDE / CAP_NET_ADMIN for init only"

**Effect**
- The *real* set includes CAP_MKNOD, CAP_SETFCAP, CAP_FSETID, CAP_SETPCAP, CAP_SYS_CHROOT, CAP_AUDIT_WRITE, CAP_FOWNER, CAP_KILL, CAP_NET_BIND_SERVICE — none of which are mentioned in the design docs.
- All fourteen caps are placed in *every* capability bucket including `ambient` (`process.capabilities.ambient`, lines 1076-1081), meaning child processes of init inherit them across `execve` unless explicitly dropped.
- The agent itself enters via a separate `runsc exec --user 1000:1000` (linux.py:758-790) and a non-root `runsc exec` does not inherit the init ambient set, so the agent should not hold these caps in practice.
- `process.noNewPrivileges: False` is set at linux.py:1085 — intentional to allow `su agent -l` to re-elevate, but it means setuid-root binaries within the overlay could gain capabilities. Since the agent isn't root-in-sandbox, it cannot create setuid-root files directly; but if any escalation path back to init exists, this becomes load-bearing.

Inside gVisor's sentry, most of these caps are interpreted by the user-space kernel, and gVisor itself does not let a sandbox escape the sentry via CAP_SETFCAP/CAP_MKNOD — so the practical blast radius is limited. Still, the docs should match the code. At minimum: dropping CAP_SETFCAP and CAP_MKNOD after init's bootstrap phase would match the claim "no dangerous caps at runtime" — init could use `capsh --drop=...` before invoking `sleep infinity`.

**Recommendation**
- Either prune the set in the OCI spec to what the doc claims, or update the doc and add a rationale for each cap that's actually kept.

### I-02 — OCI seccomp default is `SCMP_ACT_ALLOW`; only `unshare` is blocked (Informational)

**Files**
- `cli/src/safeyolo/platform/linux.py:1090-1100`

```json
"seccomp": {
    "defaultAction": "SCMP_ACT_ALLOW",
    "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
    "syscalls": [{"names": ["unshare"], "action": "SCMP_ACT_ERRNO", "errnoRet": 1}],
}
```

gVisor's sentry intercepts syscalls before the host kernel, so a permissive outer-layer seccomp does not directly translate to host syscalls. This is primarily a filter applied to sandboxed processes inside the sentry, and most dangerous syscalls are either not implemented by the sentry or hardened independently.

Still — an allow-by-default seccomp profile is the permissive end of the design spectrum. For a pre-v1 hardened sandbox, flip to `SCMP_ACT_ERRNO` default with an explicit allow-list (modelled on Docker's default profile, minus userns-creation) would be consistent with the stated "minimize trust" principle. Worth a design-time conversation rather than a hard finding.

### I-03 — `setup.py` sudoers docstring describes rules the template does NOT install (Informational)

**Files**
- `cli/src/safeyolo/commands/setup.py:391-412` — docstring claims the Linux sudoers template installs rules for `ip netns/link/addr`, `iptables`, `mount/umount`, `runsc`, `sysctl`, `mkdir`, `cp`.
- `cli/src/safeyolo/templates/safeyolo-linux.sudoers` — actual template only contains `mount -o loop,ro`, `umount`, `cp -a`, `chown -R` for the one-time rootfs extraction fallback when `fuse2fs` is unavailable.

Net security impact is *favourable* (the narrower actual template is the right surface), but the divergent docstring is misleading and could make a future contributor paste the docstring's (broader) claim back into the template, re-introducing the wider sudo surface. Update the docstring to match reality.

### I-04 — Path substitutions in sudoers template are not path-validated (Informational)

**Files**
- `cli/src/safeyolo/commands/setup.py:366-385` — `%SAFEYOLO_BASE_ROOTFS_DEST%` / `%SAFEYOLO_BASE_EXT4%` substituted from `get_share_dir()`, which respects `$SAFEYOLO_CONFIG_DIR` env var.
- Username is regex-validated (`^[a-z_][a-z0-9_-]*$`) — correct.
- Chown target is escape-treated for `:` — correct.
- Path components are not validated. A path containing a comma, newline, or sudoers-significant character is copied verbatim into the sudoers rule, then checked by `visudo -c`.

Under the stated threat model (honest operator), this isn't live — env vars are operator-controlled. But it's the kind of dual-use path that surfaces once someone composes this with a future template flow that substitutes attacker-controlled input (e.g. an agent name). Add a whitelist regex on substituted paths (`^[A-Za-z0-9/._-]+$`) before writing — `visudo -c` catches syntax errors but not semantic injection.

### I-05 — AppArmor profile is path-pinned to `/usr/local/bin/runsc` (Informational)

**Files**
- `cli/src/safeyolo/templates/apparmor-safeyolo-runsc:19` — `profile safeyolo-runsc /usr/local/bin/runsc flags=(unconfined) { userns, }`
- `cli/src/safeyolo/platform/linux.py:147-155` — `find_runsc()` returns the first of `$PATH`, `/usr/local/bin/runsc`, `/usr/bin/runsc` that exists.

If runsc is installed to `/usr/bin/runsc` (the Debian package path), the AppArmor profile does not match — on Ubuntu 24.04+ the userns creation then fails. The failure mode is closed ("sandbox doesn't start"), not open, so this is a usability/reliability issue rather than a security issue. Calling it out because it's the kind of thing that breaks in a hardening regression (e.g. a pkg upgrade that moves runsc).

**Recommendation**
- Let the profile match both paths (either two profiles, or a glob). Alternatively, verify at `setup` time that the installed runsc is at the profile's pinned path and refuse to proceed otherwise.

### M-02 — Kernel source tarball downloaded without signature/digest verification (Medium)

**Files**
- `guest/build-kernel.sh:65-70`

```bash
curl -fsSL \
    "https://cdn.kernel.org/pub/linux/kernel/v${KERNEL_MAJOR}.x/linux-${KERNEL_VERSION}.tar.xz" \
    -o "$KERNEL_TARBALL.tmp"
```

No SHA256 check, no GPG verification against Linus's signing key, no accompanying `.sign` download. The kernel binary is baked into `~/.safeyolo/share/Image` and executes as the guest kernel on every macOS microVM boot.

Compared to sibling scripts in the same directory:
- `build-rootfs.sh` pins mise + gh tarballs by SHA256 (lines 66-71, `fetch_pinned`).
- `rootfs-customize-hook.sh` verifies mise + gh after install (lines 65-69, 118-122).

Kernel is the one download in the build pipeline that skips this. Under threat model (operator-run build, TLS transport), it requires a cdn.kernel.org compromise, a CA compromise, or build-host DNS interception — low likelihood but existentially bad if it happens (arbitrary kernel code in the VM guest).

**Recommendation**
- Fetch `linux-${KERNEL_VERSION}.tar.sign` alongside the tarball; verify with `gpg --verify` against Linus's pubkey (79BE3E4300411886). Alternatively pin the tarball by SHA256 in the same style as mise/gh.

### I-06 — Debian base image pulled via floating tag (Informational)

**Files**
- `guest/build-rootfs.sh:74-78` — `DEBIAN_IMAGE="${DEBIAN_IMAGE:-docker://debian:trixie}"`; explicit TODO to replace with digest-pinned reference.

Acknowledged in-source. Note that mmdebstrap would have had the same floating-snapshot issue, so this is not a regression — just a known gap. Worth lifting the TODO into an issue + assigning a digest pin before v1.

### I-07 — `pip3 install` in rootfs-customize-hook has no pinning (Informational)

**Files**
- `guest/rootfs-customize-hook.sh:133-135`

```bash
chroot "$ROOTFS" pip3 install --break-system-packages --quiet \
    pytest httpx pytest-timeout
```

Installs the latest `pytest`, `httpx`, `pytest-timeout` from pypi, no version constraint, no `--require-hashes`. These land in the shared rootfs tree on every rebuild. A typosquat or compromised pypi release would be picked up by the next clean build.

These three packages are baked into the default base so the blackbox test suite inside the sandbox can run. Their blast radius: test code runs as agent uid 1000 inside the sandbox. Not host-escape; sandbox-internal integrity.

**Recommendation**
- Generate a hash-pinned `requirements-testdeps.txt` (e.g. via `uv pip compile --generate-hashes`), invoke `pip install --require-hashes -r requirements-testdeps.txt` from the hook.

### I-08 — Fallback mitmproxy installer has no version pinning; silently defeats `uv.lock` (Informational)

**Files**
- `scripts/install-mitmproxy-pipx.sh:18-28`

```bash
pipx install mitmproxy || true
pipx inject mitmproxy pyyaml yarl confusable-homoglyphs pydantic \
    cryptography tomlkit httpx tenacity
```

The primary path (`uv tool install --editable ./cli`) consumes `uv.lock` with hashes, and `pyproject.toml`'s `[tool.uv].override-dependencies` explicitly bumps flask, pygments, cryptography, pyopenssl, tornado to CVE-patched versions. This fallback path installs the latest of every package with no constraint file, pypi-default index, no hash check.

README steers users here if uv's Python-3.12 resolution drops mitmproxy from the workspace venv, which makes this path reachable on first install (not a niche case). The fallback silently disables the uv.lock hardening.

**Recommendation**
- Ship a `scripts/install-mitmproxy-pipx.txt` with pinned versions + hashes matching `uv.lock`'s mitmproxy + transitive set. Use `pipx install --pip-args "--require-hashes -r scripts/install-mitmproxy-pipx.txt"`.

### I-09 — Comment in `rootfs-customize-hook.sh` overstates rootless setuid blocking (Informational)

**Files**
- `guest/rootfs-customize-hook.sh:223-230`

> "Why: rootless user namespaces ignore the setuid bit, so `sudo` running as the agent user (uid 1000) can't escalate to root."

Inaccurate as a blanket statement. In an unprivileged userns the kernel honours the setuid bit when the resulting uid is in the userns's uid map, *and* when `no_new_privs` is not set. SafeYolo's OCI spec has `process.noNewPrivileges: False` (`cli/src/safeyolo/platform/linux.py:1085`) and container uid 0 IS in the uid map (mapped to host uid 100000). So setuid-root binaries do work inside the sandbox.

What actually prevents an agent from escalating via sudo on the default Debian base is different: the default base's `/etc/sudoers` has no entry for `agent`, so `sudo` prompts for a password and fails. That's policy, not kernel-structural.

Kali and Alpine rootfs scripts (`contrib/kali-pentest/build-kali-rootfs.sh:186-199`, `contrib/alpine-minimal/build-alpine-rootfs.sh:85-105`) explicitly install NOPASSWD sudo for agent, so agent → sandbox-root IS reachable in those rootfses by design. The Sentry remains the outer boundary (agent + sandbox-root both see the same emulated kernel), so this is an intentional pre-v1 choice, not a vuln. But the comment should reflect reality so a future maintainer doesn't add "rely on this" logic atop a wrong premise.

**Recommendation**
- Reword the comment: "On the default base, agent has no sudoers entry, so `sudo` is gated by password and agent can't escalate. On custom rootfs (Kali, Alpine contrib scripts) that install NOPASSWD sudo, agent → sandbox-root is intentional; the Sentry is the boundary either way."

### I-10 — Regression origin: `--listen-host 0.0.0.0` predates UDS-only architecture by 30+ commits (Informational)

**Files**
- `cli/src/safeyolo/proxy.py:354` — introduced by PR #132 ("perf: cut ~750ms-1.5s off agent boot")
- UDS-only networking: PR #167
- PROXY protocol v2 identity: PR #175 (`addons/proxy_protocol.py`)

When the proxy bind was set to `0.0.0.0`, agents reached mitmproxy over a bridge network — the bind was load-bearing. That model is long gone: PR #167 moved Linux to structural UDS-only isolation, PR #175 replaced per-agent source-IP binding with a PROXY-v2 header stamped by `proxy_bridge`. Neither PR reverted the bind-address widening. The commit context for PR #175 (adding an addon that unconditionally trusts PROXY-v2 from any inbound TCP source) *assumed* loopback-only — the addon and the bind diverged across the two PRs.

This is exactly the regression shape the audit was called for: the threat model tightened but a legacy knob didn't follow. Root of H-01.

**Recommendation**
- See H-01. Also: add a startup assertion that logs + aborts if `--listen-host` resolves to anything non-loopback without an explicit opt-in flag.

## Summary of findings

| ID | Severity | Title | File(s) |
|----|----------|-------|---------|
| H-01 | High | mitmproxy listens on `0.0.0.0`; PROXY-v2 agent identity auto-trusted from any TCP source | `cli/src/safeyolo/proxy.py:354`, `addons/proxy_protocol.py:105-151` |
| M-01 | Medium | `admin_api` binds `0.0.0.0:9090`; SECURITY.md claims loopback-only | `addons/admin_api.py:1354, 1377` |
| M-02 | Medium | Kernel source downloaded without signature/digest verification | `guest/build-kernel.sh:65-70` |
| L-01 | Low | `vsock-term.c`: unchecked `setgid`/`setuid` return values (CWE-252) | `guest/vsock-term.c:211-216` |
| I-01 | Info | OCI capability set materially wider than documented (14 caps vs ~4, all in `ambient`) | `cli/src/safeyolo/platform/linux.py:1006-1015` |
| I-02 | Info | OCI seccomp `defaultAction: SCMP_ACT_ALLOW` (only `unshare` blocked) | `cli/src/safeyolo/platform/linux.py:1090-1100` |
| I-03 | Info | `setup.py sudoers` docstring describes rules the template doesn't install | `cli/src/safeyolo/commands/setup.py:391-412` |
| I-04 | Info | Path substitutions in sudoers template not path-validated | `cli/src/safeyolo/commands/setup.py:366-385` |
| I-05 | Info | AppArmor profile path-pinned to `/usr/local/bin/runsc` only | `cli/src/safeyolo/templates/apparmor-safeyolo-runsc:19` |
| I-06 | Info | Debian base pulled via floating `docker://debian:trixie` tag (explicit TODO) | `guest/build-rootfs.sh:74-78` |
| I-07 | Info | `pip3 install` in rootfs-customize-hook has no version/hash pinning | `guest/rootfs-customize-hook.sh:133-135` |
| I-08 | Info | `install-mitmproxy-pipx.sh` fallback has no pinning, silently defeats `uv.lock` | `scripts/install-mitmproxy-pipx.sh:18-28` |
| I-09 | Info | Comment in `rootfs-customize-hook.sh` overstates rootless-userns setuid blocking | `guest/rootfs-customize-hook.sh:223-230` |
| I-10 | Info | Regression origin: `--listen-host 0.0.0.0` predates UDS-only architecture | `cli/src/safeyolo/proxy.py:354` + PRs #132/#167/#175 |

## Final assessment

- **No concrete sandbox-escape finding** under the honest-operator + malicious-agent-in-sandbox threat model. The rootless userns + gVisor Sentry + UDS egress + PROXY-v2 attribution design is coherent and self-consistent once you accept the Sentry as the outer boundary.
- **The two network-exposure findings (H-01, M-01)** are the material ones. They don't break the sandbox-isolation contract, but they break the stated "binds to localhost only" / "agent cannot forge another agent's identity" claims as soon as the host is on any untrusted network. Both trace back to a single legacy bind-address choice (introduced in PR #132) that survived the switch to UDS-only isolation + PROXY-v2 identity. A ten-line fix in `proxy.py` + a source-IP check in `proxy_protocol.py` retires H-01; `("127.0.0.1", port)` in `admin_api.py` retires M-01.
- **M-02 (unverified kernel source)** is a supply-chain gap that's out-of-pattern with the rest of the build pipeline (mise, gh are pinned; the kernel isn't). Cheap to fix with the kernel.org `.sign` file.
- **Capability / seccomp informationals (I-01, I-02)** are doc-vs-code divergences. The caps are contained by gVisor's Sentry in practice, but the docs should match the code. Auditing the list and either pruning or documenting each cap is low-risk cleanup.
- **Supply-chain informationals (I-06, I-07, I-08)** each quietly erode the reproducibility + hash-pinning story. Independently modest risk; collectively they mean "what actually got installed" can drift between two clean builds even with identical source.
- **I-10** is the "why did this happen" story behind H-01 — useful context when proposing the fix.

### What I'd do next (not in scope, but flagged)

- **Ask the maintainer** about the Dependabot #35 "1 high" alert surfaced at push time on master. I can't hit the GH API from this container; the alert ID should be checked directly.
- **Extend audit to scope C** (proxy/PDP logic) after the network-exposure findings are addressed — the PROXY-v2 auto-trust interaction with `network_guard`, `credential_guard`, `service_gateway` is worth a fuller review once the identity path is authenticated, because several downstream addons build trust on top of the spoofable IP.
- **Blackbox test** covering `--listen-host` defaulting to loopback (fails the start if `0.0.0.0`) + a PROXY-v2 spoofing attempt from an off-loopback source. Both catch regressions of the shape that caused H-01/I-10.
