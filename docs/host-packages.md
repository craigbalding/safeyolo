# Native host packages

Use [native installation](native-policy.md#install-and-start) for the current
fresh-state product. The published
[native host release](https://github.com/craigbalding/safeyolo/releases/tag/host-7a38dff14e7e4eacb4095da732ffe06d7c7c5796)
supplies production downloads for all three host platforms. Existing wheel
archives belong to the earlier Python CLI and are not inputs to native installation.

The source producer also writes `install-safeyolo.sh` beside the host archive.
An authorized host publication must include that file and the release's
`SHA256SUMS`. The bootstrap is bound to that host release. The currently
published host release does not include this bootstrap asset.

For Ubuntu AMD64, Ubuntu ARM64 and Apple Silicon macOS, the bootstrap route
uses the same two commands below. Run them in your ordinary host terminal,
in a writable directory, only when the selected public release includes
`install-safeyolo.sh`. Bash, curl, tar and the host's SHA-256 tool must be
available. Stop if the download fails. Do not run a previous file left at that
name. The installer downloads the production host package and compatible
guest, then creates the default instance at `$HOME/.safeyolo`, unless
`SAFEYOLO_CONFIG_DIR` or `SAFEYOLO_HOME` selects another root. It exposes
`safeyolo` in `$HOME/.local/bin` or `/usr/local/bin` when that directory is
already on PATH. It can request sudo for the command entry and Linux guest
ownership. Existing unrelated commands are preserved.

Host preparation, runtime selection and first-agent launch remain required
for the complete onboarding path. This acquisition sequence alone does not
meet the total two-command install-to-first-agent budget. Bootstrap publication
and that composition are still pending; the existing explicit bundle path below
remains available.

Trust comes from HTTPS delivery by the official
`github.com/craigbalding/safeyolo` publisher. A checksum from the same release
checks integrity; it does not independently authenticate that publisher.
The bootstrap does not use a remote shell pipe or a package-manager install.

```sh
curl --fail --location --proto '=https' --proto-redir '=https' --output install-safeyolo.sh https://github.com/craigbalding/safeyolo/releases/latest/download/install-safeyolo.sh
bash install-safeyolo.sh
```

Choose the published bundle for your host (linux-amd64, linux-arm64 or darwin-arm64)
when using the explicit bundle path.
For source builds, use a prepared bundle from your selected source.
A production bundle contains release Rust executables;
a debug bundle contains dev executables. The macOS helper is signed and retains
its matching profile: the development helper additionally has the
get-task-allow entitlement for authorized debugging.

An optional integrity check compares a transferred archive with its supplied
SHA-256 before extraction; it does not independently authenticate its publisher.
The unpacked install.sh invokes the same native installer used by source
install.sh. It verifies package-info, internal SHA256SUMS, native executable
identity, matching host/guest source and profile, runtime compatibility and
macOS helper signature/identity. It installs into a root with no existing
instance configuration, then initializes trust, tokens and state internally.
A matching installation made with the current installer can be repeated.
Repeat retains its host, policy, credentials, identity, agent state and selected
guest without checking Latest or upgrading. An older or conflicting installation
is preserved; use its installed command or choose a separate `--root` and
`--command-dir`. A download failure leaves verified cache inputs available for
retry. Partial downloads are not activated. An interrupted final file move can
leave incomplete files; the next invocation reports them and preserves them.
There is no wheel, venv, uv-tool replacement or old-state conversion.

[Build inputs and layout](native-policy.md#build-a-native-bundle) describe the
three host executables, Linux guest helpers/receipts, private tmux and libraries,
boot/host scripts, skills, launchers and services. The default guest is downloaded
separately during installation. Explicit prepared rootfs/images remain supported.
package-info records full source, profile, platform
and the actual minimum glibc or macOS version; it is the runtime requirement,
not an inferred wheel tag. Read installed --version and native status to
attribute a run, and retain separate guest/platform observations.

The [OCI guest source contract](guest-oci.md) defines independent default-guest
release discovery and compatibility. The published host's native installer
acquires the compatible public guest anonymously and records its selection.
Guest identity is independent of host identity.

The one-time host and initial guest publications are complete. Automatic and later
publication and promotion remain stopped. Source integration and focused
installer results do not accept the final installed platform suites.
