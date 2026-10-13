# Native host packages

Use [native installation](native-policy.md#install-and-start) for the current
fresh-state product. The published
[native host release](https://github.com/craigbalding/safeyolo/releases/tag/host-7a38dff14e7e4eacb4095da732ffe06d7c7c5796)
supplies production downloads for all three host platforms. Existing wheel
archives belong to the earlier Python CLI and are not inputs to native installation.

Choose the published bundle for your host (linux-amd64, linux-arm64 or darwin-arm64).
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
