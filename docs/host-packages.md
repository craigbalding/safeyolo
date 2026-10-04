# Host package downloads

For production installation, follow the [main quickstart](../README.md#1-install-on-your-host).
It links directly to the [latest successful release](https://github.com/craigbalding/safeyolo/releases/latest)
and gives prerequisites, checksum commands and installation steps for each
supported host. Complete the separate
[guest and host runtime setup](../cli/README.md#bootstrap-and-individual-phases)
before launching an agent.

## Choose a profile and install

Choose `production` for normal operation. Production contains Cargo's release
proxy and the production macOS helper. Choose `debug` for native debugging;
it contains Cargo's dev proxy and the development macOS helper. Both macOS
helpers are optimized Swift builds with debug symbols, hardened runtime and
the virtualization entitlement. The development helper also has
`com.apple.security.get-task-allow`; authorized local debuggers can inspect or
modify its memory and execution.

To install a debug package, download the matching `debug` archive and
`SHA256SUMS` from the same release. In the quickstart's checksum, extraction
and installation commands, replace `production` with `debug`.

The installer verifies internal checksums and wheel build identity before
replacing uv's `safeyolo` tool environment. On macOS, it also verifies the
helper's signature, entitlements and source/profile identity. It installs the
helper, debug symbols and guest terminal utility in `~/.safeyolo/bin/`, then
verifies the installed helper again.

Installing another archive replaces the command-line interface (CLI) and, on
macOS, the helper profile.
Restart affected SafeYolo processes to use the newly installed version.
Existing instance state and guest images are retained.

## Build identity and publication

The release tag is `host-` followed by the full source commit. Each archive's
`manifest.json` records source, platform, profile, compiler settings, runtime
compatibility and SHA-256 file checksums. The wheel contains the same native
build record. CLI and proxy version output includes
the full commit and production/debug profile; macOS helper identity is also
read from the signed executable. Numeric wheel versions are derived
automatically as `0.1.0.dev0+g<FULL-SHA>.<PROFILE>`; the commit release tag
identifies the download.

Latest selects a release only after its platform/profile download checks pass.
A failed publication leaves the previous latest selection intact, and an older
build cannot replace a newer latest release.
