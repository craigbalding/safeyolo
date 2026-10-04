# Host package downloads

SafeYolo's postmerge workflow publishes host packages to this repository's
[GitHub Releases](https://github.com/craigbalding/safeyolo/releases).
The [latest successful release](https://github.com/craigbalding/safeyolo/releases/latest)
selects the newest source commit whose packages passed the download consumers.
The first real publication and its platform results are tracked in
[#915](https://github.com/craigbalding/safeyolo/issues/915).

Downloads contain the Python command-line interface (CLI) and the native Rust
proxy. macOS downloads also contain the signed VM helper, its debug symbols,
and the existing guest terminal utility. Install on the host with
[uv](https://docs.astral.sh/uv/) as your usual user. uv selects or downloads a
supported Python interpreter. Installation uses the included dependency
versions and prebuilt wheels; Cargo, Swift and a local C compiler are not needed.

| Platform | Archive prefix | Runtime compatibility |
| --- | --- | --- |
| Apple Silicon macOS | `safeyolo-darwin-arm64` | macOS minimum recorded from the proxy and helper load commands |
| x86_64 Linux | `safeyolo-linux-amd64` | GNU libc (glibc) minimum recorded from the proxy's ELF version requirements |
| arm64 Linux | `safeyolo-linux-arm64` | glibc minimum recorded from the proxy's ELF version requirements |

The installer checks the actual host against the archive's `manifest.json`.
Guest images and host runtime setup remain separate. Use the existing
[bootstrap and individual phases](../cli/README.md#bootstrap-and-individual-phases)
with the source checkout for guest builds. The host package alone does not
establish a working sandbox or hardware acceptance.

## Choose a profile and install

Choose `production` for normal operation. Production contains Cargo's release
proxy and the production macOS helper. Choose `debug` for native debugging.
Debug contains Cargo's dev proxy and the development macOS helper. Both macOS
helpers use the established optimized Swift build with DWARF and dSYM symbols.
Both retain hardened runtime and the virtualization entitlement. The
development helper also has `com.apple.security.get-task-allow`; authorized
local debuggers can inspect or modify its memory and execution.

From one commit's release page, download your platform/profile archive and
`SHA256SUMS` into a new directory. Use the same release for both files.
The release tag is `host-` followed by the full source commit. The following
example runs in that download directory on an arm64 Linux host and installs
the production profile:

```sh
grep ' safeyolo-linux-arm64-production.tar.gz$' SHA256SUMS | sha256sum --check -
```

Continue only when the checksum command prints
`safeyolo-linux-arm64-production.tar.gz: OK`. Then extract and install:

```sh
tar -xzf safeyolo-linux-arm64-production.tar.gz
./safeyolo-linux-arm64-production/install.sh
safeyolo --help
```

The installer verifies internal checksums and wheel build identity before
replacing uv's `safeyolo` tool environment. On macOS it also verifies the
helper's signature, entitlements and source/profile identity, installs the
helper and terminal utility in `~/.safeyolo/bin/`, and verifies the installed
helper again. Put uv's tool directory, normally `~/.local/bin`, on `PATH`.
Successful `safeyolo --help` confirms that the installed CLI loads. The workflow
also executes the installed proxy's version command.

For x86_64 Linux, replace `linux-arm64` with `linux-amd64` in the example.
For macOS, use `darwin-arm64` and `shasum -a 256 --check -` for the checksum
command. To install a debug package, replace `production` with `debug`.
Reinstalling another archive replaces the CLI and, on macOS, the installed
helper profile. Restart the affected SafeYolo processes to use the newly
installed version. Existing instance state and guest images are retained.

## Build identity and publication

Each archive records its source commit, platform, profile, compiler and build
settings, runtime compatibility and SHA-256 file checksums. The wheel contains
the same native build record. The CLI and proxy version commands report the
full commit and production/debug profile. Numeric wheel versions are derived
automatically as `0.1.0.dev0+g<FULL-SHA>.<PROFILE>` from the milestone
base, commit and profile. The commit release tag remains the download identity;
no manual version bump or numbered milestone release occurs per merge.
macOS helper identity is also read from the signed executable. Existing
blackbox reports retain their selected source commit.

Publication waits for the current master push's successful latest `Test CLI`,
`Lint`, `Test Addons (Python 3.12)`, CodeQL `Analyze`, and `Quick native checks
(Ubuntu)` jobs for the same source commit. An unrelated optional job failure
does not block publication. Release notes retain the actual workflow conclusions
and link the successful jobs. Existing conditional premerge compilation and
required merge checks continue independently.
Source is available through `git pull` as soon as the commit reaches master.

Master CI saves runtime binaries from its maintained output paths when its
existing conditional checks produced them. Postmerge builders reuse a debug
component only when its source, platform, compiler/settings and saved checksums
match. The selected attempt's platform producer must succeed, including its
runtime save and upload steps. A rerun of an optional failed job can retain a
successful producer from an earlier attempt. Builders download the immutable
artifact ID and verify GitHub's ZIP checksum. An artifact from a different
producer attempt cannot stand in for that producer's output. Missing or
incompatible components receive one fallback build.
Production components build once. The guest terminal utility builds once for
the two macOS profiles. Wheel/archive creation copies those bytes and does not
compile again.

The workflow uploads all six archives and their checksums to a draft commit
release before making the complete set downloadable as a prerelease.
Prereleases cannot become GitHub's implicit latest selection. Consumers on the three
GitHub-hosted platforms download both profiles, verify checksums, install with
compiler commands absent from `PATH`, and execute the CLI and proxy. macOS
consumers also check the signed helper. Only a successful consumer set can
make that release eligible for latest and promote it. Latest promotion is serialized and compares
commit ancestry; an older finishing build cannot replace a newer latest
release. A failed consumer leaves the previous latest selection intact.

If publication fails, inspect the named failed job in `Postmerge host packages`.
Use GitHub Actions' **Re-run failed jobs** after correcting a transient resource
or download failure. An already published commit release is not overwritten or
recompiled by another source-check completion. A source correction needs a new
merged commit. An incomplete upload remains a draft and is not selected as latest.
