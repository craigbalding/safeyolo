# OCI guest source contract

The default guest filesystem has an independent release identity from the
SafeYolo host package. The Open Container Initiative (OCI) index, manifests,
descriptors and annotations are the sole guest release catalogue. Public guest
artifacts use `ghcr.io/craigbalding/safeyolo-guest` in GitHub Container Registry
(GHCR).

This document defines the source contract for publication, guest acquisition
and explicit guest upgrades. The [Rust validator](../proxy/src/guest_oci.rs)
and its [focused tests](../proxy/src/guest_oci/tests.rs) implement the shared
rules. The default-guest archive producer and ORAS publisher are described
below. [Guest acquisition](../proxy/src/guest_acquisition.rs) and the
[existing installer](../scripts/install_native.sh) obtain and install the
selected guest. The `guest upgrade` and `guest rollback` commands change
the default guest selection for existing instances under issue #238.
Issue #239 owns installed-platform and independent-update proof. The source
contract does not establish those outcomes or authorize public publication.

## Discovery and release identity

Each release has an immutable version tag `guest-YYYY-MM-DD.N`. The date is a
valid calendar date; `N` contains decimal digits. The complete tag is at most
128 ASCII characters. A compatibility identifier `C` is a nonempty suffix of
at most 121 ASCII letters, digits, underscores, dots or hyphens. Its discovery
tag is `compat-<C>`, for example `compat-v1` for identifier `v1`.

The host package must carry `guest_compatibility`, `guest_repository` and
`guest_discovery_tag`. Those three fields are emitted and checked by the existing
strict package metadata writer/reader. They must not
include a fixed guest index or archive digest. Host version, source, profile,
platform and runtime requirements remain separate.

The publisher must verify the complete release before moving its compatibility
tag. Guest version tags must not be retargeted. An incompatible generation
uses another channel and preserves discovery for supported older hosts.
The publisher owns serialization of promotion, conflicting-version refusal
and retention of supported releases and rollback content. OCI tagging alone
does not enforce immutability or compare-and-swap promotion. These publication
controls are implemented by the #211 publisher. The initial guest release,
`guest-2026-10-12.1`, is public. Anonymous guest acquisition and installation
have been independently assessed for all three consumer platforms under
[#239](https://github.com/craigbalding/safeyolo/issues/239).
These results do not complete that issue's installed and independent-update
proof or the publisher's ongoing retention obligations. Automatic and later
publication remain held.

## OCI objects

Use OCI Image Specification 1.1.1 objects with `schemaVersion: 2`.

| Object | Required media type or content |
| --- | --- |
| Release index | `application/vnd.oci.image.index.v1+json` |
| Each child manifest | `application/vnd.oci.image.manifest.v1+json` |
| Index and child `artifactType` | `application/vnd.safeyolo.guest.v1` |
| Child config descriptor | `application/vnd.safeyolo.guest.platform.v1+json` |
| Child config bytes | JSON containing only string `os` and `architecture` |
| Exactly one child archive layer | `application/vnd.safeyolo.guest.v1.tar+zstd` |

The config records the **consumer host**, so ORAS can infer the platform for
the index descriptor. The release index must have exactly one child descriptor
per supported consumer platform. Never select by the registry client's default
platform, by guest operating system, or by architecture alone.

| Consumer platform | Finished archive layout |
| --- | --- |
| `darwin/arm64` | `Image`, `initramfs.cpio.gz`, `rootfs-base.ext4` |
| `linux/amd64` | `rootfs-tree/`, `cache-paths.txt` for amd64 |
| `linux/arm64` | `rootfs-tree/`, `cache-paths.txt` for arm64 |

Mac and Linux arm64 archive digests must differ. The publisher's complete-child
validation checks that distinction. A consumer validates its selected chain;
that check alone does not prove the other payloads. Archives are opaque during
transport. The contract validator does not inspect archive contents or apply
OCI filesystem layers.

## Annotations and compatibility

Index, child and optional descriptor annotations are string-to-string maps.
Keys must be unique within each map. Unknown string annotations are allowed.
The validator checks annotation entries before insertion and decodes required
scalar fields from their actual JSON types. Object wrappers cannot stand in
for strings or integers. Required values must satisfy these rules:

| Annotation | Location and rule |
| --- | --- |
| `org.opencontainers.image.version` | Index and every child: guest version tag |
| `org.opencontainers.image.source` | Index and every child: `https://github.com/craigbalding/safeyolo` |
| `org.opencontainers.image.revision` | Index and every child: full lowercase Git object ID, 40 or 64 hexadecimal characters |
| `dev.safeyolo.guest.compatibility` | Index and every child: compatibility identifier `C` |
| `dev.safeyolo.guest.build-base` | Each child: fully qualified build input pinned by `@sha256:<64 lowercase hex>` |

The four shared annotation values must agree between the index and every
child. The index compatibility must equal the host's required identifier;
the tag name is insufficient. Compatibility uses exact identifier matching,
without version ranges or a dependency solver. Guest revision need not equal
host revision.

The build-base annotation records the actual architecture-specific Debian
manifest used by the producer. For example, its shape can be
`docker.io/library/debian@sha256:<selected-architecture-digest>`.
The validator checks qualification and the digest; #211 must demonstrate that
the producer actually used that pinned input. Do not use OCI's standard
`image.base.*` annotations for this opaque archive: those describe an immediate
layered base. Build provenance and base compatibility do not relax the existing
exact source/profile checks for host-shipped `safeyolo-guest`, `safeyolo-coord`
or Mac helpers.

## Descriptor verification and selection

Each index child, config and archive descriptor must carry the required media
type, a standard lowercase `sha256:<64 hex>` digest and a nonnegative `int64`
raw byte size. Verify referenced raw bytes against both digest and size before
using them. Optional descriptor annotations must also contain string values.
Do not hash parsed and reserialized JSON in place of the referenced raw bytes.
Hashes identify content; they do not authenticate the publisher independently
of the trusted repository or prevent deletion. Retention remains a publisher
responsibility. Signing or additional provenance is not a prerequisite here.

Resolve discovery once for an acquisition or upgrade operation. Validate the
resolved index's raw SHA-256 identity, media type, schema, artifact type,
annotations, completeness and compatibility. The root index has no parent
descriptor giving an expected size; record the observed raw length. Explicitly
select one consumer platform, then pin the child and archive references by
their descriptor digests. A concurrent compatibility-tag update must not mix
content from another release into that operation.

`GuestIndex::parse` validates the resolved index. `manifest(platform)` returns
its pinned child descriptor. `validate_child` checks raw child hash/size,
shared annotations, build-base, config descriptor and single archive descriptor.
`GuestChild::validate_config` checks the config's raw identity/size and exact
consumer platform. `validate_children` checks all children in
`ConsumerPlatform::ALL` order, including distinct Mac/Linux arm64 archive
identities. `Descriptor::verify` checks a reader incrementally through EOF;
`check_size` supports callers whose OCI client already verifies the hash.

Pin publisher tooling to ORAS 1.3.4. Use `push --image-spec v1.1` with the custom
platform config and typed archive, then `manifest index create` from exact
child digests. Set the required index annotations and artifact type explicitly.
Do not combine `--config` with the mutually exclusive `--artifact-platform`.

Guest acquisition uses pinned `oci-client` 0.18.0 with the existing ring TLS
provider, system/configured certificate authority (CA) roots and proxy route.
Client construction uses fallible `Client::try_from(ClientConfig)`.
`pull_manifest_raw` resolves discovery once; subsequent references pin the
child digest. `platform_resolver: None` prevents implicit client selection.
`pull_blob_stream` verifies the archive incrementally while it is written to a
temporary file. The consumer checks descriptor size before retaining that file.
The raw index, child and config are checked by the shared contract validator.
Acquisition adds no alternate catalogue or user-installed registry tooling.

## Installed selection and backend preservation

Installed state must record the guest version, repository, index digest,
selected child-manifest digest and archive-blob digest. Retain those identities
through normal start and restart. A compatibility-tag change affects new
selection operations only. Explicit guest upgrade resolves discovery again,
or selects a concrete immutable version/index digest for testing or rollback.
A compatible host-only upgrade retains the installed guest unless a guest
change is explicitly selected. Reuse unchanged verified bytes without another
download or extraction.

Stage a verified archive in persistent storage identified by its blob digest.
On Linux, preserve numeric UID/GID `100000`, modes, symlinks and
`cache-paths.txt`; the installer links to the prepared `rootfs-tree/`.
Keep referenced trees available for installed and rollback selections.
On Darwin, preserve the finished kernel/initramfs/ext4 files and sparse-image
handling, including the existing clone/copy behavior. Retain explicit offline
platform assets. A failed pull, compatibility check, verification or extraction
must leave the prior selection active, without an implicit local build.
Atomic activation and rollback must preserve policy, credentials and agent state.
Initial installed inputs remain under `share/`. An upgraded selection's
`installed_assets` points to its separate backend files under
`share/guest-versions/sha256/<archive-digest>/`. `previous` retains the prior
selection in the same JSON file. Each guest boot reads one complete selection
and stages that selection's backend inputs. Existing per-agent rootfs and cache
overrides keep their precedence. Activation does not replace the initial files
or inputs used by an earlier sandbox incarnation.
The installer feeds the verified prepared directory into its existing
`platform_assets` path. It stages backend files and `guest-selection.json`
together before initializing the fresh instance. The default persistent store
is `HOME/.local/share/safeyolo/guests`, with `blobs/sha256` and `trees/sha256`
directories. Completed trees are renamed into their digest-addressed location;
failed extraction removes its owned staging directory. The host's maintained
tar extracts the selected backend members, preserving its path/link safeguards;
Linux extraction uses sudo for numeric ownership and the host find command
checks the prepared tree ownership. Native zstd decoding needs
no separately installed zstd program. Explicit/offline inputs remain available
with `--platform-assets`; `--no-guest-download` retains proxy-only/contributor use.
The installed selection is reused without resolving discovery again.
Guest-only upgrade and rollback use the same acquisition path. Broader host
upgrade remains under #238. Installed/public proof and the unchanged-host/new-guest
journey remain under #239.

## Upgrade or roll back the installed default guest

On the installed host, run these commands as the instance owner from any working
directory. The instance must have a default guest acquired through OCI and an
installed `package-info`. The commands use the installed host's compatibility
identifier and trusted repository. Linux extraction retains the installer's sudo
requirement for numeric ownership; Mac staging uses APFS image clones.

Upgrade downloads changed guest bytes and selects the complete guest for the next
sandbox boot. Running guests keep their current inputs until you stop and start
them. The command retains the previous selection for rollback. Host binaries,
policy, credentials, audit data and agent homes stay unchanged. Keep the guest
store and the instance's `share/guest-versions/` directory: active and rollback
selections reference those files. Upgrade does not remove older guest assets.

For the default instance, select the latest compatible guest:

```sh
safeyolo guest upgrade
```

Success prints the selected version and the index, child-manifest and archive
digests as JSON. `previous` identifies the rollback selection. Repeating the
upgrade reuses unchanged archive bytes and backend inputs. Normal startup and
restart do not contact the registry or select a newer guest.

If the selected guest fails to start or you need the prior guest, restore the
previous selection locally:

```sh
safeyolo guest rollback
```

Success prints the restored guest. Rollback makes no registry request and leaves
running guests intact. After a successful rollback, repeating rollback retains
the restored selection. Stop and start the affected agent to boot that guest,
using the existing `safeyolo agent stop NAME` and `safeyolo agent start NAME`
commands with its configured name.

For another instance, put `--root /absolute/instance/path` before `guest`.
For a specific release, pass `--index sha256:DIGEST` to `guest upgrade`, replacing
`sha256:DIGEST` with the complete OCI index digest from that guest's publication.
The Rust consumer verifies that index and pins its selected child and blob;
it does not read the moving compatibility tag. Upgrade reuses the persistent
store chosen during installation. A registry, compatibility, verification or staging failure preserves
the selected guest. An interrupted command can be repeated; activation replaces
the complete current/previous selection atomically.

Custom guest profiles and host/component-pair upgrades are outside these
commands. Local source controls cover selection, guest boot staging, failure
recovery and state preservation. Public GHCR and clean booted-platform proof
remain under #239.

## Prepare and publish a default guest release

The [manual repository workflow](../.github/workflows/guest-oci.yml) prepares
releases without registry writes by default. The authorized one-time
host release (H) and initial guest release (G1) have been published.
The workflow's explicit `publish_initial_g1` mode supports only that original
G1 and identical recovery retries. Automatic and later publication remain held
under #1003. Preparation does not restart automatic host releases or change Latest.

For a maintainer with repository Actions access, select the approved source
revision in **Prepare default guest OCI release**, and enter a new guest version
and its compatibility identifier. Leave `publish_initial_g1` disabled. The
workflow builds amd64 and arm64 outputs with the maintained builders. The
arm64 build also supplies the Mac kernel,
initramfs and ext4 image. The builders use architecture-specific Debian manifest
digests and write the actual preserved manifest identity to `build-base.txt`.
That small build file becomes the child's build-base annotation; it is not a
published catalogue or a file in the backend archive. Host-shipped executable
source/profile receipts remain separate and unchanged.

Each successful archive step prints its actual compressed byte size. The
workflow returns `verified-guest-oci-layout`, containing standard OCI objects
and all three opaque archives. The verifier checks every advertised child,
config and blob, including distinct Mac/Linux arm64 archive identities.
Preparation does not prove public retrieval, bootable platform content, native
acquisition or the installed independent-update scenario.

For local preparation, use native Linux builders for each guest architecture.
Install the [builder prerequisites](../guest/README.md#linux-setup), plus GNU
tar and zstd. Use a clean source checkout and its pinned Rust toolchain.
Prepare amd64 outputs at `guest-build-amd64/` and arm64 outputs, including kernel
and initramfs, at `guest-build-arm64/`, using `OUTPUT_DIR` with
`guest/build-all.sh`. Set `ARCH` to the native architecture; set `BUILD_KERNEL=1`
for the arm64 build. Do not archive an active or unfinished build. From the
repository root, these commands write `guest-archives/` and `guest-oci/`, then
validate the complete release without registry writes. Replace the example
version and compatibility with the intended guest release values.

```sh
guest/archive-default.sh linux/amd64 guest-build-amd64 guest-archives/linux-amd64
guest/archive-default.sh linux/arm64 guest-build-arm64 guest-archives/linux-arm64
guest/archive-default.sh darwin/arm64 guest-build-arm64 guest-archives/darwin-arm64
scripts/install_oras.sh "$HOME/.local/bin"
cargo build --locked --manifest-path proxy/Cargo.toml --example verify_guest_oci
ORAS="$HOME/.local/bin/oras" scripts/publish_guest_oci.sh \
  --artifacts guest-archives --layout guest-oci --version guest-2026-10-12.1 \
  --compatibility v1 --revision "$(git rev-parse HEAD)" \
  --verifier proxy/target/debug/examples/verify_guest_oci
```

Success prints each platform's verified identities and size, followed by the
complete index digest. GNU tar preserves Linux numeric owners, modes, links,
access control lists and extended attributes. Sparse ext4 data uses GNU pax
sparse metadata when the build filesystem reports holes. A matching GNU tar
extraction restores that format. Filesystems that report a fully allocated
source do not provide a sparse-map witness; test on a native filesystem before
claiming sparse preservation. Missing `cache-paths.txt`, backend files or pinned
build provenance stop preparation. An older cached build without provenance
must be rebuilt; do not infer its input from the current Debian tag.

For initial G1 publication, use an authenticated release maintainer account with
repository Actions access. First integrate the independently accepted workflow
control into `master`, complete H's final package checks, and publish H. The
initial G1 run then uses the repository-owned `GITHUB_TOKEN` with job-only
`actions: read` for retained downloads and `packages: write` for publication.
Package access and public anonymous retrieval still need verification during
that execution.

From a terminal with authenticated `gh`, dispatch the integrated workflow:

```sh
gh workflow run guest-oci.yml --repo craigbalding/safeyolo --ref master \
  -f version=guest-2026-10-12.1 -f compatibility=v1 -F publish_initial_g1=true
```

This run skips guest builds and preparation. It downloads only the retained
artifacts from [run 38248401312](https://github.com/craigbalding/safeyolo/actions/runs/38248401312):
archive artifacts `11748025327` and `11746464998`, and verified layout
`11747551391`. They expire on 10 January 2027. The publisher, ORAS 1.3.4 installer
and native verifier come from checked source
`8234a047d810d543d8c4d1cb1fa9859987be035b`. Only the verifier is compiled; no guest
payload is rebuilt or assigned the workflow control's newer revision.

Before registry authentication, the workflow rejects conflicting version or
compatibility inputs. It verifies the retained layout's complete descriptor
chain, reconstructs the layout from the retained archives with the accepted
publisher, and requires both layouts to resolve to
`sha256:df0068692909088a90db2c8f9777807404e3b7d8061ee72bc94a5feabd7dc46e`.
Missing or corrupt inputs stop before uploads. Successful publication prints
`Published ghcr.io/craigbalding/safeyolo-guest:guest-2026-10-12.1` with
`compat-v1` pointing to that exact index. A failed run must be diagnosed before
an identical recovery retry; the mode cannot select another version, run or
registry repository.

The shared concurrency group serializes all versions and generations, with
cancellation disabled. Direct publisher invocations must use the same exclusive
publication window; OCI tags do not provide compare-and-swap.
`--publish ghcr.io/craigbalding/safeyolo-guest` enables remote writes.
`--plain-http` exists for disposable local registry tests; public GHCR uses TLS.

The publisher uploads every child and its content by digest. It rejects
conflicting guest-version reuse. It fetches all uploaded child/config/blob bytes
into fresh storage and runs the native validator before uploading the full
index. After index readback succeeds, it assigns the guest version and advances
`compat-<C>`. Repeating identical input is allowed; conflicting reuse of a guest
version fails. ORAS's creation annotation is fixed to the version date so retries
do not change content identity. Any failed verification stops before promotion.
An interrupted upload can leave untagged content; retry with the same source
and artifacts. The publisher never deletes prior version tags, indexes,
manifests or blobs. It leaves other compatibility generations unchanged.

After the first authorized publication, the package owner must make the GHCR
package public in its settings and verify all three targets anonymously with
an empty ORAS registry configuration. Ordinary Rust consumers require no
personal token or registry account. See GitHub's
[package visibility instructions](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility).
The retained run reported compressed default archives of 229,345,953 bytes for
darwin/arm64, 233,300,853 bytes for linux/amd64 and 223,000,369 bytes for
linux/arm64. Anonymous GHCR retrieval, native filesystem sparsity and installed
platform evidence remain pending until those runs occur.
Keep supported versions and rollback content out of registry cleanup jobs.
GHCR's documented blob limit or timeout must be observed with an actual default
payload before considering another distribution scheme.

The focused producer/publisher tests use real ORAS 1.3.4, skopeo's reference
parser and a disposable local Distribution API fixture. From the source checkout with the frozen test
environment, the installed ORAS and compiled native example above, run:

```sh
ORAS="$HOME/.local/bin/oras" GUEST_OCI_VERIFIER="$PWD/proxy/target/debug/examples/verify_guest_oci" \
  uv run --frozen --no-sync pytest -q tests/test_guest_oci_publisher.py \
  --basetemp="$HOME/guest-oci-tests"
```

The tests check archive metadata, real OCI creation, upload/readback ordering,
immutable-version conflicts/retries, incomplete and corrupt content refusal,
older-channel retention and default-off initial-G1 workflow controls. The
workflow controls also execute pre-authentication validation with native-verified
fixtures and challenge missing, corrupt and mismatched retained inputs. The
sparse-map test reports a skip if the filesystem cannot supply its required sparse fixture.
The metadata test stages only a few KiB on the guest filesystem to exercise
numeric ownership; archives and registry data use the disk-backed basetemp.
These are source/local observations, not public or booted-platform acceptance.

## Local contract check

For contributors in a source checkout with its pinned Rust toolchain, a
complete local OCI layout can be checked without registry access. Supply its
release index SHA-256 digest and expected host compatibility. The example
reads the index and every referenced child, config and archive from the layout;
it writes no tags or installed state.

```sh
cargo run --locked --manifest-path proxy/Cargo.toml --example verify_guest_oci -- \
  /path/to/oci-layout sha256:<release-index-digest> v1
```

Success prints each verified consumer platform, child digest, archive digest
and size, then the index digest, guest version and compatibility. Invalid
content produces a nonzero exit. Focused unit checks run with
`cargo test --locked --manifest-path proxy/Cargo.toml --lib guest_oci::tests`.
These checks establish the source contract, not public GHCR transfer, archive
extraction, installed startup or an unchanged-host G1/G2 update journey.

The tests also consume a checked-in tiny synthetic
[OCI layout](../proxy/tests/fixtures/guest-oci/index.json) produced with ORAS
1.3.4's custom platform configs and index creation. Its archive bytes are valid
compressed tar fixtures; the files inside are placeholders for wire checks,
not bootable guests or real Debian build provenance.

The contract uses the primary [OCI index](https://github.com/opencontainers/image-spec/blob/v1.1.1/image-index.md),
[manifest](https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md),
[descriptor](https://github.com/opencontainers/image-spec/blob/v1.1.1/descriptor.md)
and [annotation](https://github.com/opencontainers/image-spec/blob/v1.1.1/annotations.md)
specifications, the pinned [ORAS index implementation](https://github.com/oras-project/oras/blob/v1.3.4/cmd/oras/root/manifest/index/create.go)
and [oci-client API](https://docs.rs/oci-client/0.18.0/oci_client/client/struct.Client.html).
