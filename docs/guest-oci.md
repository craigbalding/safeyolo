# OCI guest source contract

The default guest filesystem has an independent release identity from the
SafeYolo host package. The Open Container Initiative (OCI) index, manifests,
descriptors and annotations are the sole guest release catalogue. Public guest
artifacts use `ghcr.io/craigbalding/safeyolo-guest` in GitHub Container Registry
(GHCR).

This document defines the source contract for publication, native acquisition
and explicit guest upgrades. The [native Rust validator](../proxy/src/guest_oci.rs)
and its [focused tests](../proxy/src/guest_oci/tests.rs) implement the shared
rules. The production publisher, registry client, installed selection and
upgrade path still require integration under issues #211, #237 and #238.
Issue #239 owns installed-platform and independent-update proof. The source
contract does not establish those outcomes or authorize public publication.

## Discovery and release identity

Each release has an immutable version tag `guest-YYYY-MM-DD.N`. The date is a
valid calendar date; `N` contains decimal digits. The complete tag is at most
128 ASCII characters. A compatibility identifier `C` is a nonempty suffix of
at most 121 ASCII letters, digits, underscores, dots or hyphens. Its discovery
tag is `compat-<C>`, for example `compat-v1` for identifier `v1`.

The host package must carry `guest_compatibility`, `guest_repository` and
`guest_discovery_tag`. Those three fields belong in the existing strict
package metadata writer/reader when acquisition is integrated. They must not
include a fixed guest index or archive digest. Host version, source, profile,
platform and runtime requirements remain separate.

The publisher must verify the complete release before moving its compatibility
tag. Guest version tags must not be retargeted. An incompatible generation
uses another channel and preserves discovery for supported older hosts.
The publisher owns serialization of promotion, conflicting-version refusal
and retention of supported releases and rollback content. OCI tagging alone
does not enforce immutability or compare-and-swap promotion. These publication
controls belong to #211 and remain pending under the publication hold.

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
`docker.io/library/debian:trixie@sha256:<selected-architecture-digest>`.
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

Native acquisition will use `oci-client` 0.18.0. Integrate the current ring TLS
provider, proxy and certificate authority (CA) paths with fallible
`Client::try_from(ClientConfig)`. Resolve once with `pull_manifest_raw`, use
`Reference::clone_with_digest` for subsequent requests, and select the consumer
platform explicitly with `platform_resolver: None`. Do not use implicit
`pull_image_manifest` selection or the buffering whole-image `pull` path.
Stream `pull_blob` to a staging file, use the library's hash check, and check
the actual file size against the descriptor. Raw child length also needs its
descriptor-size check. This network/TLS integration belongs to #237; the
contract adds no registry dependency or alternate integrity catalogue.

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
These installation/upgrade behaviors remain work for #237/#238 and #239 proof.

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
