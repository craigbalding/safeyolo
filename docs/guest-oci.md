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
proof or the publisher's ongoing retention obligations. The nightly workflow
automatically stages candidates and considers eligible candidates for promotion
under the age and evidence gates described below. Manual dispatch uses the same
gates. The retained G2 publication below is a historical record.

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

### Explicit custom profiles

A custom index and every child also carry the same nonempty
`dev.safeyolo.guest.profile`, for example `kali-pentest`. Each child requires
`dev.safeyolo.guest.build-inputs=sha256:<64 lowercase hex>`, the digest of its
completed build's `build-inputs.json`. That record contains declared source
hashes, base identity, architecture, output kind and frozen tool inputs.
The archive producer includes the record in the opaque archive. The normal
archive digest verifies all transported bytes.

Custom indexes contain one or more of the supported consumer platforms.
They need not contain every default-release platform. Duplicate or unknown
platforms, incompatible generations and mismatched child profile identities
are rejected. The maintained Kali profile supplies both Linux architectures
and macOS arm64; its ARM64 distro build is reused for tree and ext4 exports.

Prepare custom archives with `guest/archive-default.sh`, then invoke the same
publisher with `--profile NAME`. Retained-layout publication also requires
that explicit name. Custom publication does not update a compatibility tag.
Stock compatibility-tag discovery and default promotion exclude custom profiles. Consumers
select a custom index explicitly by immutable digest through the existing
installer or guest upgrade command. The host compatibility requirement and
normal ownership/ext4 contracts remain enforced. The
[custom-rootfs guide](../contrib/ROOTFS_SCRIPT_GUIDE.md#cached-kali-builds)
describes the local staged build and export path.

### Publish a qualified custom layout through Actions

The `custom-profile` activity in `guest-oci.yml` publishes an explicitly
selected layout through the repository's `GITHUB_TOKEN` writer.
It does not run a distro build. It copies the unchanged index by digest and
reads back every child, config and archive through the shared verifier.
Existing version and compatibility tags retain their targets. Custom indexes
remain outside default discovery and promotion.

First qualify the consumer archives with the maintained profile builder,
exporter and archive producer. Keep each selected consumer's `guest.tar.zst`,
`build-inputs.json` and `build-base.txt` together under `darwin-arm64`,
`linux-amd64` or `linux-arm64` in one archive directory. Preserve the recorded
archive and build-input hashes from that qualification. Publication checks
those identities; it does not establish boot, installed isolation or clean-host
acceptance.

On a Linux maintainer machine, use Python 3.12+, a source checkout, the maintained ORAS
publisher and a current shared native verifier that supports custom profiles.
Set `ARTIFACTS` to the qualified archive directory and `LAYOUT` to an owned
directory for the complete OCI layout. Set `PROFILE_SOURCE` to the full source
commit used for the qualified profile inputs. It can differ from the Actions
publisher commit. Set `GUEST_VERSION` to a fresh `guest-YYYY-MM-DD.N` identity,
`PROFILE_NAME` to the custom profile name, `COMPATIBILITY` to the host's required
identifier, and `VERIFIER` to the native verifier executable. From the checkout:

```sh
scripts/publish_guest_oci.sh --artifacts "$ARTIFACTS" --layout "$LAYOUT" \
  --version "$GUEST_VERSION" --compatibility "$COMPATIBILITY" \
  --revision "$PROFILE_SOURCE" --profile "$PROFILE_NAME" --verifier "$VERIFIER"
INDEX=$(oras resolve --oci-layout "$LAYOUT:$GUEST_VERSION")
```

The command verifies the complete local layout and prints its immutable index
digest. Transfer the unchanged layout with the maintained upload helper below.
The helper uses the operator's existing authenticated `gh` repository access.
Set `INPUT_RELEASE` to a new input-transfer release tag, for example
`guest-layout-` followed by the index's SHA-256 hex. Set `TRANSFER_DIR` to a new
owned directory outside the checkout, with disk space for the complete layout.

```sh
scripts/upload_guest_profile_layout.sh "$LAYOUT" "$PROFILE_SOURCE" "$INPUT_RELEASE" "$TRANSFER_DIR"
```

The helper packs `oci-layout`, `index.json` and `blobs/` at the tar root and
splits the stream into 1 GiB parts. [GitHub limits each release asset](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases)
to less than 2 GiB; splitting preserves larger complete layouts without changing their
OCI bytes. The helper creates a prerelease at `PROFILE_SOURCE`, explicitly
leaves Latest unchanged, uploads the parts with `gh release create`, and reads
their numeric asset IDs through the release API. These assets supply input
transport; OCI remains the guest catalogue. The resulting
`TRANSFER_DIR/layout-upload.json` records the ordered asset IDs, combined tar
SHA-256, source revision and release ID. No local GHCR credential is used.
After an interrupted upload, inspect that release and its assets before another
write. The helper does not replace existing assets or delete retained inputs.

After this workflow change is on `master`, an authenticated repository operator
can dispatch the writer. The following command uses Python and `gh` from the
same checkout. It sends the upload identities, selected source/profile/index and hashes the
qualified archive and build-input files. Check those hashes against the retained
qualification before dispatch. Set `REQUEST_FILE` to an owned JSON file outside
the checkout. No local GHCR login is required.

```sh
export ARTIFACTS INDEX PROFILE_SOURCE PROFILE_NAME TRANSFER_DIR COMPATIBILITY
python3 - <<'PY' > "$REQUEST_FILE"
import hashlib
import json
import os
from pathlib import Path

def digest(path):
    with path.open("rb") as stream:
        return "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()

artifacts = Path(os.environ["ARTIFACTS"])
platforms = {}
for name in ("darwin-arm64", "linux-amd64", "linux-arm64"):
    directory = artifacts / name
    if directory.is_dir():
        platforms[name.replace("-", "/")] = {
            "archive": digest(directory / "guest.tar.zst"),
            "build_inputs": digest(directory / "build-inputs.json"),
        }
transfer = json.loads((Path(os.environ["TRANSFER_DIR"]) / "layout-upload.json").read_bytes())
print(json.dumps({
    **transfer,
    "index": os.environ["INDEX"], "source_revision": os.environ["PROFILE_SOURCE"],
    "profile": os.environ["PROFILE_NAME"], "platforms": platforms,
}, indent=2))
PY
cat "$REQUEST_FILE"
```

After the request matches the qualified inputs, dispatch it:

```sh
gh workflow run guest-oci.yml --repo craigbalding/safeyolo --ref master \
  -f activity=custom-profile -f compatibility="$COMPATIBILITY" \
  -f custom_profile=@"$REQUEST_FILE"
```

The writer downloads the exact asset IDs in order, checks the combined tar
SHA-256, and extracts the layout into a new directory with Python's data-only
tar filter. The extracted root contains `oci-layout`, `index.json` and `blobs/`.
The writer refuses a mismatched source, profile, platform set, archive digest
or build-input digest before registry login. The index digest binds all
manifest and config bytes, including pinned base identities. The shared verifier
checks compatibility and every referenced descriptor. A failed upload, login
or readback fails the job. The `guest-custom-profile-result` artifact retains
the request, verified selection and reached publication results. Only a
successful readback writes `custom-profile-publication/result.json`, which
includes the selected identities, destination and Actions publisher revision.
Inspect the original run and live digest after an uncertain write before retrying.

For a clean host with a verified compatible host bundle, set `HOST_BUNDLE` to
the unpacked bundle directory, `ROOT` to the new installation directory, and
`INDEX` to the successfully published custom index digest. Use the maintained
installer from the qualified source checkout:

```sh
scripts/install_native.sh --bundle "$HOST_BUNDLE" --root "$ROOT" --guest-index "$INDEX" --yes
```

The installer selects the current host platform explicitly and verifies the
published bytes. It does not repeat the distro build. For an existing
compatible installation, select the same digest with
`safeyolo --root "$ROOT" guest upgrade --index "$INDEX"`, then stop and start
the agent to use it. Publication success alone does not prove either installed
workflow or complete the custom-profile acceptance criteria.

## Descriptor verification and selection

Each index child, config and archive descriptor must carry the required media
type, a standard lowercase `sha256:<64 hex>` digest and a nonnegative `int64`
raw byte size. Verify referenced raw bytes against both digest and size before
using them. Optional descriptor annotations must also contain string values.
Do not hash parsed and reserialized JSON in place of the referenced raw bytes.
Hashes identify content; they do not authenticate the publisher independently
of the trusted repository or prevent deletion. Retention remains a publisher
responsibility. Signing or additional provenance is not a prerequisite here.

Resolve discovery once for an acquisition or upgrade operation, unless an
explicit index digest selects the release. Validate the
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
consumer platform. `validate_children` checks all declared children in
`ConsumerPlatform::ALL` order, including distinct Mac/Linux arm64 archive
identities. `Descriptor::verify` checks a reader incrementally through EOF;
`check_size` supports callers whose OCI client already verifies the hash.

Use the current stable ORAS release resolved and verified by
`scripts/install_oras.sh`. Freeze its identity for the build. Use
`push --image-spec v1.1` with the custom platform config and typed archive,
then `manifest index create` from exact child digests. Set the required index
annotations and artifact type explicitly.
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
On Linux, the verified archive retains its original numeric UID/GID bytes,
whose published root base is `100000`.
A fresh prepared tree shifts the published range to the selected subordinate
UID and GID bases independently. Guest UID/GID 1000 map to the host account;
other guest IDs keep their offsets. Preserve modes, links, extended attributes
and `cache-paths.txt`. The installer links to this prepared `rootfs-tree/`.
The prepared-store key includes the archive digest, both subordinate bases
and the host UID/GID. Reuse requires that exact mapping. Never recursively
change ownership of a shared prepared or live tree.
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
Linux extraction uses sudo for numeric ownership. The ownership operation
checks every source owner, hard link and attribute before changing a fresh
stage. It then reopens only inodes that need ownership or attribute changes,
relative to the pinned root without following symlinks. Hard links that leave
that stage are refused. Existing prepared trees
are checked against the selected mapping and remain unchanged. Native zstd decoding needs
no separately installed zstd program. Explicit/offline inputs remain available
with `--platform-assets`; `--no-guest-download` retains proxy-only/contributor use.
The installed selection is reused without resolving discovery again.
Guest-only upgrade and rollback use the same acquisition path. Broader host
upgrade remains under #238. Installed/public proof and the unchanged-host/new-guest
journey remain under #239.

## Nightly consumer staging receipt

Nightly blackbox selects a complete staged candidate independently of the
promoted compatibility channel. The shared
[`select_blackbox_artifacts.py`](../scripts/select_blackbox_artifacts.py)
reads existing OCI version tags and attachments. It adds no release catalogue
and never writes a tag. Host build selection and retention are separate from
guest production and from public host release/Latest selection.

The staging controller attaches one original build/staging receipt
after it uploads and verifies all three archives and the complete index.
Use `application/vnd.safeyolo.guest.staging.v1+json` as both the attachment's
artifact type and the receipt layer's media type. The attachment's OCI
`subject` must contain the index digest, size and media type. Package inventories
can be other layers in this same attachment; do not add guest index children.

The selector reads this subset of the full build/staging receipt. The publisher
retains the inventories and applies the promotion guard.
The example values must be replaced with the actual index, source, UTC staging
completion and successful default-branch producer identities:

```json
{
  "schema": "safeyolo.guest-staging/v1",
  "index_digest": "sha256:<64 hexadecimal digits>",
  "source_revision": "<full source commit>",
  "staged_at": "2026-10-17T04:28:31+00:00",
  "producer": {
    "repository": "craigbalding/safeyolo",
    "workflow": ".github/workflows/guest-oci.yml",
    "run_id": 123,
    "run_attempt": 1,
    "job_id": 456
  }
}
```

The selector checks the attachment subject and descriptor hashes, the receipt's
source/index, and the successful staging job in that exact workflow run and
attempt. `staged_at` must fall inside that job's UTC interval. A retry of the
same bytes preserves the original trustworthy receipt. A new index is a new
candidate. Publication dates and legacy version dates do not supply staging
completion evidence. The current historical publications lack this new receipt;
they are not silently substituted into the nightly candidate path.

The newest completed compatible staging time determines nightly selection.
Uncompleted indexes remain visible in the selection report. Promotion age and
earlier blackbox outcomes do not determine test input. The selector checks all
three child/config identities and archive availability, then freezes this
platform's exact index, child and archive descriptors. Native acquisition or
offline verified archive extraction consumes those identities. A missing or
invalid selected input fails; execution never resolves a guest tag again.

For inspection, install ORAS through the existing publisher tooling. Replace
`sha256:DIGEST` with the recorded index digest. From any working directory:

```sh
oras discover --artifact-type application/vnd.safeyolo.guest.staging.v1+json --format json --depth 1 ghcr.io/craigbalding/safeyolo-guest@sha256:DIGEST
```

The result identifies the digest-bound staging attachment. Missing staging
input blocks nightly consumption. Testing a quarantined candidate does not
promote it. Public-install smoke continues to select `compat-*` explicitly.

## Acquire a specific guest before installation

On the consumer host, run `guest acquire` as the installation owner from any
working directory. Use a verified host package for that platform and a fresh
root without configuration or guest inputs. Registry access uses the configured
proxy, if present, and needs usable system or configured CA trust. Linux also needs the
host account's subordinate UID/GID ranges and sudo for numeric ownership, as
prepared by `safeyolo host prepare`.

Before running the example, replace `/path/to/host-package` with the verified
unpacked host package. Replace `/owned/fresh-root` and `/owned/guest-store` with
paths owned by your account. For a cold acquisition, the store must be new.
Replace `sha256:DIGEST` with the complete index digest from the guest release's
publication. The package metadata stays unchanged.

```sh
safeyolo --root /owned/fresh-root guest acquire --package-info /path/to/host-package/package-info --write-selection /owned/fresh-root/share/guest-selection.json --store /owned/guest-store --index sha256:DIGEST
```

Success prints the prepared asset directory and writes the selection as JSON.
The consumer verifies the requested index, compatibility, platform, child,
config and archive through the same path used by default acquisition. Keep
the store: installed inputs reference its prepared trees. To install these
inputs, pass the printed directory to the host package's `install.sh` with
`--platform-assets`, using the same root and a separate `--command-dir`. The
installer retains the generated `share/guest-selection.json` and installs the
backend files beside it before initialization.

Without `--index`, acquisition resolves the package's compatibility tag.
An existing installed selection is retained even when `--index` names another
release. Use `guest upgrade --index sha256:DIGEST` to change an installed guest.

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

The [guest workflow](../.github/workflows/guest-oci.yml) builds and stages at
**01:17 UTC each day**. Its independent promotion activity runs at **02:47 UTC**.
GitHub can delay scheduled runs. The promotion clock uses elapsed UTC seconds,
so a delay or a missed run does not change a candidate's age. A failed build
does not prevent the promotion activity from considering an earlier candidate.
Only the repository's default branch can run these publication activities.

Each build resolves the official Debian **Trixie** index and both Linux
architecture manifests once. The shared [resolver](../guest/resolve_inputs.py)
also selects stable mise, gh, kernel and ORAS releases. The builders use this
frozen record. They check official checksums, mise/ORAS checksum signatures
and the kernel release signature. Kernel keys come from the developers' Web Key
Directories at kernel.org and, for Ben Hutchings, Debian. The mise key comes
from its publisher at `https://mise.jdx.dev/gpg-key.pub`. These sources supply
complete keys with self-signed user IDs for GPG compatibility. The existing
full fingerprints remain the trusted identities. Resolution, verification,
a missing architecture or an incompatible tool interface fails the build. There is no
embedded old-version fallback. Actions commit pins and source lockfiles remain.

The rootfs builder uses signed `trixie`, `trixie-updates` and `trixie-security`
repositories. APT update errors fail. The builder upgrades inherited packages,
installs the guest packages and rejects remaining upgradable packages.
Rootfs, kernel and initramfs outputs are rebuilt. Cached downloads must match
the resolved identities before reuse. See the [build prerequisites](../guest/README.md#linux-setup).

### Staging and promotion

Build/stage creates all three backend archives and an immutable
`guest-YYYY-MM-DD.N` index. The automatic suffix includes the workflow run ID
and attempt, so a fresh rebuild gets a new version. Archive output reports
compressed bytes, apparent filesystem bytes and allocated disk bytes separately.
A sparse image's apparent size includes unused capacity.

The existing publisher uploads by digest, reads all uploaded archives back and
runs the native OCI verifier. It then verifies the complete index and assigns
only the immutable version tag. **Staging never moves `compat-v1`.** After the
stage job succeeds, the receipt job attaches the original verified completion
time and its exact run/job/attempt. A retry of the same retained index preserves
that original trustworthy receipt. An unfinished or failed job cannot supply age.
The index's real assembly timestamp is separate from `staged_at`.

Promotion selects the newest trusted complete candidate that has reached
**172800 elapsed seconds** from `staged_at`. Newer quarantined candidates do not
reset older clocks. Legacy versions without a trustworthy staging receipt are
ineligible. Missing, malformed, future or mismatched receipts hold promotion.
Neither a version date nor an upstream, commit or run-start date supplies age.

The guard requires existing installed guest proof for the **same index** on
Linux AMD64, Linux ARM64 and a physical Darwin/VZ host. It uses the maintained
installed runner and compatible retained production host/helper packages.
Package-only hosted macOS checks do not qualify as VZ guest proof. A qualifying
result is reused; the same test need not run at both ends of quarantine.
A missing or failed latest platform result holds promotion with a visible reason.
No product rebuild, repackaging or OCI metadata rewrite occurs during promotion.

Before moving `compat-v1`, the guard verifies every staged archive again,
rechecks the current channel and pause state, rejects replacement of a newer
accepted selection, and records the decision. It moves the tag by index digest
and verifies readback. All normal manual and scheduled promotion uses this guard.
There is no age bypass or automatic security exception. The existing publication
concurrency group serializes all versions and generations; direct maintainer
writes must use that same exclusive publication window. OCI tags have no
compare-and-swap operation. After an uncertain write, inspect the live tag and
retained decision before retrying.

Automatic guest promotion does not publish a host release, change Latest or
upgrade an installed instance. Instances still use explicit
[`guest upgrade` and `guest rollback`](#upgrade-or-roll-back-the-installed-default-guest).
Prior version tags, indexes, archives and rollback content remain retained.

### Manual run, inspection and recovery

From a source checkout, a maintainer with authenticated `gh` and repository
Actions access can request a fresh build/stage or consideration of eligible
candidates. These commands run the integrated default-branch workflow:

```sh
gh workflow run guest-oci.yml --repo craigbalding/safeyolo --ref master -f activity=build-stage
gh workflow run guest-oci.yml --repo craigbalding/safeyolo --ref master -f activity=promote
```

An optional `version=guest-YYYY-MM-DD.N` selects a new immutable build name.
Manual dispatch retains the `compatibility` input; it defaults to `v1`.
A conflicting existing name fails. Manual promotion applies the same age,
content and platform checks as the schedule. No runner sleeps for 48 hours.

For inspection, install the publisher tools on a Linux maintainer machine with
Python 3.11+, GnuPG, curl and tar. Use registry read access; if anonymous reads
are unavailable, reuse an authorized maintainer or Actions publisher identity.
Run from the source checkout. Inspection needs no Rust compiler or native OCI
verifier. The following command reads the current channel and its digest-bound
receipts; it writes no tag:

```sh
scripts/install_oras.sh "$HOME/.local/bin"
PATH="$HOME/.local/bin:$PATH" scripts/publish_guest_oci.sh --inspect \
  --reference ghcr.io/craigbalding/safeyolo-guest:compat-v1
```

Replace the reference with a version tag or `ghcr.io/craigbalding/safeyolo-guest@sha256:DIGEST`
to inspect a retained candidate. The output contains source and run links,
resolution/build/assembly/staging times, tool identities, per-architecture
package inventories and promotion decisions. The `attachments` field preserves
each attachment descriptor, original manifest and subject descriptor, parsed
receipt and original UTF-8 `receipt_text`. The staging attachment also holds
the exact signed APT metadata, APT sources, archive keyring, builder versions,
resolved inputs and kernel configuration. These records remain in GHCR after
Actions logs and build artifacts expire. An inventory does not promise a
bit-for-bit rebuild from future live APT repositories; the retained candidate
provides the exact bytes.

To recover a decision when its candidate identity is missing, set
`PROMOTION_JOB_ID` to the original Actions promotion job ID. Choose a new output
path outside the checkout for `INSPECTION_FILE`. With authenticated `gh` and
the publisher tools on `PATH`, run from the checkout:

```sh
scripts/publish_guest_oci.sh --inspect --promotion-job "$PROMOTION_JOB_ID" > "$INSPECTION_FILE"
```

The reader derives the run and actual attempt from that job's Actions record.
It searches retained immutable guest versions for decisions with that exact
repository, workflow, run, attempt and job. It does not infer the historical
candidate from the current channel. `matches` contains each matching index,
its original decisions and its retained staging/smoke attachments. No match
leaves the historical selection unknown and exits 2. Current smoke attachments
can include records added after the original promotion job.

If local registry reads are unavailable, a maintainer with authenticated `gh`
and repository Actions write access can use the integrated default-branch
`inspect` activity. From the checkout, with `PROMOTION_JOB_ID` set as above:

```sh
gh workflow run guest-oci.yml --repo craigbalding/safeyolo --ref master \
  -f activity=inspect -f promotion_job="$PROMOTION_JOB_ID"
gh run list --repo craigbalding/safeyolo --workflow guest-oci.yml --event workflow_dispatch --limit 5
```

Select that inspection dispatch's run ID as `INSPECTION_RUN_ID`, separate from
the historical promotion run. Set `INSPECTION_DIR` to a new directory outside
the checkout. After the inspection job finishes, retrieve its output:

```sh
gh run view "$INSPECTION_RUN_ID" --repo craigbalding/safeyolo
gh run download "$INSPECTION_RUN_ID" --repo craigbalding/safeyolo \
  --name guest-promotion-inspection --dir "$INSPECTION_DIR"
```

Only the inspection job runs. It uses the existing workflow identity with
registry read permission, writes the report to its Actions summary and retains
`guest-inspection.json` as an artifact, including a reported no-match result.
It does not build a native verifier, repeat installed qualification, attach a
receipt or request promotion.

A returned decision identifies the promotion controller source, run/job,
selected `index_digest`, `old_index`, proposed `new_index` and compatibility
identifier. For a held decision, `new_index` is the proposed selection; it is
not evidence of a tag write. A failed latest platform gate includes the exact
`failed_smoke` receipt, with its original finish time, result, reason and origin
fields. The same structured result appears in stdout and the Actions summary,
and the failed operation still exits nonzero. A `retention_error` means that
decision attachment or readback failed; inspect existing attachments before
assuming that the decision is available in GHCR. `publication-uncertain` means
a tag write was attempted without confirmed success. Inspect the live tag and
retained decisions before considering another write.

An older decision may omit `failed_smoke`; current smoke receipts cannot
establish which receipts existed during that operation. Keep missing historical
evidence explicit. The inspection report preserves the records it finds and
does not fill absent fields from later records.

To retrieve the full inventory files, use `oras discover --artifact-type
application/vnd.safeyolo.guest.staging.v1+json --format json --depth 1` with that
index reference. Set `RECEIPT_DIGEST` to the returned attachment digest and
`INVENTORY_DIR` to a new directory outside the checkout. Then run:

```sh
oras pull --output "$INVENTORY_DIR" "ghcr.io/craigbalding/safeyolo-guest@$RECEIPT_DIGEST"
```

The Actions summary renders the receipts and version/package changes from the
previous retained receipt. It is not the only copy. Failed promotion decisions
and platform attempts are separate attachments; later results do not overwrite
them. Resolver/build errors and held promotion failures appear in the workflow.
Use GitHub Actions failure notifications for this workflow in the maintainer's
GitHub notification settings. The independent hardware cron/mail deployment
remains separate. To inspect recent runs:

```sh
gh run list --repo craigbalding/safeyolo --workflow guest-oci.yml --limit 10
```

During an incident or explicit rollback, disable the workflow first. This pauses
both automatic guest activities. A promoter checks the workflow state before
its tag write. A write that has already started can still finish. From the same authenticated maintainer terminal:

```sh
gh workflow disable guest-oci.yml --repo craigbalding/safeyolo
```

Wait for any current publication write to finish before rollback. Inspect the
live tag and its decision if a write was already attempted. Set `ACCEPTED_INDEX`
to a previously accepted index from the retained receipts. With the authorized
GHCR publication credential, move only the compatibility tag and check readback:

```sh
oras tag "ghcr.io/craigbalding/safeyolo-guest@$ACCEPTED_INDEX" compat-v1
oras resolve ghcr.io/craigbalding/safeyolo-guest:compat-v1
```

The returned digest must equal `ACCEPTED_INDEX`. Keep the workflow disabled
until the incident is resolved. Deliberate resume restores the normal guard:

```sh
gh workflow enable guest-oci.yml --repo craigbalding/safeyolo
```

### Reuse installed platform evidence

The hosted Linux retained-input jobs attach their existing installed reports
to the selected index. The physical hardware path uses the same
`tests/blackbox/retained_inputs.py` runner. Keep its `selection.json`,
`retained-run.json`, `installed-inputs.json` and `guest/installed-sections.json`
together. The installed isolation section must pass, including owned cleanup.
The result records the physical host ID and the actual host/helper/guest bytes.

For a completed retained run, an authorized repository operator can attach
those four reports through the existing Actions publisher. A same-installation
continuation can instead supply `selection.json` and an operator observation
named `installed-continuation.json`, as described below. Use a Linux
maintainer checkout with Python 3 and authenticated `gh`. The account must have
repository write, maintain or admin permission. The workflow uses its own
repository token for GHCR writes; no local registry login is needed.

Set `REPORTS` to the report directory and `GATE_URL` to the original execution
result link. Run this command after the workflow change is on default branch
`master`. It sends the original UTF-8 report texts. It starts a
serialized upload job without selecting a resolver, build, platform test or
promotion job:

```sh
set -euo pipefail
export REPORTS GATE_URL
python3 - <<'PY' | gh workflow run guest-oci.yml --repo craigbalding/safeyolo --ref master --json
import json
import os
from pathlib import Path

names = ("selection.json", "retained-run.json", "installed-inputs.json", "guest/installed-sections.json")
reports = Path(os.environ["REPORTS"])
if (reports / "installed-continuation.json").is_file():
    names = ("selection.json", "installed-continuation.json")
texts = {name: (reports / name).read_bytes().decode("utf-8") for name in names}
print(json.dumps({"activity": "record-smoke", "smoke_gate_url": os.environ["GATE_URL"],
                  "smoke_reports": json.dumps(texts)}))
PY
```

The job summary records the operator's attestation and identifies the upload
run separately from the platform execution. The attached reports keep their
original bytes, execution time, controller revision, host/package identities,
guest descriptors and section outcomes. An exact successful attachment is
retained without another write. Matching requires the same result fields and
all attached file bytes. Existing failed records remain available.
Incomplete evidence, unresolved failed sections and invalid operator or
workflow origins fail the upload. The normal promotion age and evidence
guards still apply.

For an interrupted run whose section runner could not start, keep the failed
execution unchanged. After correcting setup, run only the unstarted sections
with the same prepared installation. The operator can supply an existing
verified observation as `installed-continuation.json`. This is an explicit
operator attestation, not a replacement `retained-run.json` or a claim that
the original command passed. The observation must contain:

- `controller.revision` and `controller.dirty`, identifying the clean controller
  used for both commands. The revision must equal `selection.json`'s
  `controller_revision`.
- `original_execution` and `resume_execution`, each retaining its distinct `id`,
  actual argv in `command`, literal `exit`, and UTC `started_at`/`ended_at`.
  The original exit must be 2 and the resumed exit must be 0.
  The original command is `retained_inputs.py run` for the recorded lane. The
  resumed command is `installed_sections.py` for that lane, with explicit
  `--section`, `--prepared-config` and `--install-commit` operands. The resume
  also retains `controller_status`, which must be empty.
- `verified_operands.host`, `observed_at`, `installed_inputs`,
  `original_sections` and `resumed_sections`. Keep the installed-input and
  section records in their existing producer formats. All required sections
  for the lane must be present in the original collection. Each unsuccessful
  original row must record exit 2, `preparation_failure`, and the runner error.
  Only those rows may be resumed. The resumed collection must pass exactly
  those sections on the original prepared installation and source revision.
- `verified_operands.owned_live_markers` and `live_product_processes`, both
  empty after cleanup. If present, every `continuity_runtime_after` row must
  have `pid_exists` false. All original and resumed section rows must record
  `cleanup: stopped` and empty `cleanup_failures`.
- `verified_operands.report_hashes`, retaining the original SHA-256 hashes for
  `reports/installed-inputs.json`, `reports/guest/installed-sections.json` and
  `continuity-reports/installed-sections.json` from the observed report layout.
  The hashes identify the underlying originals; supplying the observation
  does not claim that the upload reconstructed or reread those files.
- UTC `recorded_at`. The original execution, resumed execution, operand
  observation and recording times must be in that order.

The publisher derives a passed receipt with
`execution_mode: same-installation-continuation`. It retains both execution
records and uses the resumed command's actual end time. The observation is
attached byte for byte, including its original failures and report hashes.
An assertion failure, failed cleanup, missing required section, changed
installed input, or inconsistent continuation refuses the upload. Supply the
two continuation files together; do not mix them with the three original
runner report files. This path does not run platform tests or publish a
promotion decision. A newer failed smoke receipt still holds promotion.

An operator with existing local publisher tools and GHCR write access can
also attach completed physical evidence outside Actions:

```sh
scripts/publish_guest_oci.sh --record-smoke --reports "$REPORTS" --gate-url "$GATE_URL"
```

Both paths record the authenticated repository operator's attestation.
The guard checks the exact index, platform, compatible host identities and
result. Missing physical access or reports holds promotion; source tests do not
replace platform proof. Do not put credentials in receipts or report files.

### Retained historical publications and transport fixture

The former G1/G2/reduced-default publication switches are retired. Their
accepted indexes and historical receipts remain available. They do not acquire
quarantine age from their names or older synthetic midnight annotations.

| Version | Source | Index | Original producer |
| --- | --- | --- | --- |
| `guest-2026-10-12.1` (G1) | `8234a047d810d543d8c4d1cb1fa9859987be035b` | `sha256:df0068692909088a90db2c8f9777807404e3b7d8061ee72bc94a5feabd7dc46e` | [38248401312](https://github.com/craigbalding/safeyolo/actions/runs/38248401312); archives `11748025327`, `11746464998`; layout `11747551391` |
| `guest-2026-10-16.1` (G2) | `ee291fba78ab34e4dca630d529ac8083ec29802f` | `sha256:b5f3b69562fd4b84730813bd3eb0554b351c975bb363a1be9404f0646147c06b` | [38897452318](https://github.com/craigbalding/safeyolo/actions/runs/38897452318); archives `12044318477`, `12044582213`; layout `12045630940` |
| `guest-2026-10-16.1082` | `33224c9fc14beeb00be30eb71bdc09f91c5aa58b` | `sha256:14359301826746d088f124205de232c77c40567871550d38b035e6bfb53e5a2e` | [38975155518](https://github.com/craigbalding/safeyolo/actions/runs/38975155518); layout `12079186556` |

The reduced layout's original ZIP was 368559598 bytes, SHA-256
`53ce993673eb4e118e256601d5a5f6db1c690c48e7a52774213636f09daf349a`.
The original G1 artifacts expire on 10 January 2027; G2 artifacts expire on
14 January 2027. Retained registry content and original acceptance remain
separate from those Actions retention dates. G1's reported archive sizes were
229,345,953 bytes (Darwin ARM64), 233,300,853 bytes (Linux AMD64) and
223,000,369 bytes (Linux ARM64). These sizes do not prove a transfer over 2 GiB,
filesystem sparsity or installed guest boot. Keep supported releases out of
registry cleanup jobs. Public anonymous retrieval and #239's installed-update
proof retain their original scope. GHCR package visibility remains an owner
setting; consumers use no personal registry token.

The digest-only `transport-fixture` activity accepts explicit retained layout
run, artifact ID and seed index inputs. It creates the existing nonbootable
`guest-2026-10-16.239` fixture: the seed kernel/initramfs, a 2049 MiB random disk
and small Linux placeholders. Never boot it. It writes only by digest and checks
that all existing tags remain unchanged. It cannot move a compatibility channel.
Each execution creates new random bytes; use that execution's `fixture.json`.
For this exceptional transfer test, set `SEED_RUN`, `SEED_ARTIFACT` and
`SEED_INDEX` to the verified retained layout identities, then dispatch:

```sh
gh workflow run guest-oci.yml --repo craigbalding/safeyolo --ref master \
  -f activity=transport-fixture -f transport_run="$SEED_RUN" \
  -f transport_artifact="$SEED_ARTIFACT" -f transport_index="$SEED_INDEX"
```

The result keeps the fixture identity and partial publication readbacks after a
failure. Digest-only transport does not establish a bootable guest or anonymous
native transfer. The direct `publish_guest_by_digest.sh` path also writes only
by digest; it has no channel-write operation.

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
