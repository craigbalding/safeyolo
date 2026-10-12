#!/usr/bin/env bash
# Prepare an OCI guest release; upload/promote only with an explicit destination.
set -euo pipefail
usage() {
    echo 'Usage: publish_guest_oci.sh --artifacts DIR --layout DIR --version TAG --compatibility C --revision SHA --verifier EXECUTABLE [--publish REPOSITORY] [--plain-http]' >&2
    exit 64
}
artifacts= layout= version= compatibility= revision= verifier= repository=
plain_http=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --plain-http) plain_http=1; shift ;;
        --artifacts|--layout|--version|--compatibility|--revision|--verifier|--publish)
            [[ $# -ge 2 && -n "$2" ]] || usage
            case "$1" in
                --artifacts) artifacts=$2 ;; --layout) layout=$2 ;;
                --version) version=$2 ;; --compatibility) compatibility=$2 ;;
                --revision) revision=$2 ;; --verifier) verifier=$2 ;;
                --publish) repository=$2 ;;
            esac
            shift 2 ;;
        *) usage ;;
    esac
done
[[ -n "$artifacts" && -n "$layout" && -n "$version" && -n "$compatibility" && -n "$revision" && -x "$verifier" ]] || usage
oras=${ORAS:-oras}
[[ $("$oras" version | sed -n 's/^Version: *//p') == 1.3.4 ]] || { echo 'ORAS 1.3.4 is required.' >&2; exit 1; }
artifacts=$(cd -- "$artifacts" && pwd)
verifier=$(realpath -- "$verifier")
mkdir -p -- "$layout"
layout=$(cd -- "$layout" && pwd)
scratch=$(mktemp -d "$layout/.publish.XXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
artifact_type=application/vnd.safeyolo.guest.v1
annotations=(
    --annotation "org.opencontainers.image.version=$version"
    --annotation 'org.opencontainers.image.source=https://github.com/craigbalding/safeyolo'
    --annotation "org.opencontainers.image.revision=$revision"
    --annotation "dev.safeyolo.guest.compatibility=$compatibility"
    # ORAS otherwise adds the current time, making identical retries conflict.
    --annotation "org.opencontainers.image.created=${version:6:10}T00:00:00Z"
)
children=()
for platform in darwin-arm64 linux-amd64 linux-arm64; do
    directory="$artifacts/$platform"
    [[ -s "$directory/guest.tar.zst" && -s "$directory/build-base.txt" ]] || {
        echo "Missing archive or pinned build provenance: $directory" >&2; exit 1;
    }
    build_base=$(cat "$directory/build-base.txt")
    printf '{"os":"%s","architecture":"%s"}' "${platform%-*}" "${platform##*-}" > "$scratch/platform.json"
    (
        cd -- "$directory"
        "$oras" push --oci-layout --image-spec v1.1 --artifact-type "$artifact_type" \
            --config "$scratch/platform.json:application/vnd.safeyolo.guest.platform.v1+json" \
            "${annotations[@]}" --annotation "dev.safeyolo.guest.build-base=$build_base" \
            "$layout:$version-$platform" 'guest.tar.zst:application/vnd.safeyolo.guest.v1.tar+zstd' >/dev/null
    )
    children+=("$("$oras" resolve --oci-layout "$layout:$version-$platform")")
done
"$oras" manifest index create --oci-layout --artifact-type "$artifact_type" \
    "${annotations[@]}" "$layout:$version" "${children[@]}" >/dev/null
index_digest=$("$oras" resolve --oci-layout "$layout:$version")
"$verifier" "$layout" "$index_digest" "$compatibility"
echo "Prepared $version at $index_digest"
[[ -n "$repository" ]] || exit 0

# Direct callers must serialize this section. The repository workflow uses one
# concurrency group for all guest publication and never cancels a promotion.
remote_options=() from_options=() to_options=()
if (( plain_http )); then
    remote_options+=(--plain-http); from_options+=(--from-plain-http); to_options+=(--to-plain-http)
fi
# Upload by digest first. No guest-version or compatibility tag changes yet.
# --force traverses all blobs even when a partially uploaded manifest exists.
for child in "${children[@]}"; do
    "$oras" cp --force --from-oci-layout "${to_options[@]}" "$layout@$child" "$repository" >/dev/null
done
# Listing errors, including auth/network failures, are fatal. Uploading the
# untagged children first also creates a previously absent repository.
"$oras" repo tags "${remote_options[@]}" --format json "$repository" > "$scratch/tags.json"
if jq -e --arg version "$version" '(.tags // []) | index($version) != null' "$scratch/tags.json" >/dev/null; then
    existing=$("$oras" resolve "${remote_options[@]}" "$repository:$version")
    [[ "$existing" == "$index_digest" ]] || { echo "Immutable guest version conflict: $repository:$version" >&2; exit 1; }
fi

# Fetch every uploaded child/config/blob into fresh local storage. The native
# contract verifier challenges every descriptor and all consumer platforms.
roundtrip="$scratch/roundtrip"
for child in "${children[@]}"; do
    "$oras" cp --to-oci-layout "${from_options[@]}" "$repository@$child" "$roundtrip" >/dev/null
done
index_file="$layout/blobs/sha256/${index_digest#sha256:}"
cp -- "$index_file" "$roundtrip/blobs/sha256/${index_digest#sha256:}"
"$verifier" "$roundtrip" "$index_digest" "$compatibility"

# Only now publish the full index. Verify the returned raw index with the
# already fetched children, then attach the immutable version and moving tag.
"$oras" manifest push "${remote_options[@]}" "$repository@$index_digest" "$index_file" >/dev/null
"$oras" manifest fetch "${remote_options[@]}" "$repository@$index_digest" \
    --output "$scratch/fetched-index.json"
cmp -- "$index_file" "$scratch/fetched-index.json"
# ORAS layout blobs are read-only. Replace this owned temporary index file
# after readback comparison instead of asking ORAS to overwrite a blob.
rm -- "$roundtrip/blobs/sha256/${index_digest#sha256:}"
cp -- "$scratch/fetched-index.json" "$roundtrip/blobs/sha256/${index_digest#sha256:}"
"$verifier" "$roundtrip" "$index_digest" "$compatibility"
"$oras" tag "${remote_options[@]}" "$repository@$index_digest" "$version" >/dev/null
[[ $("$oras" resolve "${remote_options[@]}" "$repository:$version") == "$index_digest" ]]
"$oras" tag "${remote_options[@]}" "$repository@$index_digest" "compat-$compatibility" >/dev/null
[[ $("$oras" resolve "${remote_options[@]}" "$repository:compat-$compatibility") == "$index_digest" ]]
echo "Published $repository:$version; compat-$compatibility -> $index_digest"
# Retain all prior versions, generations and rollback content. No deletes.
