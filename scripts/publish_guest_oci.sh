#!/usr/bin/env bash
# Prepare or reuse an OCI guest release; publish only to an explicit destination.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
if [[ ${1:-} == --promote || ${1:-} == --record-stage || ${1:-} == --record-smoke || ${1:-} == --inspect ]]; then
    operation=${1#--}; shift
    exec "${SAFEYOLO_BUILD_PYTHON:-python3}" "$script_dir/guest_release.py" "$operation" "$@"
fi
usage() {
    echo 'Usage: publish_guest_oci.sh (--artifacts DIR | --from-layout) --layout DIR --version TAG --compatibility C --revision SHA --verifier EXECUTABLE [--publish REPOSITORY] [--plain-http]' >&2
    exit 64
}
artifacts= layout= version= compatibility= revision= verifier= repository=
plain_http=0 from_layout=0
created_at=
while [[ $# -gt 0 ]]; do
    case "$1" in
        --plain-http) plain_http=1; shift ;;
        --from-layout) from_layout=1; shift ;;
        --artifacts|--layout|--version|--compatibility|--revision|--verifier|--publish|--created-at)
            [[ $# -ge 2 && -n "$2" ]] || usage
            case "$1" in
                --artifacts) artifacts=$2 ;; --layout) layout=$2 ;;
                --version) version=$2 ;; --compatibility) compatibility=$2 ;;
                --revision) revision=$2 ;; --verifier) verifier=$2 ;;
                --publish) repository=$2 ;; --created-at) created_at=$2 ;;
            esac
            shift 2 ;;
        *) usage ;;
    esac
done
[[ -n "$layout" && -n "$version" && -n "$compatibility" && -n "$revision" && -x "$verifier" ]] || usage
if (( from_layout )); then
    [[ -z "$artifacts" && -d "$layout" ]] || usage
else
    [[ -n "$artifacts" ]] || usage
    artifacts=$(cd -- "$artifacts" && pwd)
    mkdir -p -- "$layout"
fi
oras=${ORAS:-oras}
verifier=$(realpath -- "$verifier")
layout=$(cd -- "$layout" && pwd)
scratch=$(mktemp -d "$layout/.publish.XXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
if (( ! from_layout )); then
    # Persist real assembly time locally so identical publication retries retain
    # bytes. A new build uses a fresh layout and a new immutable version.
    if [[ -z $created_at ]]; then
        if [[ -f $layout/assembled-at.txt ]]; then created_at=$(cat "$layout/assembled-at.txt")
        else created_at=$("${SAFEYOLO_BUILD_PYTHON:-python3}" -c 'from datetime import UTC, datetime; print(datetime.now(UTC).isoformat())'); fi
    fi
    printf '%s\n' "$created_at" > "$layout/assembled-at.txt"
    artifact_type=application/vnd.safeyolo.guest.v1
    annotations=(
        --annotation "org.opencontainers.image.version=$version"
        --annotation 'org.opencontainers.image.source=https://github.com/craigbalding/safeyolo'
        --annotation "org.opencontainers.image.revision=$revision"
        --annotation "dev.safeyolo.guest.compatibility=$compatibility"
        # Assembly time is distinct from verified staging completion.
        --annotation "org.opencontainers.image.created=$created_at"
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
        child=$("$oras" resolve --oci-layout "$layout:$version-$platform")
        children+=("$child")
        jq --arg digest "$child" '{digest: $digest, platform: .}' \
            "$scratch/platform.json" >> "$scratch/platforms.json"
    done
    "$oras" manifest index create --oci-layout --artifact-type "$artifact_type" \
        "${annotations[@]}" --output "$scratch/index.json" "$layout:$version" "${children[@]}"
    # Supply descriptor platforms explicitly for our custom config media type.
    # Bind each descriptor to the platform used for its unchanged child config.
    jq --slurpfile platforms "$scratch/platforms.json" '
        .manifests |= map(. as $child |
            .platform = ($platforms[] | select(.digest == $child.digest) | .platform))
    ' "$scratch/index.json" > "$scratch/platform-index.json"
    "$oras" manifest push --oci-layout "$layout:$version" "$scratch/platform-index.json" >/dev/null
fi
index_digest=$("$oras" resolve --oci-layout "$layout:$version")
index_file="$layout/blobs/sha256/${index_digest#sha256:}"
# A retained layout must match the requested release, without recreating bytes.
jq -e --arg version "$version" --arg revision "$revision" \
    '.annotations["org.opencontainers.image.version"] == $version and
     .annotations["org.opencontainers.image.revision"] == $revision' "$index_file" >/dev/null || {
    echo 'Guest layout does not match the requested version and revision.' >&2; exit 1;
}
"$verifier" "$layout" "$index_digest" "$compatibility"
jq -r '.manifests[].digest' "$index_file" > "$scratch/children"
children=()
while IFS= read -r child; do
    children+=("$child")
done < "$scratch/children"
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
# Completion is recorded only after the complete index and all archives pass
# registry readback. The following job binds this time to this successful job.
staged_at=$("${SAFEYOLO_BUILD_PYTHON:-python3}" -c 'from datetime import UTC, datetime; print(datetime.now(UTC).isoformat())')
printf '%s\n' "$staged_at" > "$layout/verified-staged-at.txt"
echo "Staged $repository:$version at $index_digest ($staged_at). Compatibility selection is unchanged."
# Retain all prior versions, generations and rollback content. No deletes.
