#!/usr/bin/env bash
# Publish a verified guest layout by digest and verify its complete readback.
set -euo pipefail
if [[ $# -lt 5 ]]; then
    echo 'Usage: publish_guest_by_digest.sh LAYOUT INDEX_DIGEST VERIFIER REPOSITORY OUTPUT_DIRECTORY [--plain-http] [--compatibility C]' >&2
    exit 64
fi
layout=$1 index=$2 verifier=$3 repository=$4 output=$5
shift 5
oras=${ORAS:-oras}
compatibility=v1
remote_options=() to_options=()
from_options=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --plain-http)
            remote_options+=(--plain-http); to_options+=(--to-plain-http)
            from_options+=(--from-plain-http); shift ;;
        --compatibility)
            [[ $# -ge 2 && -n $2 ]] || exit 64
            compatibility=$2; shift 2 ;;
        *) echo "Unknown digest publication argument: $1" >&2; exit 64 ;;
    esac
done
"$verifier" "$layout" "$index" "$compatibility"
mkdir -- "$output"
"$oras" repo tags "${remote_options[@]}" --format json "$repository" > "$output/tags.json"
jq -r '.tags[]' "$output/tags.json" > "$output/tag-names.txt"
preserved_tags=()
while IFS= read -r tag; do preserved_tags+=("$tag"); done < "$output/tag-names.txt"
for tag in "${preserved_tags[@]}"; do
    "$oras" resolve "${remote_options[@]}" "$repository:$tag" > "$output/before-$tag"
done
# An untagged destination copies the index's full graph through digest writes.
"$oras" cp --force --from-oci-layout "${to_options[@]}" "$layout@$index" "$repository"
# Read every archive back into fresh storage. Checking only manifests/configs
# cannot establish that the registry serves the selected archive bytes.
"$oras" cp --to-oci-layout "${from_options[@]}" "$repository@$index" "$output/readback"
"$verifier" "$output/readback" "$index" "$compatibility"
cp -- "$output/readback/blobs/sha256/${index#sha256:}" "$output/public-index.json"
cmp -- "$layout/blobs/sha256/${index#sha256:}" "$output/public-index.json"
for tag in "${preserved_tags[@]}"; do
    "$oras" resolve "${remote_options[@]}" "$repository:$tag" > "$output/after-$tag"
    cmp -- "$output/before-$tag" "$output/after-$tag"
done
echo "Published guest layout $repository@$index; production tags are unchanged."
