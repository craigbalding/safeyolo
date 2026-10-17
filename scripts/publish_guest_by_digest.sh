#!/usr/bin/env bash
# Publish a verified guest layout by digest. Never tag or download its archives.
set -euo pipefail
if [[ $# != 5 && ! ( $# == 6 && "$6" == --plain-http ) ]]; then
    echo 'Usage: publish_guest_by_digest.sh LAYOUT INDEX_DIGEST VERIFIER REPOSITORY OUTPUT_DIRECTORY [--plain-http]' >&2
    exit 64
fi
layout=$1 index=$2 verifier=$3 repository=$4 output=$5
oras=${ORAS:-oras}
"$verifier" "$layout" "$index" v1
mkdir -- "$output"
remote_options=() to_options=()
if [[ $# == 6 ]]; then
    remote_options+=(--plain-http); to_options+=(--to-plain-http)
fi
"$oras" repo tags "${remote_options[@]}" --format json "$repository" > "$output/tags.json"
jq -r '.tags[]' "$output/tags.json" > "$output/tag-names.txt"
preserved_tags=()
while IFS= read -r tag; do preserved_tags+=("$tag"); done < "$output/tag-names.txt"
for tag in "${preserved_tags[@]}"; do
    "$oras" resolve "${remote_options[@]}" "$repository:$tag" > "$output/before-$tag"
done
# An untagged destination copies the index's full graph through digest writes.
"$oras" cp --force --from-oci-layout "${to_options[@]}" "$layout@$index" "$repository"
"$oras" manifest fetch "${remote_options[@]}" "$repository@$index" --output "$output/public-index.json"
cmp -- "$layout/blobs/sha256/${index#sha256:}" "$output/public-index.json"
jq -r '.manifests[].digest' "$output/public-index.json" > "$output/children.txt"
while IFS= read -r child; do
    "$oras" manifest fetch "${remote_options[@]}" "$repository@$child" --output "$output/${child#sha256:}.json"
    cmp -- "$layout/blobs/sha256/${child#sha256:}" "$output/${child#sha256:}.json"
    config=$(jq -r '.config.digest' "$output/${child#sha256:}.json")
    "$oras" blob fetch "${remote_options[@]}" "$repository@$config" --output "$output/${config#sha256:}.json"
    cmp -- "$layout/blobs/sha256/${config#sha256:}" "$output/${config#sha256:}.json"
done < "$output/children.txt"
for tag in "${preserved_tags[@]}"; do
    "$oras" resolve "${remote_options[@]}" "$repository:$tag" > "$output/after-$tag"
    cmp -- "$output/before-$tag" "$output/after-$tag"
done
echo "Published guest layout $repository@$index; production tags are unchanged."
