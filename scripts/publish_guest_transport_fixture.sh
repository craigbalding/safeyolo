#!/usr/bin/env bash
# Publish a verified fixture by digest. Never tag or download its large archive.
set -euo pipefail
if [[ $# != 5 && ! ( $# == 6 && "$6" == --plain-http ) ]]; then
    echo 'Usage: publish_guest_transport_fixture.sh LAYOUT INDEX_DIGEST VERIFIER REPOSITORY OUTPUT_DIRECTORY [--plain-http]' >&2
    exit 64
fi
layout=$1 index=$2 verifier=$3 repository=$4 output=$5
oras=${ORAS:-oras}
[[ $("$oras" version | sed -n 's/^Version: *//p') == 1.3.4 ]]
"$verifier" "$layout" "$index" v1
mkdir -- "$output"
remote_options=() to_options=()
if [[ $# == 6 ]]; then
    remote_options+=(--plain-http); to_options+=(--to-plain-http)
fi
for tag in compat-v1 guest-2026-10-12.1 guest-2026-10-16.1; do
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
for tag in compat-v1 guest-2026-10-12.1 guest-2026-10-16.1; do
    "$oras" resolve "${remote_options[@]}" "$repository:$tag" > "$output/after-$tag"
    cmp -- "$output/before-$tag" "$output/after-$tag"
done
echo "Published transport fixture $repository@$index; production tags are unchanged."
echo 'The anonymous packaged native transfer remains pending. Never boot this fixture.'
