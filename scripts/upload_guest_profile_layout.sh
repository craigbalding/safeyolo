#!/usr/bin/env bash
# Transfer qualified OCI layout bytes to repository release assets for Actions.
set -euo pipefail
if [[ $# != 4 ]]; then
    echo 'Usage: upload_guest_profile_layout.sh LAYOUT SOURCE_REVISION RELEASE_TAG NEW_OUTPUT_DIRECTORY' >&2
    exit 64
fi
layout=$1 revision=$2 tag=$3 output=$4
repository=craigbalding/safeyolo
mkdir -- "$output"
# OCI archives are already compressed. Split the unchanged tar stream so each
# release asset stays below GitHub's 2 GiB per-file limit.
tar -C "$layout" -cf - oci-layout index.json blobs | split -b 1G -d -a 4 - "$output/layout.part-"
digest=$(cat "$output"/layout.part-* | sha256sum)
digest=${digest%% *}
gh release create "$tag" "$output"/layout.part-* --repo "$repository" --target "$revision" --prerelease --latest=false \
    --title "Custom guest layout inputs: $tag" --notes 'Qualified input transfer for the custom-profile Actions writer. Guest discovery remains in OCI.'
release_id=$(gh release view "$tag" --repo "$repository" --json databaseId --jq .databaseId)
gh api --paginate --slurp "repos/$repository/releases/$release_id/assets?per_page=100" \
    | jq '[.[][] | select(.name | startswith("layout.part-"))] | sort_by(.name) | map(.id | tostring)' \
    > "$output/layout-assets.json"
jq -n --arg digest "$digest" --arg source "$revision" --arg release "$release_id" \
    --slurpfile assets "$output/layout-assets.json" \
    '{layout_sha256: $digest, layout_assets: $assets[0], source_revision: $source, release_id: $release}' \
    > "$output/layout-upload.json"
echo "Layout transfer identities: $output/layout-upload.json"
