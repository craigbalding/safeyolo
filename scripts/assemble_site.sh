#!/usr/bin/env bash
# Assemble the public site from two trees into one Jekyll source:
#   website/  operator-authored pages, layouts and assets
#   site/     Dispatch publication tree (validated by `safeyolo dispatch check-site`)
# A path present in both trees is an error, so neither tree can silently
# replace the other's files.
set -euo pipefail
dest=${1:?usage: scripts/assemble_site.sh DESTINATION}
mkdir -p "$dest" && dest=$(cd "$dest" && pwd)
root=$(cd "$(dirname "$0")/.." && pwd)
rm -rf "$dest"
mkdir -p "$dest"
cp -R "$root/website/." "$dest/"
cd "$root/site"
while IFS= read -r -d '' file; do
  rel=${file#./}
  if [ -e "$dest/$rel" ]; then
    echo "assemble_site: $rel exists in both website/ and site/" >&2
    exit 1
  fi
  mkdir -p "$dest/$(dirname "$rel")"
  cp "$file" "$dest/$rel"
done < <(find . -type f -print0)
