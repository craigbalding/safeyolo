#!/bin/bash
# Run the existing installed P3 and P4 selections against one post-deletion commit.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd -P)"
B1_HEAD=d680ef82e4cdd9f1b725a421bccf8496123fd55a
INSTALL_COMMIT="${1:-}"

if [ "$#" -ne 1 ] || [[ ! "$INSTALL_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
    echo "Usage: $0 FULL_POST_DELETION_COMMIT_SHA" >&2
    exit 2
fi
if [ "$(uname -s)" != Linux ]; then
    echo "ERROR: B2 Linux pilot requires a supported Linux systrap host" >&2
    exit 2
fi
if ! git -C "$REPO_ROOT" cat-file -e "$INSTALL_COMMIT^{commit}" 2>/dev/null; then
    git -C "$REPO_ROOT" fetch origin "$INSTALL_COMMIT"
fi
if ! git -C "$REPO_ROOT" merge-base --is-ancestor "$B1_HEAD" "$INSTALL_COMMIT"; then
    echo "ERROR: selected commit $INSTALL_COMMIT does not contain the reviewed post-deletion B1 head" >&2
    exit 2
fi
if [ -n "$(git -C "$REPO_ROOT" status --porcelain=v1 --untracked-files=all)" ]; then
    echo "ERROR: B2 pilot harness checkout must be clean" >&2
    exit 2
fi

PILOT_DIR="$(mktemp -d "$HOME/safeyolo-b2-linux.XXXXXX")"
SOURCE_DIR="$PILOT_DIR/source-selected"
git -C "$REPO_ROOT" worktree add --detach "$SOURCE_DIR" "$INSTALL_COMMIT"
if [ "$(git -C "$SOURCE_DIR" rev-parse HEAD)" != "$INSTALL_COMMIT" ]; then
    echo "ERROR: detached B2 source does not match $INSTALL_COMMIT" >&2
    exit 2
fi

echo "B2 Linux pilot: installed source commit $INSTALL_COMMIT"
echo "B2 Linux pilot: selected source $SOURCE_DIR"
"$REPO_ROOT/tests/blackbox/run-p3.sh" systrap --install-commit "$INSTALL_COMMIT" --install-checkout "$SOURCE_DIR"
"$REPO_ROOT/tests/blackbox/run-p4.sh" systrap --install-commit "$INSTALL_COMMIT" --install-checkout "$SOURCE_DIR"
echo "B2 Linux pilot: P3 and P4 installed selections passed for $INSTALL_COMMIT"
