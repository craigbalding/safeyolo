#!/bin/bash
# One persistent host pane per agent in the selected session.
set -eu
SAFEYOLO_TMUX_LAYOUT=pane
export SAFEYOLO_TMUX_LAYOUT
source "$(dirname "$0")/tmux-common.sh"
