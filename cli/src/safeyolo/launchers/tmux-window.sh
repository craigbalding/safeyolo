#!/bin/bash
# One persistent host window per agent. No terminal in the guest is required.
set -eu
SAFEYOLO_TMUX_LAYOUT=window
export SAFEYOLO_TMUX_LAYOUT
source "$(dirname "$0")/tmux-common.sh"
