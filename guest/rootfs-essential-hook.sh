#!/bin/bash
#
# mmdebstrap essential-hook — runs after essential packages are installed
# but BEFORE the --include packages. Drops a dpkg.cfg.d file that tells
# dpkg to skip docs, man pages, info files, and non-English locales for
# ALL subsequent installs — including build-essential and its ~100MB of
# compiler docs that would otherwise dominate the rootfs size.
#
# Copyright files are kept explicitly (Debian redistribution compliance)
# via the path-include rule.
#
# Invoked by guest/build-rootfs.sh via --essential-hook=<this-script>.
# mmdebstrap runs this directly (no sh -c wrap) because it's an executable
# file path, so the shebang is honored and we get full bash.
# $1 is the path to the rootfs under construction.
set -euo pipefail

ROOTFS="$1"
mkdir -p "$ROOTFS/etc/dpkg/dpkg.cfg.d"
cat > "$ROOTFS/etc/dpkg/dpkg.cfg.d/01-nodoc" <<'NODOC'
path-exclude /usr/share/doc/*
path-include /usr/share/doc/*/copyright
path-exclude /usr/share/man/*
path-exclude /usr/share/info/*
path-exclude /usr/share/locale/*
path-include /usr/share/locale/en*
path-include /usr/share/locale/locale.alias
NODOC
