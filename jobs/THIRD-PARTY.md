# Hyperlight runtime inputs

The helper links Hyperlight and Hyperlight-Unikraft by The Hyperlight Authors
under Apache-2.0. Their
source releases and the complete Rust dependency versions are pinned in the
two Cargo lockfiles. The host uses a repository-local patch to Hyperlight
0.19.0 that removes only its informational build timestamp; its source,
license and patch explanation are retained in
[`hyperlight-host/vendor/hyperlight-host`](hyperlight-host/vendor/hyperlight-host/SAFEYOLO.md).
The Unikraft integration embeds its released kernel;
the kernel uses Unikraft's BSD-3-Clause sources and the licenses of its selected
libraries. The Python image contains CPython and its runtime libraries.
The bundle builder adds Debian 12's OpenSSL 3 shared libraries, pinned by
architecture, version and package digest in `scripts/build_hyperlight_jobs.py`.
Their copyright and Apache-2.0 license notice remain inside the guest at
`/usr/share/doc/libssl3/copyright`, with the full license at
`/usr/share/common-licenses/Apache-2.0`. The builder exposes the Python image's
bundled certifi public roots at OpenSSL's default CA file, `/usr/lib/ssl/cert.pem`.
The runtime manifest's `rootfs_source` identifies the base image; its rootfs
digest covers the completed image, including these additions.

Keep the upstream license and notice files with any distributed runtime bundle.
The builder retains available Rust-package license files and their license
declarations in `licenses/`. The Python
runtime filesystem retains the files supplied by its upstream image. The
upstream image recipe and kernel build sources are available in the pinned
[Hyperlight-Unikraft source](https://github.com/hyperlight-dev/hyperlight-unikraft/tree/34c0d647a9f8679c0ce53b76e174894b2c5bfa7a).
