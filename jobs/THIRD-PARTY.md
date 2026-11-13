# Hyperlight runtime inputs

The helper links Hyperlight and Hyperlight-Unikraft by The Hyperlight Authors
under Apache-2.0. Their
source releases and the complete Rust dependency versions are pinned in the
two Cargo lockfiles. The Unikraft integration embeds its released kernel;
the kernel uses Unikraft's BSD-3-Clause sources and the licenses of its selected
libraries. The Python image contains CPython and its runtime libraries.

Keep the upstream license and notice files with any distributed runtime bundle.
The builder retains available Rust-package license files and their license
declarations in `licenses/`. The Python
runtime filesystem retains the files supplied by its upstream image. The
upstream image recipe and kernel build sources are available in the pinned
[Hyperlight-Unikraft source](https://github.com/hyperlight-dev/hyperlight-unikraft/tree/34c0d647a9f8679c0ce53b76e174894b2c5bfa7a).
