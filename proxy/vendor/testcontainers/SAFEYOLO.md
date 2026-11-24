# Maintained streaming archives for OCI development tests

Source: the MIT/Apache-2.0-licensed crates.io `testcontainers` 0.28.0 package,
upstream commit `59792c3d6631218fb0da174d7093c719f58f7071`.
The published archive SHA-256 is
`6e2bbe381afaaa58ea610c5fc3ffb2184063a32b3e358a179f0b4865dd59934a`.
The library, tests and upstream licenses are retained. Repository hooks
normalize trailing whitespace and final newlines in the copied files.

OCI's Docker development tests select this local consumer patch.
Its archive calls use maintained `async-tar` 0.6.2 with the Tokio runtime,
instead of unmaintained `astral-tokio-tar`. The replacement retains asynchronous
GNU archive construction, file and directory copies, modes, streaming
extraction and copy errors. A builder guard finalizes the in-memory archive
during errors and cancellation. Extraction checks the declared file length,
including PAX overrides, before reporting success. It includes the upstream PAX extension-header
repair published in GHSA-35rm-7j9c-2f7m. The copy controls exercise both source
boundaries without requiring a Docker daemon.

The optional properties reader needs only one integer-to-boolean conversion
from `serde_with`. A local Serde deserializer replaces that dependency and its
optional chrono lock entry. The property still accepts absent values, 0 and 1,
and refuses other values. Property precedence and Docker TLS behavior are
unchanged.

The import retains the complete library because OCI uses its container and
readiness APIs as well as the archive consumer. Reimplementing those APIs or
removing Docker tests would change the supported development workflow.
The edits are limited to the manifests, two archive consumers, the properties
reader and focused controls. SafeYolo's production OCI path does not select
this development dependency.
