# Browser wall-clock time without chrono

Source: the Apache-2.0-licensed crates.io `russh-util` 0.52.0 package,
upstream commit `3d09c20c52a542ffa327723d3a44cb1edd9b0ca4`.
The published archive SHA-256 is
`668424a5dde0bcb45b55ba7de8476b93831b4aa2fa6947e145f3b053e22c60b6`.
The archive records that commit with dirty source; the archive digest
identifies the imported bytes. The library and its Apache license are retained.

The wasm32 clock uses `web-time::SystemTime` instead of chrono.
Browser time still comes from `Date.now()`. Duration subtraction still refuses
a negative result. Other targets still re-export `std::time::Instant`.
The runtime utilities are unchanged. The clock controls also run on a native
host with fixed timestamps; a wasm32 compile checks the selected browser API.
