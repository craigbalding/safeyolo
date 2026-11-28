# Hyperlight ELF assembly selection

Source: the crates.io ring 0.17.14 package. Its published archive SHA-256 is
`a4689e6c2294d81e88dc6261c768b63bc4fcdb852be6d1352498b114f61383b7`.
The package's ISC, MIT and OpenSSL license texts remain in `LICENSE`.

The sole build change selects ring's existing Linux/ELF assembly for the exact
`aarch64-hyperlight-none` and `x86_64-hyperlight-none` target names. Upstream's
OS list omits `none`; a full Core client link otherwise lacks required
assembly symbols, including P-256 operations. Cargo check alone misses this
failure. Other target selection and all cryptographic implementation code are
unchanged. Repository hooks may normalize trailing whitespace and final newlines.

Only the Core guest manifest selects this patch. Host proxy/helper builds use
their normal ring dependency. The guest uses a fresh host-backed entropy
callback through getrandom's custom interface; no deterministic fallback is
provided. TLS, hostname and chain validation still execute in the guest.
An ELF link is not runtime qualification of assembly or client behavior in a VM.
