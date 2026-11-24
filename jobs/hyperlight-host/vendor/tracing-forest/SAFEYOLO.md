# Timestamped development traces without chrono

Source: the MIT-licensed crates.io `tracing-forest` 0.3.1 package,
upstream commit `8c08e8686b031425248490fda3c5c1f0b0bacfba`.
The published archive SHA-256 is
`f09cb459317a3811f76644334473239d696cd8efc606963ae7d1c308cead3b74`.
The library and tests are retained. The package declares the MIT license but
contains no license file; `LICENSE` supplies that text and author attribution.

The optional `time` feature replaces the former chrono feature.
Event and span timestamps use `time::OffsetDateTime` in UTC. Printed and
serialized timestamps use RFC 3339 with the `Z` UTC suffix. Tree structure,
context, durations, fields and the other features are unchanged.
Hyperlight selects this implementation for its development tracing example.
The span's `defer` local is guarded by the `defer` feature. This also lets
Hyperlight select `uuid` without `defer` and compile without unused-variable
errors.
