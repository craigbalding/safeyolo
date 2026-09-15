# SafeYolo patch to fancy-regex 0.19.2

This directory contains the runtime source, required documentation includes, MIT license and regression tests for a pinned local patch. `UPSTREAM.json` records the crate checksum, upstream commit and file hashes. `PATCH.diff` shows changes to the upstream manifest and three source files. `Cargo.toml.orig` and upstream notices are retained.

SafeYolo's Python scanner accepts `(a|aa)*\1$` and matches a complete 1,000,100-byte message. The original Rust engine stops at one million saved branches and returns an error. That error drops even a log-mode message. The patch removes this artificial cutoff when SafeYolo selects `stack_limit(None)`.

## Behavior

- `RegexBuilder::stack_limit` and `RegexOptionsBuilder::stack_limit` accept `Option<usize>`. The upstream default remains `Some(1_000_000)`. An explicit `None` permits VM buffers to grow as needed. It does not eagerly reserve maximum capacity or change the separate backtracking effort limit.
- Branches, capture saves, explicit stack storage, atomic-group scratch, delegated capture slots and returned capture vectors use fallible capacity growth. Failure returns `RuntimeError::AllocationFailed` without subject, pattern or allocator diagnostics.
- With `None`, a scoped guard releases per-search VM buffers on success and error. Compiled rules and bounded-mode scratch reuse keep their existing lifetimes. Concurrent searches use separate pooled scratch states.
- Python grammar, Unicode classes, case folding and parsing depth are unchanged. The native scanner remains inactive until its separate compatibility gaps are resolved.

The fallible-allocation guarantee covers the patched VM buffers. Parsing, compilation, pool bookkeeping and allocations inside the delegated regex engine remain outside this patch. This is not a process-wide guarantee of recovery from arbitrary allocator exhaustion.

## Validation

From the repository root, use the Rust toolchain and cached dependencies. These commands test the patch without starting a proxy or accessing credentials:

```sh
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 cargo test --offline --manifest-path proxy/vendor/fancy-regex/Cargo.toml --lib
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 cargo test --offline --manifest-path proxy/vendor/fancy-regex/Cargo.toml --test runtime_allocation -- --test-threads=1 --nocapture
```

The first command runs 307 inherited unit tests, including VM state property tests. The second runs four patch regressions. Those regressions exercise 43 injected allocation failures, recovery, buffer release after success and failure, the preserved default cutoff, complete-message matching and concurrent cloned rules. Fault injection affects only the current test thread and never exhausts actual memory.

The main `proxy/tests/inspection.rs` suite also compares actual Python and native log-mode matches at 1,000,100, 4,194,304 and 8,388,608 bytes. Its normally ignored Python oracles require the checkout's Python environment. Passing the stack regression does not establish parity for the remaining grammar and Unicode cases.

## Resource tradeoff

An isolated unoptimized ARM64 probe ran 1,000 small scans, three 4 MiB scans, then 1,000 more small scans. Releasing VM buffers left about 8,568 KiB resident after the large scans. Retaining the same buffers left about 336,160 KiB resident. Both runs peaked near 328 MiB. The release mode took 93.8 ms versus 85.1 ms for the first small batch, and 1,158.6 ms versus 1,050.4 ms for the large batch. This single run records allocation cost and memory retention; it is not a production performance acceptance result.

The complete experiment is recorded under `/home/agent/safeyolo-rust-620-evidence/inspection-stack-patch`. The preceding PCRE2 comparison remains separate under `/home/agent/safeyolo-rust-620-evidence/regex-engine-probe`.
