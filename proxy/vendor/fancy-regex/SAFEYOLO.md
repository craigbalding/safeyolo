# SafeYolo patch to fancy-regex 0.19.2

This directory contains the runtime source, required documentation includes, MIT license and regression tests for a pinned local patch. `UPSTREAM.json` records the crate checksum, upstream commit and file hashes. `PATCH.diff` shows the substantive upstream changes without context lines. A separately recorded two-space cleanup keeps the patch artifact free of trailing whitespace. `Cargo.toml.orig` and upstream notices are retained.

SafeYolo's Python scanner accepts `(a|aa)*\1$` and matches a complete 1,000,100-byte message. The original Rust engine stops at one million saved branches and returns an error. That error drops even a log-mode message. The patch removes this artificial cutoff when SafeYolo selects `stack_limit(None)`.

## Behavior

- `RegexBuilder::stack_limit` and `RegexOptionsBuilder::stack_limit` accept `Option<usize>`. The upstream default remains `Some(1_000_000)`. An explicit `None` permits VM buffers to grow as needed. It does not eagerly reserve maximum capacity or change the separate backtracking effort limit.
- Branches, capture saves, explicit stack storage, atomic-group scratch, delegated capture slots and returned capture vectors use fallible capacity growth. Failure returns `RuntimeError::AllocationFailed` without subject, pattern or allocator diagnostics.
- With `None`, a scoped guard releases per-search VM buffers on success and error. Compiled rules and bounded-mode scratch reuse keep their existing lifetimes. Concurrent searches use separate pooled scratch states.
- The allocation and cancellation changes preserve matching behavior. The separately gated ASCII-backreference extension below changes case folding only for annotated backreferences. Separate Python compatibility gaps still block production activation.

The fallible-allocation guarantee covers the patched VM buffers. Parsing, compilation, pool bookkeeping and allocations inside the delegated regex engine remain outside this patch. This is not a process-wide guarantee of recovery from arbitrary allocator exhaustion.

## Validation

From the repository root, use the Rust toolchain and cached dependencies. These commands test the patch without starting a proxy or accessing credentials:

```sh
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 cargo test --offline --manifest-path proxy/vendor/fancy-regex/Cargo.toml --lib
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 cargo test --offline --manifest-path proxy/vendor/fancy-regex/Cargo.toml --test runtime_allocation -- --test-threads=1 --nocapture
```

The first command runs 307 inherited unit tests, including VM state property tests. The second runs five patch regressions. Those regressions exercise 43 injected allocation failures, recovery, buffer release after success, failure and cancellation, the preserved default cutoff, complete-message matching and concurrent cloned rules. Fault injection affects only the current test thread and never exhausts actual memory.

The main `proxy/tests/inspection.rs` suite also compares actual Python and native log-mode matches at 1,000,100, 4,194,304 and 8,388,608 bytes. Its normally ignored Python oracles require the checkout's Python environment. Passing the stack regression does not establish parity for the remaining grammar and Unicode cases.

## Resource tradeoff

An isolated unoptimized ARM64 probe ran 1,000 small scans, three 4 MiB scans, then 1,000 more small scans. Releasing VM buffers left about 8,568 KiB resident after the large scans. Retaining the same buffers left about 336,160 KiB resident. Both runs peaked near 328 MiB. The release mode took 93.8 ms versus 85.1 ms for the first small batch, and 1,158.6 ms versus 1,050.4 ms for the large batch. This single run records allocation cost and memory retention; it is not a production performance acceptance result.

The complete experiment is recorded under `/home/agent/safeyolo-rust-620-evidence/inspection-stack-patch`. The preceding PCRE2 comparison remains separate under `/home/agent/safeyolo-rust-620-evidence/regex-engine-probe`.

## Per-call cancellation

`RegexInput::with_cancel_flag(&AtomicBool)` borrows a flag for one search. Compiled `Regex` values, clones and pooled VM state do not store the flag. Once a caller cancels a request, the caller keeps its flag true. A later request uses its own flag. Calls without a flag preserve their existing behavior.

VM instruction and backtracking loops poll the flag. Capture saves/restoration, atomic cuts, case-insensitive literal loops and long byte/backreference comparisons also poll. Byte comparisons poll between 4 KiB chunks; that chunk size is not a subject limit. An observed cancellation returns `RuntimeError::Cancelled` without a match, subject or pattern. The existing scoped guard releases unbounded VM buffers on this error too.

The extension covers `Regex` direct and iterator input APIs. `RegexSet` has a separate candidate-search loop that this patch does not change. The SafeYolo scanner uses `Regex` directly.

Opaque delegated searches only permit checks before and after each call. Their API does not expose a cancellation callback. The lower-level `search_with` methods supply a cache rather than incremental execution. Changing to `earliest(true)` can change match priority, so this patch preserves existing search semantics. The native engine can compose several algorithms and fall back during one search; replacing it with a manually stepped DFA would require a separate compatibility implementation. These conclusions follow from the pinned [regex-automata 0.4.18 API](https://docs.rs/regex-automata/0.4.18/regex_automata/meta/struct.Regex.html) and its locally cached dependency source.

The cancellation regression runs the accepted `a{8192}` rule on 8,192 `a` bytes. It cancels after the delegated input is accessed. The call remains busy for a 20 ms observation window, then returns `Cancelled` after about 2.69 seconds in the recorded unoptimized run. This is a remaining cancellation-latency gap. Allocator calls, bulk initialization/copies and library UTF-8 validation also cannot be interrupted midway. This patch imposes no new deadline, work limit or message cap.

From the repository root, run the additional tests with the cached Rust toolchain:

```sh
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 cargo test --offline --manifest-path proxy/vendor/fancy-regex/Cargo.toml --test runtime_cancellation -- --include-ignored --test-threads=1 --nocapture
```

All six tests pass in the recorded run. A synthetic input hook proves that the cancellation test has entered VM execution before another thread cancels it. Other cases cover clones, fresh requests, captures, atomic groups, lookbehind, unchanged match offsets and delayed delegated results. The main scanner's cancellable WS API returns a distinct `Cancelled` error. It checks cancellation before counter changes and returns no finding or inspection-error decision for an observed cancellation. A completed counter update is not rolled back if cancellation arrives later. The transport must check its flag again before publishing results because cancellation can race with the API return.

Evidence and runnable commands are recorded under `/home/agent/safeyolo-rust-620-evidence/inspection-cancellation`. There are 19 main scanner tests including five Python oracles, 315 inherited all-feature unit tests, six cancellation regressions and five allocation regressions. Focused library/new-test Clippy and main all-target Clippy pass. Broad vendored all-target Clippy reports 47 existing lints in unchanged upstream tests; this patch retains that source and records the failed command.

## Scoped ASCII backreferences

The SafeYolo frontend lowers Python ASCII scopes and octal escapes before it compiles a rule. ASCII mode changes character categories and case folding. It preserves Unicode scalar input, so a dot still consumes one complete non-ASCII character. Ordinary literals and classes use the existing engine syntax.

Case-insensitive backreferences need one additional bit on each parsed reference. The crate exposes parsing and mutable expression traversal, but its builders accept pattern strings. It has no public builder that accepts an annotated expression tree. `allow_ascii_backref_flag(true)` therefore enables an internal `(?A:...)` scope. The option defaults to false. The SafeYolo frontend rejects authored Python-invalid A flags before it enables the option. The internal scope changes backreferences only; it does not implement a Python ASCII scope by itself.

The parser copies that bit through `AstNode::Backref` and `Expr::Backref`. The compiler selects the existing ASCII comparison instruction for an annotated reference. The virtual machine matching loop is unchanged. Unannotated references keep their existing behavior. Mechanical constructor changes set the new bit to false in inherited tests. `RegexSet` and public expression constructors acquire the same new field through the shared expression type; SafeYolo does not use a separate regex engine or fallback matcher.

From the repository root, run the additional tests with the cached Rust toolchain. The Python command also needs the checkout's existing Python environment, including its test dependencies:

```sh
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 cargo test --offline --manifest-path proxy/vendor/fancy-regex/Cargo.toml --test ascii_backrefs
SAFEYOLO_POLICY_PYTHON="$PWD/.venv/bin/python" CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 cargo test --offline --manifest-path proxy/Cargo.toml --test inspection -- --include-ignored
```

The external candidate passes three new vendor tests and 23 scanner tests, including six Python oracles. It also passes all 315 inherited all-feature unit tests and the existing five allocation and six cancellation regressions. The finite Python 3.12.14 matrix compares 895 patterns against 87 subjects. Of the 895 compile cases, 827 patterns are accepted by both engines. Their 71,949 match comparisons include nested flags, octal escapes inside and outside classes, numeric and named backreferences, reference ambiguity, case folding, invalid inputs and literal text resembling the internal flag. Focused vendor Clippy and external scanner all-target Clippy pass.

The matrix separates 36 D41 source-defect rows from compatibility results. Python's scoped-ASCII search prefilter can apply a Unicode negative category before its actual ASCII matching instruction. For example, `re.search(r"(?a:\W)", "é")` returns no match, but Python fullmatch and anchored search match the same character. An operator's block rule for characters outside the ASCII word set therefore misses that body in the old scanner. The native scanner enforces that configured rule. The regression records the original search, fullmatch, anchored search and `re.DEBUG` evidence; it does not add a new rule or reproduce the faulty prefilter.

Forty-two matrix rows still differ on Turkish-I case folding. One accepted named-Unicode escape remains unsupported. Other recorded Unicode-version, Unicode-backreference and parsing-depth gaps remain outside this finite repair. Opaque delegated-search cancellation is also unchanged. The external evidence and source review archive are under `/home/agent/safeyolo-rust-620-evidence/regex-ascii-octal`. These results do not establish complete Python regex parity or authorize scanner activation.
