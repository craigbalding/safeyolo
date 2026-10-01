# SafeYolo patch to fancy-regex 0.19.2

This directory contains the runtime source, required documentation includes, MIT license and regression tests for a pinned local patch. `UPSTREAM.json` records the crate checksum, upstream commit and file hashes. `PATCH.diff` shows the substantive upstream changes without context lines. A separately recorded two-space cleanup keeps the patch artifact free of trailing whitespace. `Cargo.toml.orig` and upstream notices are retained.

SafeYolo's Python scanner accepts `(a|aa)*\1$` and matches a complete 1,000,100-byte message. The original Rust engine stops at one million saved branches and returns an error. That error drops even a log-mode message. The patch removes this artificial cutoff when SafeYolo selects `stack_limit(None)`.

## Behavior

- `RegexBuilder::stack_limit` and `RegexOptionsBuilder::stack_limit` accept `Option<usize>`. The upstream default remains `Some(1_000_000)`. An explicit `None` permits VM buffers to grow as needed. It does not eagerly reserve maximum capacity or change the separate backtracking effort limit.
- Branches, capture saves, explicit stack storage, atomic-group scratch, delegated capture slots and returned capture vectors use fallible capacity growth. Failure returns `RuntimeError::AllocationFailed` without subject, pattern or allocator diagnostics.
- With `None`, a scoped guard releases per-search VM buffers on success and error. Compiled rules and bounded-mode scratch reuse keep their existing lifetimes. Concurrent searches use separate pooled scratch states.
- The allocation and cancellation changes preserve matching behavior. The separately gated ASCII and Python backreference options below affect only opted-in references. Separate Python compatibility gaps still block production activation.

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

The parser copies that bit through `AstNode::Backref` and `Expr::Backref`. At the scoped-ASCII checkpoint, the compiler selected the existing ASCII comparison instruction for an annotated reference without changing the matching loop. The later opt-in Python comparison below repairs mixed scalar references. With that option disabled, references keep the checkpoint behavior. Mechanical constructor changes set the new bit to false in inherited tests. `RegexSet` and public expression constructors acquire the same new field through the shared expression type; SafeYolo does not use a separate regex engine or fallback matcher.

From the repository root, run the additional tests with the cached Rust toolchain. The Python command also needs the checkout's existing Python environment, including its test dependencies:

```sh
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 cargo test --offline --manifest-path proxy/vendor/fancy-regex/Cargo.toml --test ascii_backrefs
SAFEYOLO_POLICY_PYTHON="$PWD/.venv/bin/python" CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 cargo test --offline --manifest-path proxy/Cargo.toml --test inspection -- --include-ignored
```

The external candidate passes three new vendor tests and 23 scanner tests, including six Python oracles. It also passes all 315 inherited all-feature unit tests and the existing five allocation and six cancellation regressions. The finite Python 3.12.14 matrix compares 895 patterns against 87 subjects. Of the 895 compile cases, 827 patterns are accepted by both engines. Their 71,949 match comparisons include nested flags, octal escapes inside and outside classes, numeric and named backreferences, reference ambiguity, case folding, invalid inputs and literal text resembling the internal flag. Focused vendor Clippy and external scanner all-target Clippy pass.

The matrix separates 36 D41 source-defect rows from compatibility results. Python's scoped-ASCII search prefilter can apply a Unicode negative category before its actual ASCII matching instruction. For example, `re.search(r"(?a:\W)", "é")` returns no match, but Python fullmatch and anchored search match the same character. An operator's block rule for characters outside the ASCII word set therefore misses that body in the old scanner. The native scanner enforces that configured rule. The regression records the original search, fullmatch, anchored search and `re.DEBUG` evidence; it does not add a new rule or reproduce the faulty prefilter.

At the scoped-ASCII checkpoint, 42 matrix rows still differed on Turkish-I case folding. The following section records the subsequent correction. One accepted named-Unicode escape remains unsupported. Other recorded Unicode-version, Unicode-backreference and parsing-depth gaps remain outside this finite repair. Opaque delegated-search cancellation is also unchanged. The external evidence and source review archive are under `/home/agent/safeyolo-rust-620-evidence/regex-ascii-octal`. These checkpoint results do not establish complete Python regex parity or production acceptance.

## Python literal and backreference case behavior

Python case-insensitive literals match all four I forms: `I`, `i`, `İ` and `ı`. Python backreferences use a different relation. They compare the lowercase value of each captured scalar with the lowercase value of the corresponding subject scalar. As a result, a Unicode backreference groups `I`, `i` and `İ`, but keeps `ı` separate. It also keeps `σ` distinct from `ς`, `s` from `ſ`, and `µ` from `μ`. The actual source instructions and finite witnesses are recorded under `/home/agent/safeyolo-rust-620-evidence/regex-turkish-i`.

The SafeYolo frontend closes the four-I set in Unicode-insensitive literals and positive classes before applying class negation. ASCII scopes and disabled case-insensitive scopes retain their existing meaning. `RegexOptionsBuilder::python_backreferences(true)` and the corresponding `RegexBuilder` method select a separate `PythonBackref` instruction. The option defaults to false. It does not change literal folding, case-sensitive backreferences or ASCII byte mode. SafeYolo enables it through its existing pattern compiler.

The new instruction compares one scalar at a time and returns the subject's consumed byte offset. It therefore handles width-changing matches such as `iİ`, `Kk` and `ßẞ`. In ASCII scopes it folds ASCII letters while keeping other scalars exact, including mixed references such as `äaäA`. The instruction polls the existing per-call cancellation flag and allocates no comparison buffer. The existing scratch-release guard and resource cutoffs are unchanged.

The source lowercase data has 1,433 nonidentity mappings, represented by 182 strided delta ranges. The generated fields occupy 2,912 bytes before code and object alignment. `PYTHON_LOWERCASE.json` records its source, generator and hashes. `tools/generate_python_lowercase.py` regenerates it with the specified CPython 3.12/Unicode 15 interpreter. `LICENSE-CPYTHON` retains the full source license. The upstream engine remains MIT-licensed; the vendored package license expression also identifies the Python data. Runtime matching does not invoke Python and does not depend on the Rust compiler's newer Unicode lowercase table.

The optional seek optimization is disabled by default. When it is enabled, a Python backreference uses the existing minimum-size placeholder in the derived filter. This admits the complete set of possible reference matches. Inlining a case-insensitive literal would incorrectly skip `iİ`. The original seek path remains unchanged when the option is false.

From the repository root, use the cached Rust toolchain and the checkout's Python environment to test the opt-in instruction:

```sh
SAFEYOLO_POLICY_PYTHON="$PWD/.venv/bin/python" CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 cargo test --offline --manifest-path proxy/vendor/fancy-regex/Cargo.toml --test python_backrefs -- --include-ignored
```

All seven new tests pass in the external candidate. They cover default behavior, positive and negative reference pairs, capture byte offsets, mixed ASCII references, enabled seek, cancellation during actual scalar comparison, and comparison-loop allocation counting. The Python oracle verifies the generated Rust lowercase function for all 1,112,064 valid Unicode scalar values. The allocation measurement ends at the last subject scalar; later pool bookkeeping remains outside that measurement.

The candidate also passes 26 scanner tests, including seven Python oracles, 315 inherited all-feature unit tests, three prior ASCII-reference tests, five allocation tests and six cancellation tests. The new scanner oracle compares 80 patterns with 2,362 subjects. A separate 206-pattern matrix agrees with Python on all 46,593 comparisons, including capture offsets. The prior ASCII/octal matrix still separates D41 source-prefilter corrections from parity; its 42 Turkish-I differences are repaired. Named-Unicode escapes, other recorded Unicode-version/character-class differences, parsing depth, opaque delegated-search cancellation and the HTTP text adapter remain unresolved. These tests establish this bounded correction, not complete Python regex parity or production acceptance.
