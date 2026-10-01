# Issue 634 resume handoff

This bounded follow-up starts from accepted candidate `2412b20248ab793754e0693252c708e2121e6487`.
The source repair commit is `5209afd3` (`fix(proxy): retain owned plumb audit diagnostics`).
The final commit containing this handoff file is the commit immediately after
`5209afd3`; resolve its exact SHA with `git rev-parse HEAD` in this worktree.

Worktree: `/home/agent/safeyolo-rust-620-evidence/lifecycle-634-resume-worktree`

Reusable target: `/home/agent/safeyolo-rust-620-evidence/634-resume-target`

Toolchain: `rustc 1.94.0 (4a4ef493e 2026-03-02)` and `cargo 1.94.0
(85eff7c80 2026-01-15)`, from
`/home/agent/.rustup/toolchains/1.94.0-aarch64-unknown-linux-gnu`.

All guarded Rust commands use:

```sh
SAFEYOLO_CARGO_RESERVE_GIB=20 \
  CARGO_TARGET_DIR=/home/agent/safeyolo-rust-620-evidence/634-resume-target \
  ./scripts/cargo_with_space.sh ...
```

Post-repair focused results:

| Command suffix | Result |
| --- | --- |
| `test --manifest-path proxy/Cargo.toml --offline --locked --lib agent_api` | 24 passed, 1 ignored |
| `test --manifest-path proxy/Cargo.toml --offline --locked --lib http::agent_audit_tests` | 5 passed |
| `test --manifest-path proxy/Cargo.toml --offline --locked --lib agent_api::plumb::tests` | 15 passed |
| `test --manifest-path proxy/Cargo.toml --offline --locked --lib admin_api::services::tests` | 10 passed |
| `test --manifest-path proxy/Cargo.toml --offline --locked --lib admin_api::tests::plumb_resolution_events_remove_retained_pending_approval` | 1 passed |
| `test --manifest-path proxy/Cargo.toml --offline --locked --test admin_service_shutdown` | 1 passed |
| `test --manifest-path proxy/Cargo.toml --offline --locked --lib audit::writer::tests` | 6 passed |
| `test --manifest-path proxy/Cargo.toml --offline --locked --lib connection_tasks::tests` | 8 passed |
| `test --manifest-path proxy/Cargo.toml --offline --locked --lib circuit_runtime::tests` | 3 passed |
| `check --manifest-path proxy/Cargo.toml --offline --locked` | passed |

The accepted focused checks also remain applicable: admin services 10 passed,
admin plumb audit 1 passed, admin shutdown 1 passed, audit writer 6 passed,
connection ownership 8 passed, and circuit runtime 3 passed.

The plumb owner now returns owned audit intents to the local diagnostic path
while marking canonical submission as owner-held, so `proxy.agent_api` retains
audit and failure markers without a second canonical event. The canonical
plumb event shape has no operator peer/path fields; the empty common metadata
arguments are therefore intentionally ignored. Message and leave cancellation
tests hold SQLite, abort the caller, drain the owner, reopen the same state
directory, and verify projection plus canonical audit.

Open gaps remain the broader standalone #626/#628/#629 matrix, real process
restart and socket-location proof, and abrupt termination durability. The
restart wording in `docs/proxy-parity.md` describes the second live owner
check accurately. Repository-wide formatting still reports pre-existing diffs
in `proxy/src/trace/tests.rs` and `proxy/tests/credential_http.rs`; strict
clippy still reports existing lints in `admin_api.rs`, `grants.rs`, and
`policy.rs`.
