# SafeYolo CLI Implementation Plan

## Summary

This document outlines the phased implementation of the SafeYolo CLI tool and corresponding credential_guard.py refactoring.

**Total scope**: ~4 phases, each independently shippable

## Phase 1: CLI Foundation + Basic Lifecycle

**Goal**: Replace manual docker-compose workflow with `safeyolo` CLI

### Deliverables

1. **New repository**: `safeyolo-cli/`
   - Python package structure
   - pyproject.toml with dependencies
   - Basic CI (lint, test)

2. **Core commands**:
   - `safeyolo init` - Generate config files (non-interactive first)
   - `safeyolo start` - Start container via docker-compose
   - `safeyolo stop` - Stop container
   - `safeyolo status` - Show container health + basic stats
   - `safeyolo logs` - Tail formatted logs

3. **Config handling**:
   - Load from `./safeyolo/` or `~/.safeyolo/`
   - Validate config schema
   - Generate docker-compose.yml from config

4. **Admin API client**:
   - `api.py` - httpx client for admin endpoints
   - Auth token handling

### Files to Create

```
safeyolo-cli/
├── pyproject.toml
├── README.md
├── src/safeyolo/
│   ├── __init__.py
│   ├── cli.py                 # Typer app, command registration
│   ├── config.py              # Config loading, validation, paths
│   ├── api.py                 # Admin API client
│   ├── docker.py              # docker-compose wrapper
│   └── commands/
│       ├── __init__.py
│       ├── init.py            # safeyolo init
│       ├── lifecycle.py       # start, stop, status
│       └── logs.py            # safeyolo logs
└── tests/
    ├── __init__.py
    ├── test_config.py
    └── test_api.py
```

### Tasks

- [ ] Create safeyolo-cli repository
- [ ] Set up pyproject.toml with Typer, httpx, rich, pyyaml
- [ ] Implement config.py (paths, loading, validation)
- [ ] Implement api.py (admin API client with auth)
- [ ] Implement docker.py (docker-compose wrapper)
- [ ] Implement `safeyolo init` (generate config template)
- [ ] Implement `safeyolo start` (validate + docker-compose up)
- [ ] Implement `safeyolo stop` (docker-compose down)
- [ ] Implement `safeyolo status` (health check + stats summary)
- [ ] Implement `safeyolo logs` (tail with rich formatting)
- [ ] Add basic tests
- [ ] Publish to PyPI (test.pypi.org first)

### Dependencies

```toml
dependencies = [
    "typer>=0.9.0",
    "httpx>=0.25.0",
    "pyyaml>=6.0",
    "rich>=13.0",
]
```

### Exit Criteria

- User can `pipx install safeyolo` and run `safeyolo init && safeyolo start`
- `safeyolo status` shows health and basic metrics
- `safeyolo logs` shows formatted log output
- No changes to proxy container required

---

## Phase 2: Slim credential_guard.py

**Goal**: Refactor credential_guard.py to ~200 lines of pure detection logic

### Deliverables

1. **Refactored credential_guard.py**:
   - Remove notification code (Pushcut, ntfy sending)
   - Remove approval state management (pending dict)
   - Remove policy file writing (read-only)
   - Keep: detection, validation, decision, event emission

2. **New admin API endpoints** (if needed):
   - `POST /admin/approve/{token_hmac}` - approve by HMAC
   - `POST /admin/deny/{token_hmac}` - deny by HMAC
   - Policy file updates happen via admin API, not addon

3. **Updated event format**:
   - Ensure all info needed for external approval flow is in JSONL
   - Include `token_hmac` in greylist events

### credential_guard.py Target Structure

```python
"""
Credential Guard - API key protection for AI coding agents

Detects credentials in HTTP requests and validates they're going
to authorized destinations. Emits structured events for all decisions.

~200 lines - designed for easy security audit
"""

class CredentialGuard:
    name = "credential-guard"

    def load(self, loader):
        # Register options

    def configure(self, updated):
        # Load rules from mounted config
        # Load policies from mounted files

    def request(self, flow):
        # 1. Detect credentials (patterns + entropy)
        # 2. Validate destination
        # 3. Decide: allow / block / greylist
        # 4. Emit event
        # 5. Return response

    # Private methods:
    # - _detect_credentials()
    # - _validate_destination()
    # - _check_policy()
    # - _make_decision()
    # - _emit_event()
```

### Modules to Extract (move to experimental or delete)

From current credential_guard.py, remove:
- `ApprovalNotifier` class (~150 lines)
- `PolicyStore` write methods (~100 lines)
- ntfy/Pushcut notification logic (~100 lines)
- Pending approval state management (~50 lines)

### Tasks

- [ ] Create credential_guard_slim.py as new implementation
- [ ] Extract detection logic (keep)
- [ ] Extract validation logic (keep)
- [ ] Extract decision logic (keep)
- [ ] Remove notification code
- [ ] Remove approval state management
- [ ] Update event emission to include all needed fields
- [ ] Update admin_api.py to handle policy writes
- [ ] Test that 428 responses still work for agents
- [ ] Verify JSONL events contain all approval info
- [ ] Swap in slim version, move old to experimental branch
- [ ] Update tests

### Exit Criteria

- credential_guard.py is <250 lines
- All detection/validation logic preserved
- Events contain `token_hmac` for external approval
- Proxy still returns 428 for greylist cases
- Old approval flow still works via experimental branch

---

## Phase 3: CLI Approval Workflow

**Goal**: Implement `safeyolo watch` as external approval daemon

### Deliverables

1. **`safeyolo watch` command**:
   - Tail safeyolo.jsonl
   - Filter for greylist events
   - Interactive TUI for approve/deny
   - Call admin API on decision

2. **Notification backends**:
   - ntfy (send notification, poll for response)
   - macOS Notification Center (with action buttons)
   - Webhook (POST event, receive callback)

3. **CLI approval commands**:
   - `safeyolo pending` - list pending (from log scan)
   - `safeyolo approve <token>` - approve via admin API
   - `safeyolo deny <token>` - deny via admin API

### Files to Create

```
src/safeyolo/
├── commands/
│   ├── watch.py               # safeyolo watch
│   └── admin.py               # approve, deny, pending
└── notify/
    ├── __init__.py            # NotifyBackend base class
    ├── ntfy.py                # ntfy.sh integration
    ├── macos.py               # macOS notifications
    └── webhook.py             # Generic webhook
```

### watch.py Design

```python
async def watch(notify: str, auto_deny: str | None):
    """Watch for approval requests and handle them."""

    async for event in tail_jsonl(log_path):
        if not is_greylist_event(event):
            continue

        # Send notification
        notifier = get_notifier(notify)
        await notifier.send(event)

        # Wait for response (TUI, callback, or timeout)
        decision = await wait_for_decision(event, auto_deny)

        # Apply decision
        if decision == "approve":
            await api.approve(event["token_hmac"])
        elif decision == "deny":
            await api.deny(event["token_hmac"])
```

### Tasks

- [ ] Implement log tailing with watchfiles
- [ ] Implement event filtering for greylist events
- [ ] Implement interactive TUI (rich)
- [ ] Implement ntfy notification backend
- [ ] Implement macOS notification backend (optional)
- [ ] Implement webhook notification backend
- [ ] Implement `safeyolo pending` (scan recent logs)
- [ ] Implement `safeyolo approve` / `deny`
- [ ] Add auto-deny timeout option
- [ ] Test full approval flow end-to-end

### Exit Criteria

- `safeyolo watch` shows live approval requests
- User can approve/deny interactively
- ntfy notifications work with action buttons
- Approved credentials work on retry
- No notification code in proxy container

---

## Phase 4: Polish & Onboarding

**Goal**: Smooth onboarding experience, documentation, release

### Deliverables

1. **Interactive `safeyolo init`**:
   - API provider selection (checkboxes)
   - Notification method selection
   - Generate complete config
   - Validate Docker is available

2. **Additional commands**:
   - `safeyolo check` - verify setup is working
   - `safeyolo test <url>` - test request through proxy
   - `safeyolo mode` - change addon modes
   - `safeyolo rules` - view/edit rules

3. **Documentation**:
   - README with quickstart
   - Full command reference
   - Configuration reference
   - Migration guide for existing users

4. **Release**:
   - PyPI publication
   - GitHub releases
   - Update main safeyolo README

### Tasks

- [ ] Implement interactive init wizard
- [ ] Implement `safeyolo check`
- [ ] Implement `safeyolo test`
- [ ] Implement `safeyolo mode`
- [ ] Implement `safeyolo rules`
- [ ] Write README
- [ ] Write command reference docs
- [ ] Write migration guide
- [ ] Set up PyPI publishing
- [ ] Create GitHub release workflow
- [ ] Update main repo README to reference CLI

### Exit Criteria

- New user can go from zero to working proxy in <5 minutes
- All commands documented with examples
- Published to PyPI
- Main repo README updated

---

## Timeline Estimate

| Phase | Scope | Estimate |
|-------|-------|----------|
| Phase 1 | CLI Foundation | First to implement |
| Phase 2 | Slim credential_guard | After Phase 1 |
| Phase 3 | Approval Workflow | After Phase 2 |
| Phase 4 | Polish & Release | After Phase 3 |

Phases can be released independently - each provides value on its own.

---

## Open Questions

1. **Separate repo or monorepo?**
   - Separate: cleaner versioning, smaller installs
   - Monorepo: easier to keep in sync, single PR for changes
   - **Recommendation**: Separate repos, CLI references container by image tag

2. **Config format: YAML or TOML?**
   - YAML: familiar, already used for policies
   - TOML: Python standard (pyproject.toml), stricter
   - **Recommendation**: YAML for consistency with existing config

3. **Docker management: docker-compose or direct API?**
   - docker-compose: simpler, user can customize compose file
   - Direct API: more control, no compose dependency
   - **Recommendation**: docker-compose initially, direct API later as option

4. **Minimum Python version?**
   - 3.10+: match patterns, modern typing
   - 3.9+: broader compatibility
   - **Recommendation**: 3.10+ (Typer works best with modern typing)

---

## Success Metrics

- [ ] credential_guard.py passes "5-minute audit" test
- [ ] New user can set up SafeYolo in <5 minutes
- [ ] Zero notification/approval code in proxy container
- [ ] CLI works on macOS, Linux (Windows: best effort)
- [ ] Published to PyPI with >100 downloads in first month
