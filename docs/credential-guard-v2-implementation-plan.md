# Credential Guard v2 - Implementation Plan

## Overview

Phased implementation plan for Credential Guard v2 enhancements to SafeYolo.

**Estimated Total:** 2-3 days (solo dev)

---

## Phase 1: Foundation (4-6 hours)

### 1.1 Configuration Infrastructure

**Tasks:**
- [ ] Create `config/safe_headers.yaml` with initial patterns
- [ ] Create `config/credential_guard.yaml` with defaults
- [ ] Add config loader for safe headers (YAML parsing)
- [ ] Add HMAC secret generation/loading (env var or auto-generate)

**Files:**
- `config/safe_headers.yaml` (new)
- `config/credential_guard.yaml` (new)
- `addons/credential_guard.py` (modify: add config loading)

**Testing:**
- Load safe_headers.yaml successfully
- Handle missing config (use defaults)
- HMAC secret generation on first run

---

### 1.2 HMAC Fingerprinting

**Tasks:**
- [ ] Add HMAC fingerprinting function
- [ ] Replace credential prefix storage with HMAC
- [ ] Update temp allowlist to use HMAC keys
- [ ] Update violation logging (no raw tokens)

**Files:**
- `addons/credential_guard.py` (modify: fingerprinting)

**Testing:**
- Same token generates same HMAC
- Different tokens generate different HMACs
- Violation logs never contain raw tokens
- Temp allowlist works with HMACs

---

### 1.3 Default Policy

**Tasks:**
- [ ] Define DEFAULT_POLICY constant (OpenAI, Anthropic, GitHub, etc.)
- [ ] Add policy merge logic (DEFAULT ⊕ file ⊕ runtime)
- [ ] Load optional policy file from disk (YAML)
- [ ] Implement path wildcard matching (`/v1/*`)

**Files:**
- `addons/credential_guard.py` (modify: policy logic)

**Testing:**
- DEFAULT_POLICY allows sk-proj-* → api.openai.com
- File policy overrides defaults
- Runtime approvals override file policy
- Path wildcards match correctly
- Query strings stripped before matching

---

## Phase 2: Smart Header Analysis (4-6 hours)

### 2.1 Tier 1: Standard Auth Headers

**Tasks:**
- [ ] Define STANDARD_AUTH_HEADERS set
- [ ] Implement `check_standard_headers()` function
- [ ] Extract tokens from Bearer/Basic schemes
- [ ] Pattern matching for known credential types

**Files:**
- `addons/credential_guard.py` (modify: header analysis)

**Testing:**
- `Authorization: Bearer sk-proj-*` → detected as OpenAI
- `X-API-Key: sk-ant-*` → detected as Anthropic
- `Authorization: Basic ...` → extracted correctly
- Unknown patterns flagged as `unknown_secret`

---

### 2.2 Tier 2: Non-Standard Headers with Heuristics

**Tasks:**
- [ ] Implement `is_safe_header()` (exact match + pattern)
- [ ] Implement `looks_like_secret()` (entropy heuristics)
- [ ] Implement `check_nonstandard_headers()` function
- [ ] Combine tier 1 + tier 2 in `analyze_headers()`

**Files:**
- `addons/credential_guard.py` (modify: header analysis)

**Testing:**
- Trace IDs (X-Request-ID, X-Trace-ID) → not flagged
- High-entropy custom header → flagged as unknown_secret
- Short values (< 20 chars) → not flagged
- Low charset diversity → not flagged

---

## Phase 3: 428 Greylist Responses (3-4 hours)

### 3.1 Decision Engine

**Tasks:**
- [ ] Implement 3-way decision logic:
  - Allow (in policy)
  - Greylist: destination mismatch (self-correct)
  - Greylist: requires approval (wait)
- [ ] Add confidence scoring (high/medium/low)

**Files:**
- `addons/credential_guard.py` (modify: decision logic)

**Testing:**
- Known credential + wrong dest → greylist_mismatch
- Known credential + correct dest + not in policy → greylist_approval
- Unknown credential → greylist_approval
- In policy → allow

---

### 3.2 Response Builders

**Tasks:**
- [ ] Implement `create_destination_mismatch_response()` (Type 1)
- [ ] Implement `create_requires_approval_response()` (Type 2)
- [ ] Add reflection prompts for both types
- [ ] Add policy snippet generation
- [ ] Add retry strategy to response

**Files:**
- `addons/credential_guard.py` (modify: response creation)

**Testing:**
- Type 1 has `action: self_correct`, expected hosts
- Type 2 has `action: wait_for_approval`, policy_snippet
- Both are valid JSON
- Reflection prompts are clear

---

## Phase 4: Approval Backend (4-6 hours)

### 4.1 Pending Approvals Store

**Tasks:**
- [ ] Add `pending_approvals` dict (in-memory)
- [ ] Implement capability token generation
- [ ] Add cleanup for very old pending approvals (optional)
- [ ] Add approval/deny logic

**Files:**
- `addons/credential_guard.py` (modify: approval state)

**Testing:**
- Capability tokens are unique
- Pending approvals stored correctly
- Approval marks as approved
- Deny marks as denied

---

### 4.2 Ntfy Integration

**Tasks:**
- [ ] Implement `NtfyApprovalBackend` class
- [ ] Send notifications with action buttons
- [ ] Include approval/deny URLs (localhost:8081/admin/...)
- [ ] Handle notification errors gracefully

**Files:**
- `addons/credential_guard.py` (new: ntfy backend)
- Or `addons/approval_backends/ntfy.py` (new file)

**Testing:**
- Notification sent on greylist
- Action buttons include correct URLs
- Errors logged, don't crash proxy
- Can send to ntfy.sh successfully

---

### 4.3 Admin API Extensions

**Tasks:**
- [ ] Add `POST /admin/approve/{token}` endpoint
- [ ] Add `POST /admin/deny/{token}` endpoint
- [ ] Add `GET /admin/approvals/pending` endpoint
- [ ] Add `POST /admin/policy/validate` endpoint (for pre-commit hook)
- [ ] Add `GET /admin/policy/{project}` endpoint (read project policy file)
- [ ] Add `POST /admin/policy/defaults` (override defaults)

**Files:**
- `addons/admin_api.py` (modify: new endpoints)

**Testing:**
- Approve endpoint writes to /app/data/policies/{project}.yaml
- Deny endpoint marks as denied
- Validate endpoint returns errors for invalid YAML
- Policy endpoint returns current file content
- Defaults override works

**Note:** No import endpoint needed - users edit files directly on host

---

## Phase 5: Policy File Storage (2-3 hours)

### 5.1 Mounted Directory Storage

**Tasks:**
- [ ] Implement `ProjectPolicyStore` class
- [ ] Read/write to `/app/data/policies/{project}.yaml` (mounted from host)
- [ ] Create policy file on first approval (if doesn't exist)
- [ ] Thread-safe writes (file locking)
- [ ] Atomic writes (tmp file + rename)

**Files:**
- `addons/credential_guard.py` (new: policy store)

**Testing:**
- Policy files created in mounted directory (visible on host)
- Concurrent writes don't corrupt file
- YAML is valid and human-readable
- Per-project isolation works

**Docker setup:**
```yaml
volumes:
  - ${SAFEYOLO_POLICY_DIR:-~/.safeyolo/policies}:/app/data/policies:rw
```

---

### 5.2 File Watch and Reload

**Tasks:**
- [ ] Implement file watch for policy directory
- [ ] Validate YAML on file change
- [ ] Reload policy atomically (invalid = keep old)
- [ ] Log errors for invalid files

**Files:**
- `addons/credential_guard.py` (modify: file watching)

**Testing:**
- File edits on host trigger reload in container
- Invalid YAML logged, old policy kept
- Policy merge: DEFAULT ⊕ project_file
- Reload is atomic (no partial state)

---

## Phase 6: Project Identification (2-3 hours)

### 6.1 Service Discovery Integration

**Tasks:**
- [ ] Import `get_service_discovery()` from existing addon
- [ ] Map source IP → container name
- [ ] Extract project ID from labels (`com.docker.compose.project`)
- [ ] Fallback to container name if no label

**Files:**
- `addons/credential_guard.py` (modify: project detection)

**Testing:**
- Source IP correctly mapped to container
- Project ID extracted from labels
- Fallback to container name works
- Policy scoped per project

---

## Phase 7: Integration and Polish (2-3 hours)

### 7.1 End-to-End Testing

**Tasks:**
- [ ] Test full approval flow (unknown credential → ntfy → approve → allow)
- [ ] Test self-correct flow (wrong destination → 428 → agent fixes)
- [ ] Test default policy (OpenAI/Anthropic allowed automatically)
- [ ] Test policy export and manual commit
- [ ] Test multi-project isolation

**Testing:**
- All scenarios work end-to-end
- No credential leakage in logs
- Performance is acceptable (< 10ms overhead per request)

---

### 7.2 Documentation

**Tasks:**
- [ ] Update main README with v2 features
- [ ] Document ntfy setup (topic creation, config)
- [ ] Document policy export workflow
- [ ] Add example policy files
- [ ] Document safe_headers customization
- [ ] Create pre-commit hook file (`~/.safeyolo/hooks/pre-commit`)
- [ ] Document pre-commit hook setup (copy to `.git/hooks/`)
- [ ] Add example validation error output to docs

**Files:**
- `README.md` (update)
- `docs/approval-workflows.md` (new)
- `docs/policy-management.md` (new)
- `examples/safeyolo_policy.yaml` (new)
- `hooks/pre-commit` (new)

---

### 7.3 Migration from v1

**Tasks:**
- [ ] Document breaking changes
- [ ] Provide migration script (if needed)
- [ ] Update docker-compose.yml with new env vars

**Files:**
- `docs/migration-v1-to-v2.md` (new)
- `docker-compose.yml` (update)

---

## Phase 8: Future - GitHub PR Backend (Not in Initial Scope)

### 8.1 PR Creation

**Tasks:**
- [ ] Implement `PRApprovalBackend` class
- [ ] Create branch with policy change
- [ ] Generate PR with description
- [ ] Poll for PR merge status

**Files:**
- `addons/approval_backends/pr.py` (new)

---

## Testing Checklist

### Unit Tests
- [ ] HMAC fingerprinting
- [ ] Entropy heuristics
- [ ] Safe header matching (exact + pattern)
- [ ] Path wildcard matching
- [ ] Policy merge logic
- [ ] Token extraction (Bearer/Basic)

### Integration Tests
- [ ] Full approval flow (ntfy)
- [ ] Self-correct flow (destination mismatch)
- [ ] Default policy allows common services
- [ ] Policy export/import
- [ ] Multi-project isolation
- [ ] Admin API endpoints

### Manual Tests
- [ ] Ntfy notifications arrive on phone/watch
- [ ] Approval buttons work from ntfy
- [ ] Policy export via curl works
- [ ] File watch reloads policy
- [ ] No credential leakage in logs

---

## Deployment Checklist

- [ ] Environment variables documented (NTFY_TOPIC, HMAC_SECRET, SAFEYOLO_POLICY_DIR)
- [ ] Config files with sensible defaults
- [ ] Docker volumes for persistent state (/app/data)
- [ ] Admin API only on localhost (security)
- [ ] Safe headers config extensible
- [ ] Pre-commit hook available in repo (hooks/pre-commit)
- [ ] Pre-commit hook setup documented
- [ ] Migration guide from v1
- [ ] Rollback plan if needed

---

## Success Metrics

**Performance:**
- < 10ms overhead per request
- No memory leaks (long-running test)

**Security:**
- Zero raw credentials in logs
- Zero credential leakage in responses
- HMAC fingerprints collision-free

**UX:**
- Default policy: 0 prompts for OpenAI/Anthropic/GitHub
- Approval latency: < 30s (human response time)
- Policy export: 1 command

**Reliability:**
- 428 responses guide agent correctly
- Approval state persists across restarts
- File corruption handled gracefully

---

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| HMAC collisions | Use SHA256, first 16 chars = 2^64 space |
| File corruption | Atomic writes (tmp + rename) |
| Ntfy downtime | Agent retries, logs error |
| False positives (trace IDs) | Configurable safe_headers.yaml |
| Policy file conflicts | Manual export (no auto-write) |

---

## Timeline Estimate

| Phase | Estimated Time |
|-------|----------------|
| Phase 1: Foundation | 4-6 hours |
| Phase 2: Smart Header Analysis | 4-6 hours |
| Phase 3: 428 Greylist Responses | 3-4 hours |
| Phase 4: Approval Backend | 4-6 hours |
| Phase 5: Runtime Policy Storage | 2-3 hours |
| Phase 6: Project Identification | 2-3 hours |
| Phase 7: Integration and Polish | 2-3 hours |
| **Total** | **21-31 hours (2-4 days)** |

**Phase 8 (GitHub PR):** +1-2 days (future work)

---

## Next Steps

1. Review design doc and implementation plan
2. Get approval to proceed
3. Create feature branch: `feature/credential-guard-v2`
4. Start with Phase 1 (Foundation)
5. Commit after each phase completes
6. Test thoroughly before merging to main

---

**Plan Version:** 1.1
**Last Updated:** 2025-01-02
**Status:** Ready for Implementation
**Changes in v1.1:** Simplified to configurable policy directory (no API import/export complexity)
