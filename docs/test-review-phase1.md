# Test Review: Phase 1.1-1.3 (Credential Guard v2)

**Date:** 2026-01-02
**Scope:** Review existing tests and identify gaps for Phase 1 implementation

---

## Current Test Coverage

### ✅ **Well Tested** (No Changes Needed)

1. **Pattern Matching (TestCredentialRule)**
   - OpenAI key patterns: ✅
   - Anthropic key patterns: ✅
   - Pattern rejection (short keys, wrong prefix): ✅

2. **Host Matching (TestCredentialRule)**
   - Exact host matching: ✅
   - Wildcard subdomain matching (`*.googleapis.com`): ✅
   - Port stripping: ✅

3. **LLM-Friendly Responses (TestLLMFriendlyResponse)**
   - Prompt injection warnings: ✅
   - Reflection prompts: ✅
   - Suggested URLs: ✅

4. **Violation Stats (TestStats)**
   - Total violation count: ✅
   - Per-type violation count: ✅

5. **Blocking vs Warn Mode (TestBlockingMode)**
   - Block mode blocks: ✅
   - Warn mode logs but doesn't block: ✅

---

## ⚠️ **Needs Updating** (Breaking Changes)

### 1. **Temp Allowlist Tests** (TestTempAllowlist)

**Problem:** Tests pass raw credentials to `add_temp_allowlist()`, but v2 expects full credentials (for HMAC fingerprinting).

**Current:**
```python
credential_guard.add_temp_allowlist("sk-proj-abc...", "evil.com", 60)
```

**v2 Behavior:**
- Parameter is now the full credential (not prefix)
- Internally generates HMAC fingerprint
- Stores `(hmac_fingerprint, host)` tuple

**Status:** ✅ Actually works! The v2 implementation takes full credential and generates HMAC internally.

**Action Required:** Update assertions to check for `credential_fingerprint` format:
```python
# Should assert hmac:xxx format in logs/metadata
assert "hmac:" in flow.metadata.get("credential_fingerprint", "")
```

---

### 2. **Metadata Assertions** (Multiple Test Classes)

**Problem:** Tests check for `credential_prefix` in flow.metadata, but v2 uses `credential_fingerprint`.

**Files to Update:**
- `test_blocks_openai_key_to_wrong_host` (line 110)
- `test_blocks_key_in_header` (check metadata)
- `test_temp_allowlist_allows_blocked_request` (line 190)
- `test_warn_mode_logs_but_does_not_block` (line 288)
- `test_blocking_mode_blocks` (line 314)

**Old:**
```python
assert flow.metadata.get("credential_prefix") == "sk-proj-abc123..."
```

**New:**
```python
assert flow.metadata.get("credential_fingerprint").startswith("hmac:")
```

---

### 3. **Credential Guard Fixture** (conftest.py)

**Problem:** Fixture doesn't initialize v2 features (HMAC secret, configs, policies).

**Current:**
```python
@pytest.fixture
def credential_guard():
    addon = CredentialGuard()
    addon.rules = list(DEFAULT_RULES)
    addon._should_block = lambda: True
    return addon
```

**Missing:**
- `addon.hmac_secret` not initialized (causes HMAC fingerprinting to fail)
- `addon.config` not loaded
- `addon.safe_headers_config` not loaded
- `addon.default_policy` not initialized (actually defaults to DEFAULT_POLICY in __init__)

**Action Required:**
```python
@pytest.fixture
def credential_guard():
    addon = CredentialGuard()
    addon.rules = list(DEFAULT_RULES)
    addon._should_block = lambda: True

    # v2 initialization
    addon.hmac_secret = b"test-secret-for-hmac-fingerprinting"
    addon.config = {}
    addon.safe_headers_config = {}
    # default_policy already set in __init__

    return addon
```

---

### 4. **Body/URL Scanning Tests**

**Problem:** Tests assume body scanning is enabled, but v2 defaults to `scan_bodies=False`.

**Affected Tests:**
- `test_blocks_openai_key_to_wrong_host` (checks body content)
- `test_allows_openai_key_to_openai` (checks body content)
- `test_blocks_key_in_url` (requires `scan_urls=True`)

**Action Required:**
- Either: Mock `ctx.options.credguard_scan_bodies = True`
- Or: Use header-based tests instead (preferred)
- For URL tests: Mock `ctx.options.credguard_scan_urls = True`

---

## 🚨 **Material Gaps** (New Tests Needed)

### Phase 1.1: Configuration Infrastructure

**Missing Tests:**

1. **HMAC Fingerprinting**
   ```python
   def test_hmac_fingerprint_deterministic():
       """Same credential generates same fingerprint."""

   def test_hmac_fingerprint_unique():
       """Different credentials generate different fingerprints."""

   def test_hmac_fingerprint_no_collisions():
       """Test collision resistance with many credentials."""
   ```

2. **HMAC Secret Loading**
   ```python
   def test_hmac_secret_from_env():
       """Load HMAC secret from CREDGUARD_HMAC_SECRET env var."""

   def test_hmac_secret_from_file():
       """Load existing HMAC secret from file."""

   def test_hmac_secret_generation():
       """Generate new HMAC secret if missing."""

   def test_hmac_secret_file_permissions():
       """Generated secret file has 0o600 permissions."""
   ```

3. **Config Loading**
   ```python
   def test_load_safe_headers_config():
       """Load safe_headers.yaml successfully."""

   def test_load_credential_guard_config():
       """Load credential_guard.yaml successfully."""

   def test_config_missing_files():
       """Handle missing config files gracefully (use defaults)."""

   def test_config_invalid_yaml():
       """Handle invalid YAML gracefully (log error, use defaults)."""
   ```

---

### Phase 1.2: HMAC Fingerprinting

**Missing Tests:**

1. **Temp Allowlist with HMAC**
   ```python
   def test_temp_allowlist_uses_hmac():
       """Verify allowlist stores HMAC, not raw credentials."""

   def test_get_temp_allowlist_returns_hmac():
       """Verify get_temp_allowlist() returns hmac:xxx format."""
   ```

2. **Violation Logging with HMAC**
   ```python
   def test_violation_log_never_contains_raw_credential():
       """Ensure _log_violation() never logs raw tokens."""

   def test_block_response_headers_contain_hmac():
       """X-Credential-Fingerprint header has hmac:xxx format."""
   ```

3. **Flow Metadata with HMAC**
   ```python
   def test_metadata_credential_fingerprint_format():
       """flow.metadata['credential_fingerprint'] is hmac:xxx."""
   ```

---

### Phase 1.3: Default Policy

**Missing Tests:**

1. **Path Wildcard Matching**
   ```python
   def test_path_wildcard_suffix():
       """Test /v1/* matches /v1/chat/completions."""
       assert path_matches_pattern("/v1/chat/completions", "/v1/*")
       assert path_matches_pattern("/v1/", "/v1/*")
       assert not path_matches_pattern("/v2/chat", "/v1/*")

   def test_path_wildcard_prefix():
       """Test */completions matches /v1/chat/completions."""
       assert path_matches_pattern("/v1/chat/completions", "*/completions")

   def test_path_exact_match():
       """Test exact path matching."""
       assert path_matches_pattern("/v1/chat/completions", "/v1/chat/completions")

   def test_path_query_string_stripped():
       """Test query strings are stripped before matching."""
       assert path_matches_pattern("/v1/chat?key=123", "/v1/*")
   ```

2. **Host Pattern Matching**
   ```python
   def test_matches_host_pattern_exact():
       """Test exact host matching."""

   def test_matches_host_pattern_wildcard():
       """Test *.example.com matching."""

   def test_matches_host_pattern_strips_port():
       """Test host:port matching."""
   ```

3. **DEFAULT_POLICY Behavior**
   ```python
   def test_openai_allowed_by_default_policy():
       """OpenAI keys to api.openai.com/v1/* allowed by default."""
       # sk-proj-xxx -> api.openai.com/v1/chat/completions
       # Should NOT block (no 403 response)

   def test_anthropic_allowed_by_default_policy():
       """Anthropic keys to api.anthropic.com/v1/* allowed by default."""

   def test_github_allowed_by_default_policy():
       """GitHub tokens to api.github.com allowed by default."""

   def test_openai_wrong_path_blocked():
       """OpenAI key to api.openai.com/admin/* blocked (not in default policy)."""
       # Default policy only allows /v1/*

   def test_openai_wrong_host_blocked():
       """OpenAI key to evil.com blocked (not in default policy)."""
   ```

4. **Policy Checking Logic**
   ```python
   def test_check_policy_approval_matches_all_criteria():
       """Policy approval requires pattern + host + path match."""

   def test_check_policy_approval_fails_wrong_pattern():
       """Wrong credential pattern fails policy check."""

   def test_check_policy_approval_fails_wrong_host():
       """Wrong host fails policy check."""

   def test_check_policy_approval_fails_wrong_path():
       """Wrong path fails policy check."""
   ```

5. **Policy Loading**
   ```python
   def test_load_policy_files_from_directory():
       """Load all .yaml files from /app/data/policies."""

   def test_load_policy_invalid_yaml():
       """Log error and skip invalid policy files."""

   def test_load_policy_missing_directory():
       """Handle missing policy directory gracefully."""
   ```

6. **Policy Merging**
   ```python
   def test_merge_policies_default_only():
       """With no project policy, use DEFAULT_POLICY."""

   def test_merge_policies_with_project():
       """Merge DEFAULT_POLICY + project policy."""

   def test_merge_policies_project_extends_default():
       """Project policy adds to default (doesn't replace)."""
   ```

---

## 📊 **Test Coverage Summary**

| Feature | Existing Tests | Needs Update | Missing Tests | Priority |
|---------|---------------|--------------|---------------|----------|
| Pattern Matching | ✅ 5 tests | - | - | ✅ Complete |
| Host Matching | ✅ 3 tests | - | 2 edge cases | Low |
| Blocking Behavior | ✅ 5 tests | Metadata assertions | - | **High** |
| Temp Allowlist | ✅ 2 tests | HMAC format checks | 2 HMAC tests | **High** |
| LLM Responses | ✅ 1 test | - | - | ✅ Complete |
| Stats | ✅ 1 test | - | - | ✅ Complete |
| Blocking Mode | ✅ 2 tests | - | - | ✅ Complete |
| **HMAC Fingerprinting** | ❌ 0 tests | - | 6 tests | **CRITICAL** |
| **Config Loading** | ❌ 0 tests | - | 4 tests | **High** |
| **Path Wildcards** | ❌ 0 tests | - | 4 tests | **CRITICAL** |
| **Host Patterns** | Partial (3) | - | 2 tests | Medium |
| **DEFAULT_POLICY** | ❌ 0 tests | - | 5 tests | **CRITICAL** |
| **Policy Loading** | ❌ 0 tests | - | 3 tests | **High** |
| **Policy Merging** | ❌ 0 tests | - | 3 tests | **High** |

---

## 🎯 **Recommended Test Strategy**

### Immediate (Before Phase 2)

1. **Fix Breaking Changes** (30 min)
   - Update credential_guard fixture with HMAC secret
   - Update metadata assertions (credential_prefix → credential_fingerprint)
   - Fix body/URL scanning assumptions

2. **Critical Gaps** (2-3 hours)
   - HMAC fingerprinting (6 tests)
   - Path wildcard matching (4 tests)
   - DEFAULT_POLICY behavior (5 tests)

3. **Verify Phase 1** (30 min)
   - Run all tests
   - Ensure no regressions
   - Document remaining gaps for later

### Later (Before Production)

4. **High Priority Gaps** (2-3 hours)
   - Config loading (4 tests)
   - Policy loading (3 tests)
   - Policy merging (3 tests)
   - Temp allowlist HMAC (2 tests)

5. **Nice to Have** (1-2 hours)
   - Host pattern edge cases
   - HMAC collision resistance
   - Secret file permissions

---

## 📝 **Test Organization Proposal**

Reorganize tests into focused modules:

```
tests/
├── conftest.py (fixtures)
├── test_credential_guard.py (KEEP - integration tests)
└── test_credential_guard_v2/
    ├── test_hmac_fingerprinting.py (NEW)
    ├── test_config_loading.py (NEW)
    ├── test_path_matching.py (NEW)
    ├── test_policy_default.py (NEW)
    ├── test_policy_loading.py (NEW)
    └── test_policy_merging.py (NEW)
```

OR: Keep everything in `test_credential_guard.py` organized by class (current pattern).

**Recommendation:** Keep current single-file approach for now (less churn), add new test classes:
- `TestHMACFingerprinting`
- `TestConfigLoading`
- `TestPathMatching`
- `TestDefaultPolicy`
- `TestPolicyLoading`
- `TestPolicyMerging`

---

## 🔥 **Critical Risks Without Tests**

1. **HMAC Collisions** - If fingerprinting is broken, allowlist won't work
2. **Path Matching Bugs** - Default policy could fail, blocking legitimate requests
3. **Policy Loading Errors** - Silent failures could leave users without protection
4. **Config Parsing** - YAML errors could crash the addon on startup

---

## ✅ **Success Criteria**

Phase 1 testing is complete when:
- [ ] All existing tests pass with v2 changes
- [ ] HMAC fingerprinting fully tested (6 tests)
- [ ] Path wildcard matching fully tested (4 tests)
- [ ] DEFAULT_POLICY behavior verified (5 tests)
- [ ] Config loading error handling tested (4 tests)
- [ ] Test coverage > 80% for Phase 1 code
- [ ] No raw credentials in any test logs/metadata

---

**Next Steps:**
1. Review this document
2. Decide on test strategy (immediate vs later)
3. Update fixtures (conftest.py)
4. Write critical tests first
5. Run full test suite
6. Document remaining gaps
