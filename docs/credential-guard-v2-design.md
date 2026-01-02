# Credential Guard v2 - Design Document

## Executive Summary

Credential Guard v2 enhances SafeYolo's credential protection with smart HTTP header analysis, 428 greylist responses, HMAC fingerprinting, and pluggable approval workflows (ntfy → GitHub PR progression).

**Design Goals:**
- **Solo devs first** - Zero friction for common cases, remote approval for edge cases
- **Team-ready** - Clear path to GitHub PR-based approvals
- **Smart defaults** - OpenAI/Anthropic/GitHub work out of box
- **Simple implementation** - Files not SQLite, manual export not auto-write

---

## Design Decisions

### 1. Smart HTTP Header Analysis

**Two-tier detection:**

**Tier 1: Standard auth headers** (no heuristics needed)
- `Authorization`, `Proxy-Authorization`, `X-API-Key`, `Api-Key`, `X-Auth-Token`, `X-Access-Token`
- Header name itself indicates credentials
- Extract token (handle Bearer/Basic schemes)
- Pattern match for credential type (sk-proj-, sk-ant-, etc.)
- High confidence

**Tier 2: Non-standard headers** (entropy heuristics)
- Check all other headers for credential-like values
- Skip safe headers (Host, User-Agent, Content-Type, trace IDs, etc.)
- Apply entropy heuristics (length ≥20, charset diversity ≥16, alphanumeric)
- Flag as `unknown_secret` if matches
- Medium confidence

**Configurable safe headers:**
```yaml
# config/safe_headers.yaml
exact_match:
  - host
  - user-agent
  - content-type
  - x-request-id
  - x-trace-id
  - x-amzn-trace-id
  - traceparent
  - tracestate

patterns:
  - "^x-.*-id$"           # x-request-id, x-correlation-id
  - "^x-.*-trace.*$"      # x-cloud-trace-context
  - "^x-b3-.*$"           # B3 propagation
  - "^x-amz.*-id.*$"      # AWS trace headers
  - "^x-datadog-.*$"      # Datadog APM
```

**Why:** Cloud trace IDs have high entropy but aren't secrets.

---

### 2. Three-Way Decision Logic

```python
if token_hmac in approved_policy:
    return ALLOW

elif known_credential_type and destination in expected_hosts:
    return GREYLIST_428_APPROVAL_REQUIRED  # Plausible, needs approval

elif known_credential_type and destination not in expected_hosts:
    return GREYLIST_428_SELF_CORRECT  # Likely hallucination

elif unknown_credential_type:
    return GREYLIST_428_APPROVAL_REQUIRED  # Cautious with unknowns

else:
    return ALLOW
```

**Two types of 428 responses:**

**Type 1: Destination Mismatch (self-correct)**
```json
{
  "error": "credential_destination_mismatch",
  "status": 428,
  "blocked": {
    "credential_type": "openai",
    "destination": "api.openai-typo.com"
  },
  "expected": {
    "hosts": ["api.openai.com"]
  },
  "reflection_prompt": "LIKELY HALLUCINATION DETECTED...",
  "action": "self_correct"
}
```
- Agent recognizes error, fixes URL, retries
- NO approval workflow triggered

**Type 2: Requires Approval (wait)**
```json
{
  "error": "credential_requires_approval",
  "status": 428,
  "blocked": {
    "credential_type": "unknown_secret",
    "destination": "internal-api.company.com"
  },
  "policy_snippet": {
    "token_hmac": "hmac:abc123",
    "hosts": ["internal-api.company.com"],
    "paths": ["/v1/*"]
  },
  "approval": {
    "method": "ntfy",
    "token": "cap_xyz789"
  },
  "retry_strategy": {
    "interval_seconds": 30,
    "max_duration_seconds": 3600
  },
  "action": "wait_for_approval"
}
```
- Agent retries periodically
- Human approves via ntfy (or PR in future)
- NO timeout on approvals (agent gives up after max_duration)

---

### 3. HMAC Fingerprinting

**Never store raw credentials:**
```python
token_hmac = hmac.new(
    key=HMAC_SECRET,  # From env or generated on first run
    msg=credential.encode('utf-8'),
    digestmod='sha256'
).hexdigest()[:16]  # First 16 chars sufficient

# Store: "hmac:a1b2c3d4e5f6"
# Never store: "sk-proj-abc123xyz..."
```

**Why:** Violation logs, policy files, admin API never expose raw tokens.

---

### 4. Default Policy (Smart Defaults)

**Built-in, always active:**
```python
DEFAULT_POLICY = {
    "approved": [
        # OpenAI
        {"pattern": "sk-proj-.*", "hosts": ["api.openai.com"], "paths": ["/v1/*"]},
        {"pattern": "sk-(?!ant-|or-).*", "hosts": ["api.openai.com"], "paths": ["/v1/*"]},

        # Anthropic
        {"pattern": "sk-ant-.*", "hosts": ["api.anthropic.com"], "paths": ["/v1/*"]},

        # GitHub
        {"pattern": "ghp_.*", "hosts": ["api.github.com", "github.com"], "paths": ["/*"]},
        {"pattern": "gho_.*", "hosts": ["api.github.com", "github.com"], "paths": ["/*"]},

        # Google
        {"pattern": "AIza.*", "hosts": ["*.googleapis.com"], "paths": ["/*"]},

        # OpenRouter
        {"pattern": "sk-or-.*", "hosts": ["openrouter.ai", "api.openrouter.ai"], "paths": ["/v1/*"]},

        # AWS (if added to defaults)
        # {"pattern": "AKIA[A-Z0-9]{16}", "hosts": ["*.amazonaws.com"], "paths": ["/*"]},
    ]
}
```

**Build up over time** - add common services as defaults.

**Override via admin API:**
```bash
# Disable default for OpenAI (require approval)
curl -X POST http://localhost:8081/admin/policy/defaults \
  -d '{"disable": ["openai"]}'
```

---

### 5. Path Canonicalization

**mitmproxy preserves paths as-sent** (no canonicalization):
- `//v1/chat` → `request.path = '////v1/chat'`
- `/v1/../chat` → `request.path = '/v1/../chat'`
- Query strings included: `request.path = '/v1/chat?foo=bar'`

**Policy matching:**
```python
def path_matches(request_path: str, policy_pattern: str) -> bool:
    # Strip query string
    path = request_path.split('?')[0]

    # Exact match
    if path == policy_pattern:
        return True

    # Wildcard: /v1/* matches /v1/chat, /v1/completions
    if policy_pattern.endswith('/*'):
        prefix = policy_pattern[:-2]
        return path.startswith(prefix + '/')

    return False
```

**Let target servers handle canonicalization** - don't try to normalize on proxy side.

---

### 6. Project Identification

**Use existing service discovery addon:**
```python
from .service_discovery import get_service_discovery

# In credential_guard request handler:
discovery = get_service_discovery()
source_ip = flow.client_conn.peername[0]

for name, service in discovery.get_services().items():
    if service.internal_ip == source_ip:
        project_id = service.labels.get("com.docker.compose.project", name)
        break
```

**Fallback:** Use container name if no project label.

**Policy scoping:**
```json
{
  "myproject": {
    "approved": [...]
  },
  "otherproject": {
    "approved": [...]
  }
}
```

---

### 7. Policy Storage (Configurable Directory)

**Simple approach: Mounted directory on host**

**Solo dev (default):**
```yaml
# docker-compose.yml
services:
  safeyolo:
    volumes:
      - ~/.safeyolo/policies:/app/data/policies:rw
```

**Host filesystem:**
```
~/.safeyolo/policies/
  ├── myproject.yaml           # SafeYolo reads/writes directly
  └── otherproject.yaml
```

**Team (configurable):**
```yaml
# docker-compose.yml
services:
  safeyolo:
    volumes:
      - ${SAFEYOLO_POLICY_DIR:-~/.safeyolo/policies}:/app/data/policies:rw
```

**Team sets location:**
```bash
export SAFEYOLO_POLICY_DIR=/shared/safeyolo/policies
# or /mnt/nfs/safeyolo/policies
# or wherever team manages policies
```

**Policy file format (per-project):**
```yaml
# ~/.safeyolo/policies/myproject.yaml
approved:
  - token_hmac: "hmac:abc123"
    hosts: ["internal-api.company.com"]
    paths: ["/v1/*"]
    approved_at: "2025-01-02T14:30:00Z"
    approved_by: "ntfy"
    note: "Internal service API"
```

**Why files (not SQLite):**
- Only one writer (approval backend)
- Approvals are infrequent
- Policy size is small (< 1000 entries)
- Human-readable (can edit directly)
- Simpler code

**File watch and reload:**
```python
# SafeYolo watches policy directory
# On file change: validate → reload
# Invalid files: log error, keep old policy
```

**Team workflow:**
- SafeYolo writes to shared directory
- Team manages that directory however they want (git, rsync, NFS, etc.)
- SafeYolo reloads on file changes
- No source code access required ✅

**Policy validation:**
- File watch validates on change
- Invalid files logged, old policy kept
- For better UX: use pre-commit hook (see below)

---

### 8. Policy Validation (Pre-commit Hook)

**Problem:** User edits policy file with typo → invalid file → silent failure

**Solution:** Pre-commit hook validates before commit

**Setup (one-time):**
```bash
cd ~/.safeyolo/policies
git init
cp ~/.safeyolo/hooks/pre-commit .git/hooks/
chmod +x .git/hooks/pre-commit
```

**Hook validates via admin API:**
```bash
#!/bin/bash
# Validate all policy files before commit

for file in *.yaml; do
  [ -f "$file" ] || continue

  echo "Validating $file..."
  result=$(curl -sf -X POST http://localhost:8081/admin/policy/validate \
    --data-binary @"$file" 2>&1)

  if [ $? -ne 0 ]; then
    echo "❌ Invalid policy file: $file"
    echo "$result" | jq -r '.errors[] | "  Line \(.line): \(.message)"'
    exit 1
  fi
done

echo "✅ All policy files valid"
```

**User workflow:**
```bash
# Edit policy
vim myproject.yaml

# Commit
git add myproject.yaml
git commit -m "add preset approvals"

# Hook validates:
# Validating myproject.yaml...
# ❌ Invalid policy file: myproject.yaml
#   Line 5: Missing required field 'token_hmac'
#
# Commit blocked! Fix errors and retry.
```

**Benefits:**
- Immediate feedback at commit time
- Blocks invalid commits automatically
- Familiar git workflow
- No special tooling needed

**Admin API endpoint:**
```
POST /admin/policy/validate
Content-Type: application/yaml
Body: <policy YAML>

Response:
{
  "valid": true
}

Or:
{
  "valid": false,
  "errors": [
    {"line": 5, "field": "token_hmac", "message": "Required field missing"},
    {"line": 12, "field": "hosts", "message": "Must be array, got string"}
  ]
}
```

---

### 9. Approval Workflows

**Pluggable backends:**

**Phase 1: Ntfy (reference implementation)**
```yaml
approval_backend: "ntfy"

ntfy:
  url: "https://ntfy.sh"
  topic: "${NTFY_TOPIC}"
  admin_api_url: "http://localhost:8081/admin"
```

**Ntfy notification with action buttons:**
```json
{
  "topic": "safeyolo-alerts",
  "title": "🔐 Credential Approval: unknown_secret",
  "message": "unknown_secret → internal-api.company.com",
  "priority": 4,
  "actions": [
    {
      "action": "http",
      "label": "✅ Approve",
      "url": "http://localhost:8081/admin/approve/cap_xyz789",
      "method": "POST",
      "clear": true
    },
    {
      "action": "http",
      "label": "❌ Deny",
      "url": "http://localhost:8081/admin/deny/cap_xyz789",
      "method": "POST",
      "clear": true
    }
  ]
}
```

**Phase 2: GitHub PR (future)**
```yaml
approval_backend: "pr"

pr:
  repository: "user/project"
  policy_file: "safeyolo_policy.yaml"
  branch_prefix: "safeyolo/approve-"
```

**Approval flow (same for both):**
1. Agent makes request with unknown credential+destination
2. Proxy returns 428 with `policy_snippet`
3. Backend-specific approval request:
   - Ntfy: Send notification with buttons
   - PR: Agent creates PR with policy snippet
4. Agent retries periodically (every 30s)
5. Human approves when convenient (minutes or days)
6. Policy updates (runtime or file)
7. Agent retry succeeds

**No approval timeout** - agent gives up after max_duration (default 1 hour), but approval can happen anytime.

---

### 10. Admin API (localhost only)

**Security model:**
- Admin API: `127.0.0.1:8081` (NOT exposed to containers)
- No Agent API needed (proxy makes decisions, agent just gets allow/block/greylist)

**Endpoints:**
```
POST /admin/approve/{token}              # Approve pending request
POST /admin/deny/{token}                 # Deny pending request
POST /admin/policy/validate              # Validate policy YAML (for pre-commit hook)
GET  /admin/policy/{project}             # Get policy for project
GET  /admin/policy/effective?project=X   # Show merged effective policy
POST /admin/policy/defaults              # Override default policy
GET  /admin/approvals/pending            # List pending approvals
GET  /admin/stats                        # Violation stats
```

**Why no Agent API:**
- Containers don't need to read policy (proxy decides)
- 428 response includes all info needed (policy snippet for PR)
- Simpler, more secure
- Less code

---

### 11. Configuration

**Main config:**
```yaml
# config/credential_guard.yaml

credential_guard:
  # Detection
  scan_all_headers: true
  detect_high_entropy: true
  min_entropy_length: 20
  safe_headers_file: "config/safe_headers.yaml"

  # Decision
  block_wrong_destinations: true     # 428 self-correct
  greylist_new_pairings: true        # 428 approval required

  # Approval backend
  approval_backend: "ntfy"

  ntfy:
    url: "https://ntfy.sh"
    topic: "${NTFY_TOPIC}"
    admin_api_url: "http://localhost:8081/admin"

  # Policy
  use_default_policy: true
  policies_dir: "/app/data/policies"    # Mounted from host (configurable)
  policy_reload: "watch"                # Watch for file changes

  # HMAC
  hmac_secret: "${HMAC_SECRET}"  # From env or auto-generated

  # Retry guidance for agents
  retry_defaults:
    interval_seconds: 30
    max_duration_seconds: 3600  # 1 hour (null = no limit)
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Agent Container                         │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  Coding Agent (Claude, GPT, etc.)                          │ │
│  │  - Makes HTTP requests with credentials                    │ │
│  │  - Handles 428 greylist responses                          │ │
│  │  - Retries after approval                                  │ │
│  └────────────────────────────────────────────────────────────┘ │
│                              ↓ HTTP requests                    │
└──────────────────────────────┼──────────────────────────────────┘
                               ↓
┌──────────────────────────────┼──────────────────────────────────┐
│                    SafeYolo Proxy :8080                         │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  Credential Guard Addon                                    │ │
│  │  - Smart header analysis (2-tier)                          │ │
│  │  - Pattern matching + entropy heuristics                   │ │
│  │  - HMAC fingerprinting                                     │ │
│  │  - Policy check (DEFAULT ⊕ file ⊕ runtime)                │ │
│  │  - 3-way decision (allow/greylist/block)                   │ │
│  └────────────────────────────────────────────────────────────┘ │
│           ↓ allow                  ↓ greylist                   │
│  ┌──────────────────┐    ┌──────────────────────────────────┐  │
│  │ Proxy to dest    │    │  Approval Backend (ntfy/PR)      │  │
│  └──────────────────┘    └──────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                               ↓ ntfy notification
┌──────────────────────────────┼──────────────────────────────────┐
│                    Admin API :8081 (localhost)                  │
│  POST /admin/approve/{token}                                    │
│  GET  /admin/policy/export?project=X                            │
└─────────────────────────────────────────────────────────────────┘
                               ↓
┌──────────────────────────────┼──────────────────────────────────┐
│                         Human (phone/laptop)                    │
│  - Receives ntfy on watch/phone                                 │
│  - Taps "Approve" button                                        │
│  - Or: curl to export policy, commit to repo                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Implementation Notes

### Existing Code to Preserve
- Current credential_guard.py has pattern matching, temp allowlist, violation logging
- Reuse pattern matching logic
- Keep violation stats/logging

### New Code to Add
- Smart header analysis (2-tier)
- Entropy heuristics (tier 2)
- Safe headers config loader
- HMAC fingerprinting
- 428 greylist response builder (2 types)
- Ntfy approval backend
- Policy merge logic (DEFAULT ⊕ file ⊕ runtime)
- Path wildcard matching
- Admin API policy export endpoint

### Config Files to Create
- `config/safe_headers.yaml` (configurable exclusions)
- `config/credential_guard.yaml` (main config)
- `/app/data/runtime_approvals.json` (runtime state)

### Testing Strategy
- Unit tests for header analysis, entropy heuristics
- Integration tests for 428 responses
- Test approval workflow (ntfy mock)
- Test policy merge logic
- Test path matching (wildcard, query string stripping)

---

## Future Enhancements (Not in Initial Scope)

1. **GitHub PR approval backend**
   - Agent creates PR with policy snippet
   - Human reviews/merges PR
   - Proxy polls for policy file updates

2. **LLM-assisted approval**
   - Claude reviews approval requests with project context
   - Recommends approve/deny
   - Human has final say

3. **Per-project policy files**
   - Each project has own policy.yaml
   - Mounted read-only to containers

4. **Approval quotas**
   - Limit N approvals per day/week
   - Prevent runaway costs

5. **Intent binding**
   - Agent explains "why" in approval request
   - Human approves purpose, not just destination

---

## Success Criteria

**Phase 1 (Ntfy approval):**
- ✅ Smart header analysis catches unknown credentials
- ✅ Default policy allows OpenAI/Anthropic/GitHub without prompts
- ✅ 428 greylist responses guide agent behavior
- ✅ Ntfy notifications work on watch/phone
- ✅ Approval via phone adds to runtime policy
- ✅ Manual export to safeyolo_policy.yaml works
- ✅ No credential leakage in logs/responses

**Phase 2 (PR approval):**
- ✅ Agent creates PR with policy snippet
- ✅ Human reviews/merges PR
- ✅ Proxy reloads policy on file change
- ✅ Same 428 format works for both workflows

---

## Decisions Log

| Decision | Rationale |
|----------|-----------|
| Files not SQLite | One writer, small dataset, simpler code |
| Configurable policy directory | Solo: ~/.safeyolo/; Teams: set SAFEYOLO_POLICY_DIR |
| No source code access | Encourages adoption, clean separation |
| No Agent API | Not needed, simplifies security |
| No approval timeout | Agent gives up, not proxy; supports PR workflow |
| HMAC fingerprinting | Never store raw credentials |
| Default policy | Zero friction for common services |
| Configurable safe headers | Cloud trace IDs vary by provider |
| 428 not 403 | Gives agent guidance, supports reflection |
| Two types of 428 | Self-correct vs wait-for-approval |
| Ntfy → PR progression | Solo devs first, team-ready later |

---

**Document Version:** 1.1
**Last Updated:** 2025-01-02
**Status:** Design Complete, Ready for Implementation
**Changes in v1.1:** Simplified policy storage to configurable directory (no complex API sync)
