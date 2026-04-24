# SafeYolo Security Audit (pre-v1)

**Auditor:** Claude (red-team analyst role)
**Date:** 2026-04-24
**Branch audited:** `master` @ 826db59 (PR #196 tip)
**Audit branch:** `claude/security-audit-safeyolo-BdT1N`

## Scope

Per operator direction:

- **A** Host-side privileged operations (sudo, setuid, capabilities)
- **B** Sandbox escape surface (gVisor OCI spec, userns, caps, mounts, AppArmor, macOS VZ entitlements)
- **D** Supply chain (build scripts, host scripts, rootfs hooks, dependency pinning)
- **Out of scope:** (C) Proxy/PDP logic (credential detection, policy eval, admin API auth) — except where it touches A/B/D

**Threat model:** honest operator + malicious agent inside the sandbox. Focus: undocumented gaps and regressions; pre-v1 design-level issues flagged but not weighted.

## Method

1. Enumerate every privileged operation on the host (grep for sudo/setuid/cap/chmod/chown).
2. Read each path end-to-end; assess blast radius.
3. Diff against recent PRs (#187, #190, #194, #195, #196) for regressions introduced by the OCI/userns rework and rootfs unification.
4. PoC only when the path "looks safe but isn't" or is too complex to assess by inspection.

## Status

| Section | Status |
|---------|--------|
| 1. Privileged-op catalog (A) | pending |
| 2. `safeyolo setup` review (A) | pending |
| 3. Linux sandbox: userns/OCI/caps/mounts (B) | pending |
| 4. Proxy bridge / identity attribution (B) | pending |
| 5. macOS VM helper + entitlements (B) | pending |
| 6. Guest-init and config share (B) | pending |
| 7. Supply chain: builds, host scripts, rootfs hooks (D) | pending |
| 8. Dependency pinning (D) | pending |
| 9. Regression diff: #187, #190, #194, #195, #196 | pending |
| 10. Findings summary | pending |

## Findings

(findings will be appended here, classified Critical / High / Medium / Low / Informational, each with file:line refs and — where the path is complex — a PoC sketch)
