# Wails3 Cockpit - Quick Reference

**Date**: 2026-01-21

## Recommended Architecture (TL;DR)

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| **Primary Bridge** | HTTP + SSE | Native browser support, Go stdlib only |
| **Backup Bridge** | Stdio | Offline mode for doctor scripts |
| **Web UI** | Lit WebComponents | Minimal deps, easy to generate |
| **Catalog** | TOML | Human-readable, easy to parse |
| **Script Types** | Bun, Python, Shell | Cover all common use cases |

---

## Directory Structure

```
cockpit/app/
├── internal/cockpit/
│   ├── manager.go         # ProcessManager (script lifecycle)
│   ├── sse.go             # SSEEmitter (streaming to UI)
│   ├── http.go            # HTTP handlers (script registration)
│   └── stdio_bridge.go    # Stdio bridge (offline mode)
├── scripts/
│   ├── catalog.toml       # Script definitions
│   ├── scripts/
│   │   ├── backup-db/
│   │   │   ├── main.ts
│   │   │   └── metadata.toml
│   │   └── health-check/
│   │       ├── main.py
│   │       └── metadata.toml
│   ├── lib/
│   │   ├── bridge.ts      # TypeScript bridge client
│   │   └── bridge.py      # Python bridge client
│   └── templates/
│       ├── bun-script-template.ts
│       └── python-script-template.py
├── frontend/src/
│   ├── components/
│   │   ├── script-tile.ts     # Individual script tile
│   │   └── cockpit-dashboard.ts # Main dashboard
│   └── lib/
│       └── sse-client.ts     # Minimal SSE client
└── main.go                   # Wails3 entry point
```

---

## Key Bridge Patterns

### Pattern 1: HTTP + SSE (Primary)

```
Script ──POST /api/script/register──► Go Bridge
Script ──POST /api/script/log──────► Go Bridge
Go Bridge ──SSE /api/stream──────────► UI
```

**Use for**: All scripts that have network access

**Implementation**: See `internal/cockpit/http.go`, `internal/cockpit/sse.go`

---

### Pattern 2: Stdio (Offline/Doctor)

```
Script ──stdout (JSON)─────────────► Go Bridge
Script ◄────stdin (if interactive)─────┤
Go Bridge ──SSE /api/stream──────────► UI
```

**Use for**: Scripts that must work offline (doctor, housekeeping)

**Implementation**: See `internal/cockpit/stdio_bridge.go`

---

## Script Catalog Example

```toml
# scripts/catalog.toml
[[script]]
id = "backup-db"
name = "Database Backup"
type = "bun"
entry = "scripts/scripts/backup-db/main.ts"
protocol = "http_sse"
run_mode = "oneshot"
tags = ["maintenance", "daily"]

[[script]]
id = "doctor"
name = "System Doctor"
type = "shell"
entry = "scripts/scripts/doctor/main.sh"
protocol = "stdio"
run_mode = "oneshot"
offline_capable = true
```

---

## Script Registration Workflow

### From UI Catalog
```
UI ──POST /api/script/start──► Go Bridge
Go Bridge ──exec script────────► Process
Process ──ENV: COCKPIT_*─────► Script
Script ──POST /register──────► Go Bridge
Go Bridge ──SSE: "started"───► UI
```

### From CLI (External)
```
User runs: COCKPIT_SCRIPT_ID=my-script ./script.sh
Script ──POST /api/script/register──► Go Bridge
Go Bridge ──SSE: "started"──────────► UI
```

---

## Bridge Client Usage

### Bun Script

```typescript
import { ScriptBridge } from '../lib/bridge.js'

const bridge = new ScriptBridge({
  scriptId: process.env.COCKPIT_SCRIPT_ID,
  protocol: 'http',
})

await bridge.register()
bridge.log('stdout', 'Starting...')
```

### Python Script

```python
from lib.bridge import ScriptBridge
import os

bridge = ScriptBridge(
    script_id=os.getenv('COCKPIT_SCRIPT_ID'),
    protocol='http',
)

bridge.register()
bridge.log('stdout', 'Starting...')
```

---

## Web Component Usage

### In Dashboard

```html
<cockpit-dashboard>
  <!-- Automatically renders script tiles -->
</cockpit-dashboard>
```

### Individual Tile

```html
<script-tile
  script-id="backup-db"
  script-name="Database Backup"
  script-type="bun">
</script-tile>
```

---

## Minimal Dependencies

| Layer | Dependencies |
|-------|--------------|
| Go | Wails3, go-toml (stdlib only otherwise) |
| UI | Lit (via bun), @wailsio/runtime |
| Bun Scripts | Bun runtime (built-in fetch) |
| Python Scripts | Python stdlib (urllib) |

---

## Critical Files

- `internal/cockpit/manager.go` - Script lifecycle management
- `internal/cockpit/sse.go` - Real-time streaming to UI
- `scripts/lib/bridge.ts` - TypeScript bridge client
- `scripts/lib/bridge.py` - Python bridge client
- `frontend/src/components/script-tile.ts` - Script display component
- `frontend/src/components/cockpit-dashboard.ts` - Main dashboard
- `scripts/catalog.toml` - Script definitions

---

## Environment Variables (for Scripts)

- `COCKPIT_SCRIPT_ID` - Unique script identifier
- `COCKPIT_BRIDGE_PROTOCOL` - http | stdio
- `COCKPIT_BRIDGE_URL` - Bridge endpoint URL (default: http://localhost:34115)
- `COCKPIT_HEARTBEAT_INTERVAL` - Seconds between heartbeats
- `COCKPIT_LOG_BATCH_SIZE` - Lines to batch before sending

---

## Security Notes

1. Run scripts as separate processes (isolated)
2. Add shared secret for HTTP endpoints (future)
3. Validate all script IDs and parameters
4. Consider rate limiting HTTP endpoints
5. Containerize untrusted scripts (future)

---

## See Full Architecture

For detailed explanations and complete code snippets, see:
`docs/wails3-cockpit-architecture.md`
