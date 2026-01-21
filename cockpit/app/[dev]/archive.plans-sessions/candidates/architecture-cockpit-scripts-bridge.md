# Cockpit Scripts Bridge Architecture

> Design considerations and implementation snippets for the Wails3 cockpit that monitors and controls bun/python scripts.

## Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Wails3 Cockpit App                              │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                    WebView (Lit Web Components)                   │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐  │  │
│  │  │  ScriptTile │ │  ScriptTile │ │  ScriptTile │ │  ScriptTile │  │  │
│  │  │  (python)   │ │   (bun)     │ │  (sysmon)   │ │   (bun)     │  │  │
│  │  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘ └──────┬──────┘  │  │
│  │         │               │               │               │         │  │
│  └─────────┼───────────────┼───────────────┼───────────────┼─────────┘  │
│            │               │               │               │            │
│  ┌─────────▼───────────────▼───────────────▼───────────────▼─────────┐  │
│  │                     Go Bridge Layer                               │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐ │  │
│  │  │ ScriptRegistry│  │ WebSocket Hub│  │ Direct Stdio (fallback) │ │  │
│  │  └──────────────┘  └──────────────┘  └──────────────────────────┘ │  │
│  └───────────────────────────┬───────────────────────────────────────┘  │
└──────────────────────────────┼──────────────────────────────────────────┘
                               │
           ┌───────────────────┼───────────────────┐
           │                   │                   │
           ▼                   ▼                   ▼
    ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
    │ Bun Script  │     │Python Script│     │ CLI-Started │
    │ (connects)  │     │ (connects)  │     │   Script    │
    └─────────────┘     └─────────────┘     └─────────────┘
```

---

## 1. Communication Protocol Recommendation

### Primary: WebSocket with JSON-RPC-like Messages

**Why WebSocket over alternatives:**
- **vs REST**: Bidirectional streaming needed for stdout/stderr
- **vs SSE**: Scripts need to receive commands too (start, stop, input)
- **vs gRPC**: Heavier dependency, websocket is browser-native
- **vs Unix sockets**: Need network bridge for flexibility

**Message Protocol:**
```typescript
// Shared message types (both Go and TS should mirror these)
interface CockpitMessage {
  type: 'register' | 'output' | 'status' | 'command' | 'heartbeat';
  scriptId: string;
  timestamp: number;
  payload: unknown;
}

interface RegisterPayload {
  name: string;
  catalogEntry: string;  // reference to catalog TOML key
  pid?: number;
  capabilities: ('stdin' | 'signals' | 'metrics')[];
}

interface OutputPayload {
  stream: 'stdout' | 'stderr' | 'structured';
  data: string;
  sequence: number;  // for ordering
}

interface StatusPayload {
  state: 'starting' | 'running' | 'paused' | 'stopping' | 'stopped' | 'error';
  exitCode?: number;
  error?: string;
}

interface CommandPayload {
  action: 'start' | 'stop' | 'pause' | 'resume' | 'stdin' | 'signal';
  data?: string;
}
```

### Secondary: Direct stdio for Housekeeping Scripts

For scripts that must work without network (doctor/diagnostic):
- Go spawns process directly
- Captures stdout/stderr via pipes
- Emits to frontend via Wails events

---

## 2. Script Catalog Format (TOML)

```toml
# scripts/catalog.toml

[meta]
version = "1.0"
catalog_root = "./scripts"  # relative to this file

# ─────────────────────────────────────────────────────────────────
# Script Definitions
# ─────────────────────────────────────────────────────────────────

[scripts.safeyolo-status]
name = "SafeYolo Status"
description = "Check proxy health and active rules"
runtime = "bun"
entrypoint = "status/index.ts"
category = "diagnostics"
bridge = "websocket"  # or "direct" for stdio fallback

# UI component override (optional - defaults to base tile)
component = "script-tile-status"  # custom Lit element name

# Interaction capabilities
[scripts.safeyolo-status.capabilities]
stdin = false
signals = true
metrics = true

# Environment variables passed to script
[scripts.safeyolo-status.env]
COCKPIT_WS_URL = "${COCKPIT_WS_URL}"
SCRIPT_ID = "${SCRIPT_ID}"  # injected at launch

# ─────────────────────────────────────────────────────────────────

[scripts.log-tailer]
name = "Log Tailer"
description = "Stream proxy access logs"
runtime = "python"
entrypoint = "logtailer/main.py"
category = "monitoring"
bridge = "websocket"

[scripts.log-tailer.capabilities]
stdin = true   # accepts filter commands
signals = true
metrics = false

# ─────────────────────────────────────────────────────────────────

[scripts.doctor]
name = "System Doctor"
description = "Diagnose local setup issues"
runtime = "bun"
entrypoint = "doctor/index.ts"
category = "housekeeping"
bridge = "direct"  # <-- uses stdio, no network dependency

[scripts.doctor.capabilities]
stdin = false
signals = false
metrics = false
```

---

## 3. Go Bridge Layer

### 3.1 Script Registry Service

```go
// services/registry.go
package services

import (
	"sync"
	"time"
)

type ScriptState string

const (
	StateStarting ScriptState = "starting"
	StateRunning  ScriptState = "running"
	StateStopped  ScriptState = "stopped"
	StateError    ScriptState = "error"
)

type ScriptInstance struct {
	ID           string            `json:"id"`
	CatalogKey   string            `json:"catalogKey"`
	Name         string            `json:"name"`
	State        ScriptState       `json:"state"`
	PID          int               `json:"pid,omitempty"`
	StartedAt    time.Time         `json:"startedAt"`
	Capabilities []string          `json:"capabilities"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type ScriptRegistry struct {
	mu        sync.RWMutex
	instances map[string]*ScriptInstance
	onChange  func(instance *ScriptInstance) // notify frontend
}

func NewScriptRegistry(onChange func(*ScriptInstance)) *ScriptRegistry {
	return &ScriptRegistry{
		instances: make(map[string]*ScriptInstance),
		onChange:  onChange,
	}
}

// Register is called when a script connects via WebSocket
func (r *ScriptRegistry) Register(id string, info *ScriptInstance) {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	info.ID = id
	info.State = StateRunning
	info.StartedAt = time.Now()
	r.instances[id] = info
	
	if r.onChange != nil {
		r.onChange(info)
	}
}

// Unregister removes a script (disconnected or stopped)
func (r *ScriptRegistry) Unregister(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	if inst, ok := r.instances[id]; ok {
		inst.State = StateStopped
		if r.onChange != nil {
			r.onChange(inst)
		}
		delete(r.instances, id)
	}
}

// List returns all registered scripts
func (r *ScriptRegistry) List() []*ScriptInstance {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	result := make([]*ScriptInstance, 0, len(r.instances))
	for _, inst := range r.instances {
		result = append(result, inst)
	}
	return result
}

// Get returns a specific script instance
func (r *ScriptRegistry) Get(id string) (*ScriptInstance, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	inst, ok := r.instances[id]
	return inst, ok
}
```

### 3.2 WebSocket Hub

```go
// services/wshub.go
package services

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

type Message struct {
	Type      string          `json:"type"`
	ScriptID  string          `json:"scriptId"`
	Timestamp int64           `json:"timestamp"`
	Payload   json.RawMessage `json:"payload"`
}

type WSHub struct {
	mu       sync.RWMutex
	scripts  map[string]*websocket.Conn // script connections
	frontend *websocket.Conn            // single frontend conn (or use Wails events)
	registry *ScriptRegistry
}

func NewWSHub(registry *ScriptRegistry) *WSHub {
	return &WSHub{
		scripts:  make(map[string]*websocket.Conn),
		registry: registry,
	}
}

// HandleScript handles incoming script connections
func (h *WSHub) HandleScript(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"}, // tighten in production
	})
	if err != nil {
		log.Printf("websocket accept error: %v", err)
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	ctx := r.Context()
	var scriptID string

	for {
		var msg Message
		if err := wsjson.Read(ctx, conn, &msg); err != nil {
			log.Printf("read error: %v", err)
			break
		}

		switch msg.Type {
		case "register":
			scriptID = msg.ScriptID
			h.mu.Lock()
			h.scripts[scriptID] = conn
			h.mu.Unlock()

			var reg ScriptInstance
			json.Unmarshal(msg.Payload, &reg)
			h.registry.Register(scriptID, &reg)

		case "output", "status":
			// Forward to frontend via Wails event
			h.forwardToFrontend(msg)

		case "heartbeat":
			// Update last seen, respond with ack
		}
	}

	// Cleanup on disconnect
	if scriptID != "" {
		h.mu.Lock()
		delete(h.scripts, scriptID)
		h.mu.Unlock()
		h.registry.Unregister(scriptID)
	}
}

// SendToScript sends a command to a specific script
func (h *WSHub) SendToScript(scriptID string, msg Message) error {
	h.mu.RLock()
	conn, ok := h.scripts[scriptID]
	h.mu.RUnlock()

	if !ok {
		return ErrScriptNotConnected
	}

	return wsjson.Write(context.Background(), conn, msg)
}

func (h *WSHub) forwardToFrontend(msg Message) {
	// Option A: Use Wails event system
	// app.Event.Emit("script:message", msg)
	
	// Option B: WebSocket to frontend (if not using Wails events)
}

var ErrScriptNotConnected = errors.New("script not connected")
```

### 3.3 Direct Stdio Bridge (Fallback)

```go
// services/direct_runner.go
package services

import (
	"bufio"
	"context"
	"io"
	"os/exec"
	"sync"

	"github.com/wailsapp/wails/v3/pkg/application"
)

type DirectRunner struct {
	app      *application.App
	registry *ScriptRegistry
	procs    map[string]*exec.Cmd
	mu       sync.Mutex
}

func NewDirectRunner(app *application.App, registry *ScriptRegistry) *DirectRunner {
	return &DirectRunner{
		app:      app,
		registry: registry,
		procs:    make(map[string]*exec.Cmd),
	}
}

// RunDirect spawns a script and captures stdio
func (d *DirectRunner) RunDirect(ctx context.Context, scriptID string, runtime string, entrypoint string) error {
	var cmd *exec.Cmd
	
	switch runtime {
	case "bun":
		cmd = exec.CommandContext(ctx, "bun", "run", entrypoint)
	case "python":
		cmd = exec.CommandContext(ctx, "python", entrypoint)
	default:
		return ErrUnsupportedRuntime
	}

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return err
	}

	d.mu.Lock()
	d.procs[scriptID] = cmd
	d.mu.Unlock()

	// Register in registry
	d.registry.Register(scriptID, &ScriptInstance{
		CatalogKey:   scriptID,
		PID:          cmd.Process.Pid,
		Capabilities: []string{}, // direct mode has limited capabilities
	})

	// Stream stdout
	go d.streamPipe(scriptID, "stdout", stdout)
	go d.streamPipe(scriptID, "stderr", stderr)

	// Wait for completion
	go func() {
		err := cmd.Wait()
		d.mu.Lock()
		delete(d.procs, scriptID)
		d.mu.Unlock()
		
		status := "stopped"
		if err != nil {
			status = "error"
		}
		d.app.Event.Emit("script:status", map[string]any{
			"scriptId": scriptID,
			"state":    status,
			"exitCode": cmd.ProcessState.ExitCode(),
		})
		d.registry.Unregister(scriptID)
	}()

	return nil
}

func (d *DirectRunner) streamPipe(scriptID, stream string, pipe io.ReadCloser) {
	scanner := bufio.NewScanner(pipe)
	seq := 0
	for scanner.Scan() {
		d.app.Event.Emit("script:output", map[string]any{
			"scriptId": scriptID,
			"stream":   stream,
			"data":     scanner.Text(),
			"sequence": seq,
		})
		seq++
	}
}

// Stop terminates a directly-run script
func (d *DirectRunner) Stop(scriptID string) error {
	d.mu.Lock()
	cmd, ok := d.procs[scriptID]
	d.mu.Unlock()
	
	if !ok {
		return ErrScriptNotRunning
	}
	
	return cmd.Process.Kill()
}

var (
	ErrUnsupportedRuntime = errors.New("unsupported runtime")
	ErrScriptNotRunning   = errors.New("script not running")
)
```

### 3.4 Wails Service Integration

```go
// services/cockpit_service.go
package services

import (
	"context"

	"github.com/wailsapp/wails/v3/pkg/application"
)

// CockpitService exposes methods to the frontend
type CockpitService struct {
	app      *application.App
	catalog  *CatalogLoader
	registry *ScriptRegistry
	hub      *WSHub
	direct   *DirectRunner
}

// --- Methods exposed to frontend via Wails bindings ---

// ListScripts returns all registered script instances
func (s *CockpitService) ListScripts() []*ScriptInstance {
	return s.registry.List()
}

// GetCatalog returns available scripts from catalog.toml
func (s *CockpitService) GetCatalog() []CatalogEntry {
	return s.catalog.Entries()
}

// StartScript launches a script from catalog
func (s *CockpitService) StartScript(catalogKey string) (string, error) {
	entry, err := s.catalog.Get(catalogKey)
	if err != nil {
		return "", err
	}

	scriptID := generateScriptID(catalogKey)

	if entry.Bridge == "direct" {
		// Use stdio bridge
		err = s.direct.RunDirect(context.Background(), scriptID, entry.Runtime, entry.Entrypoint)
	} else {
		// Launch script which will connect via WebSocket
		err = s.launchNetworkedScript(scriptID, entry)
	}

	return scriptID, err
}

// StopScript stops a running script
func (s *CockpitService) StopScript(scriptID string) error {
	inst, ok := s.registry.Get(scriptID)
	if !ok {
		return ErrScriptNotRunning
	}

	// Check if direct or networked
	if inst.Metadata["bridge"] == "direct" {
		return s.direct.Stop(scriptID)
	}

	// Send stop command via WebSocket
	return s.hub.SendToScript(scriptID, Message{
		Type:     "command",
		ScriptID: scriptID,
		Payload:  []byte(`{"action":"stop"}`),
	})
}

// SendInput sends stdin data to a script (if capable)
func (s *CockpitService) SendInput(scriptID string, data string) error {
	return s.hub.SendToScript(scriptID, Message{
		Type:     "command",
		ScriptID: scriptID,
		Payload:  []byte(`{"action":"stdin","data":"` + data + `"}`),
	})
}

func (s *CockpitService) launchNetworkedScript(scriptID string, entry *CatalogEntry) error {
	// Implementation: spawn process with env vars pointing to WS endpoint
	// Script is responsible for connecting back
	return nil
}

func generateScriptID(catalogKey string) string {
	return catalogKey + "-" + randomSuffix()
}
```

---

## 4. Web Components (Lit)

### 4.1 Base Script Tile

```typescript
// frontend/src/components/script-tile-base.ts
import { LitElement, html, css, PropertyValues } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { Events } from '@wailsio/runtime';

export interface ScriptInstance {
  id: string;
  catalogKey: string;
  name: string;
  state: 'starting' | 'running' | 'paused' | 'stopped' | 'error';
  capabilities: string[];
  startedAt: string;
}

export interface OutputLine {
  stream: 'stdout' | 'stderr' | 'structured';
  data: string;
  sequence: number;
}

@customElement('script-tile-base')
export class ScriptTileBase extends LitElement {
  static styles = css`
    :host {
      display: block;
      border: 1px solid var(--tile-border, #333);
      border-radius: 8px;
      background: var(--tile-bg, #1a1a2e);
      padding: 1rem;
      min-height: 200px;
    }

    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.5rem;
    }

    .title {
      font-weight: 600;
      color: var(--tile-title, #e0e0e0);
    }

    .status {
      font-size: 0.75rem;
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
    }

    .status[data-state="running"] { background: #2d5a27; }
    .status[data-state="stopped"] { background: #5a2727; }
    .status[data-state="starting"] { background: #5a5327; }
    .status[data-state="error"] { background: #5a1a1a; }

    .output {
      font-family: monospace;
      font-size: 0.8rem;
      background: #0d0d14;
      padding: 0.5rem;
      border-radius: 4px;
      max-height: 150px;
      overflow-y: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }

    .output-line { margin: 0; }
    .output-line[data-stream="stderr"] { color: #ff6b6b; }
    .output-line[data-stream="stdout"] { color: #a0e0a0; }

    .controls {
      display: flex;
      gap: 0.5rem;
      margin-top: 0.5rem;
    }

    button {
      padding: 0.25rem 0.75rem;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 0.8rem;
    }

    button.stop { background: #5a2727; color: white; }
    button.start { background: #2d5a27; color: white; }
  `;

  @property({ type: Object }) instance!: ScriptInstance;
  @property({ type: Number }) maxLines = 100;

  @state() private outputLines: OutputLine[] = [];
  @state() private currentState: string = 'stopped';

  private unsubscribers: (() => void)[] = [];

  connectedCallback(): void {
    super.connectedCallback();
    this.subscribeToEvents();
    this.currentState = this.instance?.state || 'stopped';
  }

  disconnectedCallback(): void {
    super.disconnectedCallback();
    this.unsubscribers.forEach(unsub => unsub());
  }

  protected subscribeToEvents(): void {
    // Subscribe to Wails events for this script
    const outputUnsub = Events.On('script:output', (event: any) => {
      if (event.scriptId === this.instance?.id) {
        this.handleOutput(event);
      }
    });

    const statusUnsub = Events.On('script:status', (event: any) => {
      if (event.scriptId === this.instance?.id) {
        this.handleStatus(event);
      }
    });

    this.unsubscribers.push(outputUnsub, statusUnsub);
  }

  protected handleOutput(event: OutputLine): void {
    this.outputLines = [...this.outputLines, event].slice(-this.maxLines);
  }

  protected handleStatus(event: { state: string }): void {
    this.currentState = event.state;
  }

  protected async handleStop(): Promise<void> {
    const { CockpitService } = await import('../../bindings/services');
    await CockpitService.StopScript(this.instance.id);
  }

  protected render() {
    return html`
      <div class="header">
        <span class="title">${this.instance?.name || 'Unknown'}</span>
        <span class="status" data-state=${this.currentState}>${this.currentState}</span>
      </div>
      
      <div class="output">
        ${this.outputLines.map(line => html`
          <p class="output-line" data-stream=${line.stream}>${line.data}</p>
        `)}
      </div>

      <div class="controls">
        ${this.renderControls()}
      </div>
    `;
  }

  protected renderControls() {
    if (this.currentState === 'running') {
      return html`<button class="stop" @click=${this.handleStop}>Stop</button>`;
    }
    return html`<button class="start" disabled>Stopped</button>`;
  }
}
```

### 4.2 Cockpit Dashboard

```typescript
// frontend/src/components/cockpit-dashboard.ts
import { LitElement, html, css } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { Events } from '@wailsio/runtime';
import type { ScriptInstance } from './script-tile-base.js';
import './script-tile-base.js';

interface CatalogEntry {
  key: string;
  name: string;
  description: string;
  category: string;
}

@customElement('cockpit-dashboard')
export class CockpitDashboard extends LitElement {
  static styles = css`
    :host {
      display: block;
      padding: 1rem;
      background: #0f0f1a;
      min-height: 100vh;
    }

    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
    }

    h1 {
      color: #e0e0e0;
      margin: 0;
      font-size: 1.5rem;
    }

    .catalog-launcher {
      display: flex;
      gap: 0.5rem;
    }

    .catalog-launcher select {
      padding: 0.5rem;
      border-radius: 4px;
      background: #1a1a2e;
      color: #e0e0e0;
      border: 1px solid #333;
    }

    .catalog-launcher button {
      padding: 0.5rem 1rem;
      background: #2d5a27;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
    }

    .tiles {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
      gap: 1rem;
    }

    .empty-state {
      color: #666;
      text-align: center;
      padding: 2rem;
    }
  `;

  @state() private scripts: ScriptInstance[] = [];
  @state() private catalog: CatalogEntry[] = [];
  @state() private selectedCatalogKey = '';

  async connectedCallback(): Promise<void> {
    super.connectedCallback();
    await this.loadInitialState();
    this.subscribeToUpdates();
  }

  private async loadInitialState(): Promise<void> {
    const { CockpitService } = await import('../../bindings/services');
    this.scripts = await CockpitService.ListScripts();
    this.catalog = await CockpitService.GetCatalog();
    if (this.catalog.length > 0) {
      this.selectedCatalogKey = this.catalog[0].key;
    }
  }

  private subscribeToUpdates(): void {
    Events.On('script:registered', (script: ScriptInstance) => {
      this.scripts = [...this.scripts, script];
    });

    Events.On('script:unregistered', (event: { scriptId: string }) => {
      this.scripts = this.scripts.filter(s => s.id !== event.scriptId);
    });
  }

  private async handleLaunch(): Promise<void> {
    if (!this.selectedCatalogKey) return;
    
    const { CockpitService } = await import('../../bindings/services');
    await CockpitService.StartScript(this.selectedCatalogKey);
  }

  render() {
    return html`
      <div class="header">
        <h1>SafeYolo Cockpit</h1>
        <div class="catalog-launcher">
          <select @change=${(e: Event) => this.selectedCatalogKey = (e.target as HTMLSelectElement).value}>
            ${this.catalog.map(entry => html`
              <option value=${entry.key}>${entry.name}</option>
            `)}
          </select>
          <button @click=${this.handleLaunch}>Launch</button>
        </div>
      </div>

      <div class="tiles">
        ${this.scripts.length === 0 
          ? html`<div class="empty-state">No scripts running. Launch one from the catalog.</div>`
          : this.scripts.map(script => html`
              <script-tile-base .instance=${script}></script-tile-base>
            `)
        }
      </div>
    `;
  }
}
```

### 4.3 Custom Tile Example (Extending Base)

```typescript
// frontend/src/components/script-tile-status.ts
// Custom tile for scripts that emit structured metrics

import { html, css } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { ScriptTileBase, OutputLine } from './script-tile-base.js';

interface MetricsData {
  requestsPerSec: number;
  activeConnections: number;
  blockedRequests: number;
}

@customElement('script-tile-status')
export class ScriptTileStatus extends ScriptTileBase {
  static styles = [
    ScriptTileBase.styles,
    css`
      .metrics {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 0.5rem;
        margin-bottom: 0.5rem;
      }

      .metric {
        background: #1a2a1a;
        padding: 0.5rem;
        border-radius: 4px;
        text-align: center;
      }

      .metric-value {
        font-size: 1.5rem;
        font-weight: bold;
        color: #4ade80;
      }

      .metric-label {
        font-size: 0.7rem;
        color: #888;
      }
    `
  ];

  @state() private metrics: MetricsData = {
    requestsPerSec: 0,
    activeConnections: 0,
    blockedRequests: 0
  };

  protected handleOutput(event: OutputLine): void {
    if (event.stream === 'structured') {
      try {
        this.metrics = JSON.parse(event.data);
      } catch {
        super.handleOutput(event);
      }
    } else {
      super.handleOutput(event);
    }
  }

  protected render() {
    return html`
      <div class="header">
        <span class="title">${this.instance?.name || 'Status Monitor'}</span>
        <span class="status" data-state=${this.currentState}>${this.currentState}</span>
      </div>

      <div class="metrics">
        <div class="metric">
          <div class="metric-value">${this.metrics.requestsPerSec}</div>
          <div class="metric-label">req/s</div>
        </div>
        <div class="metric">
          <div class="metric-value">${this.metrics.activeConnections}</div>
          <div class="metric-label">connections</div>
        </div>
        <div class="metric">
          <div class="metric-value">${this.metrics.blockedRequests}</div>
          <div class="metric-label">blocked</div>
        </div>
      </div>

      <div class="output">
        ${this.outputLines.slice(-5).map(line => html`
          <p class="output-line" data-stream=${line.stream}>${line.data}</p>
        `)}
      </div>

      <div class="controls">
        ${this.renderControls()}
      </div>
    `;
  }
}
```

---

## 5. Script-Side Integration

### 5.1 Bun Script Template

```typescript
// scripts/template-bun/cockpit-client.ts
// Reusable client for bun scripts to connect to cockpit

const COCKPIT_WS_URL = process.env.COCKPIT_WS_URL || 'ws://localhost:34115/ws';
const SCRIPT_ID = process.env.SCRIPT_ID || 'unknown';
const CATALOG_KEY = process.env.CATALOG_KEY || 'unknown';

class CockpitClient {
  private ws: WebSocket | null = null;
  private sequence = 0;

  async connect(): Promise<void> {
    this.ws = new WebSocket(COCKPIT_WS_URL);
    
    await new Promise<void>((resolve, reject) => {
      this.ws!.onopen = () => {
        this.register();
        resolve();
      };
      this.ws!.onerror = reject;
    });

    this.ws.onmessage = (event) => this.handleMessage(JSON.parse(event.data));
  }

  private register(): void {
    this.send({
      type: 'register',
      scriptId: SCRIPT_ID,
      timestamp: Date.now(),
      payload: {
        name: 'Script Name', // Override in actual script
        catalogEntry: CATALOG_KEY,
        pid: process.pid,
        capabilities: ['stdin', 'signals']
      }
    });
  }

  private handleMessage(msg: any): void {
    if (msg.type === 'command') {
      const { action, data } = msg.payload;
      switch (action) {
        case 'stop':
          this.cleanup();
          process.exit(0);
          break;
        case 'stdin':
          // Emit to script's stdin handler
          this.onInput?.(data);
          break;
      }
    }
  }

  stdout(data: string): void {
    this.send({
      type: 'output',
      scriptId: SCRIPT_ID,
      timestamp: Date.now(),
      payload: { stream: 'stdout', data, sequence: this.sequence++ }
    });
  }

  stderr(data: string): void {
    this.send({
      type: 'output',
      scriptId: SCRIPT_ID,
      timestamp: Date.now(),
      payload: { stream: 'stderr', data, sequence: this.sequence++ }
    });
  }

  // For structured data (metrics, JSON)
  structured(data: object): void {
    this.send({
      type: 'output',
      scriptId: SCRIPT_ID,
      timestamp: Date.now(),
      payload: { stream: 'structured', data: JSON.stringify(data), sequence: this.sequence++ }
    });
  }

  status(state: string, exitCode?: number): void {
    this.send({
      type: 'status',
      scriptId: SCRIPT_ID,
      timestamp: Date.now(),
      payload: { state, exitCode }
    });
  }

  private send(msg: object): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(msg));
    }
  }

  onInput?: (data: string) => void;

  cleanup(): void {
    this.status('stopping');
    this.ws?.close();
  }
}

export const cockpit = new CockpitClient();

// Usage in actual script:
// await cockpit.connect();
// cockpit.stdout('Processing started...');
// cockpit.structured({ requestsPerSec: 42 });
```

### 5.2 Python Script Template

```python
# scripts/template-python/cockpit_client.py
# Reusable client for Python scripts to connect to cockpit

import os
import json
import asyncio
import websockets
from typing import Callable, Optional

COCKPIT_WS_URL = os.environ.get('COCKPIT_WS_URL', 'ws://localhost:34115/ws')
SCRIPT_ID = os.environ.get('SCRIPT_ID', 'unknown')
CATALOG_KEY = os.environ.get('CATALOG_KEY', 'unknown')


class CockpitClient:
    def __init__(self, name: str, capabilities: list[str] = None):
        self.name = name
        self.capabilities = capabilities or ['signals']
        self.ws: Optional[websockets.WebSocketClientProtocol] = None
        self.sequence = 0
        self.on_input: Optional[Callable[[str], None]] = None
        self._running = True

    async def connect(self):
        self.ws = await websockets.connect(COCKPIT_WS_URL)
        await self._register()
        asyncio.create_task(self._listen())

    async def _register(self):
        await self._send({
            'type': 'register',
            'scriptId': SCRIPT_ID,
            'timestamp': self._timestamp(),
            'payload': {
                'name': self.name,
                'catalogEntry': CATALOG_KEY,
                'pid': os.getpid(),
                'capabilities': self.capabilities
            }
        })

    async def _listen(self):
        async for message in self.ws:
            msg = json.loads(message)
            if msg['type'] == 'command':
                action = msg['payload'].get('action')
                if action == 'stop':
                    self._running = False
                    await self.cleanup()
                elif action == 'stdin' and self.on_input:
                    self.on_input(msg['payload'].get('data', ''))

    async def stdout(self, data: str):
        await self._send({
            'type': 'output',
            'scriptId': SCRIPT_ID,
            'timestamp': self._timestamp(),
            'payload': {'stream': 'stdout', 'data': data, 'sequence': self._next_seq()}
        })

    async def stderr(self, data: str):
        await self._send({
            'type': 'output',
            'scriptId': SCRIPT_ID,
            'timestamp': self._timestamp(),
            'payload': {'stream': 'stderr', 'data': data, 'sequence': self._next_seq()}
        })

    async def structured(self, data: dict):
        await self._send({
            'type': 'output',
            'scriptId': SCRIPT_ID,
            'timestamp': self._timestamp(),
            'payload': {'stream': 'structured', 'data': json.dumps(data), 'sequence': self._next_seq()}
        })

    async def status(self, state: str, exit_code: int = None):
        payload = {'state': state}
        if exit_code is not None:
            payload['exitCode'] = exit_code
        await self._send({
            'type': 'status',
            'scriptId': SCRIPT_ID,
            'timestamp': self._timestamp(),
            'payload': payload
        })

    async def _send(self, msg: dict):
        if self.ws:
            await self.ws.send(json.dumps(msg))

    async def cleanup(self):
        await self.status('stopping')
        if self.ws:
            await self.ws.close()

    def _timestamp(self) -> int:
        import time
        return int(time.time() * 1000)

    def _next_seq(self) -> int:
        seq = self.sequence
        self.sequence += 1
        return seq

    @property
    def running(self) -> bool:
        return self._running


# Usage:
# client = CockpitClient('Log Tailer', ['stdin', 'signals'])
# await client.connect()
# await client.stdout('Tailing logs...')
# while client.running:
#     await client.structured({'lines_processed': count})
```

---

## 6. Integration Conventions

### 6.1 Script Development Workflow

1. **Create catalog entry** in `scripts/catalog.toml`
2. **Create script** using template client (`cockpit-client.ts` or `cockpit_client.py`)
3. **Optionally create custom tile** extending `ScriptTileBase` if special UI needed
4. **Register custom tile** in catalog with `component = "your-tile-name"`

### 6.2 CLI-Started Scripts

Scripts started from CLI should:
1. Check for `COCKPIT_WS_URL` env var
2. If present, connect and register
3. If absent, fall back to normal stdout/stderr

```typescript
// In bun script
if (process.env.COCKPIT_WS_URL) {
  await cockpit.connect();
  cockpit.stdout('Connected to cockpit');
} else {
  console.log('Running standalone (no cockpit)');
}
```

### 6.3 Dependency Choices

| Need | Recommendation | Rationale |
|------|----------------|-----------|
| WebSocket (Go) | `github.com/coder/websocket` | Stdlib-like, well maintained, no gorilla/websocket |
| WebSocket (Bun) | Native `WebSocket` | Built-in |
| WebSocket (Python) | `websockets` | Minimal, asyncio-native |
| TOML parsing (Go) | `github.com/BurntSushi/toml` | De facto standard |
| Web Components | `lit` | Already in use, minimal |
| UI framework | None (custom CSS) | Minimize deps |

### 6.4 Port/Endpoint Configuration

```toml
# config/cockpit.toml
[server]
ws_port = 34115           # WebSocket for script connections
ws_path = "/ws"

[scripts]
catalog_path = "./scripts/catalog.toml"
```

---

## 7. Security Considerations

- **Script isolation**: Scripts run as separate processes, no shared memory
- **WebSocket auth**: Consider adding token-based auth for script registration
- **Catalog validation**: Validate entrypoints exist before launch
- **Resource limits**: Consider cgroups/ulimits for spawned scripts

---

## 8. Open Questions / Decisions Needed

1. **Single vs multiple frontend WebSocket connections?**
   - Current design uses Wails events (no separate WS to frontend)
   - Alternative: dedicated WS for lower latency

2. **Script discovery for CLI-launched scripts?**
   - Option A: Scripts always connect to known port
   - Option B: mDNS/Bonjour discovery
   - Option C: Shared file/socket for port discovery

3. **Persistence of script state?**
   - Should registry survive app restart?
   - SQLite vs in-memory?

4. **Authentication for scripts?**
   - Pre-shared tokens in catalog?
   - Certificate-based?
