# Wails3 Cockpit - Architecture Considerations

**Date**: 2026-01-21
**Status**: Architectural Design Document

## Overview

Design considerations for a Wails3-based "cockpit" application that monitors and orchestrates Bun/Python/shell scripts on the host OS. The app provides a tile-based web UI for script management, supporting both UI-launched and CLI-launched scripts.

## Core Requirements

1. **Dual-script origin**: Scripts may be started from UI catalog or CLI
2. **Multiple script types**: Bun, Python, and shell scripts
3. **Execution modes**: One-shot tasks and long-running daemons
4. **Monitoring**: Real-time stdout/stderr streaming and status updates
5. **Bridge flexibility**: Network-based communication between scripts and UI
6. **Offline capability**: Some scripts must work without network connectivity
7. **Minimal dependencies**: Prefer core ecosystem packages
8. **No business logic in Go**: Go layer is pure interop/orchestration

---

## Bridge Protocol Considerations

### Option 1: HTTP + SSE (Recommended Primary)

**Pros:**
- Native browser support (no WebSocket libraries needed)
- Simple unidirectional streaming from Go to UI
- Easy to implement with Go stdlib only
- Automatic reconnection handling by browser
- Works well with CORS if needed

**Cons:**
- Only server-to-client streaming
- Client-to-server requires separate HTTP endpoints
- Less efficient for bidirectional high-frequency communication

**Best for:**
- Log streaming (Go → UI)
- Status updates (Go → UI)
- Script registration/discovery (Script → Go via HTTP POST)

---

### Option 2: WebSocket

**Pros:**
- Full duplex communication
- Lower overhead for frequent bidirectional messaging
- Single connection per tile

**Cons:**
- Requires external dependency (gorilla/websocket or similar)
- More complex reconnection logic
- Overkill for simple log streaming

**Best for:**
- Interactive scripts requiring user input
- Scripts with high-frequency control messages

---

### Option 3: Unix Domain Sockets (UDS) + stdio

**Pros:**
- No network overhead (pure local IPC)
- Fast and efficient
- Works without network stack
- Go stdlib only

**Cons:**
- Requires script to be Go-aware
- Cannot be used by arbitrary CLI scripts
- Browser cannot directly connect (requires Go proxy)

**Best for:**
- Doctor/housekeeping bridge (offline mode)
- Scripts that must work when network is down
- Local-only communication patterns

---

### Option 4: Named Pipes (Windows) / FIFO (Linux)

**Pros:**
- Simple file-like interface
- Works with shell tools easily

**Cons:**
- Platform-specific differences
- Blocking semantics can be tricky
- Not browser-accessible

**Best for:**
- Legacy script integration
- System app monitoring

---

## Recommended Hybrid Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Wails3 Desktop App                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │              Go Bridge Layer (Interop Only)         │  │
│  │                                                     │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────┐  │  │
│  │  │HTTP Handlers │  │SSE Emitter   │  │Stdio     │  │  │
│  │  │  (REST API)  │  │(Streaming)   │  │Bridge    │  │  │
│  │  └──────────────┘  └──────────────┘  └──────────┘  │  │
│  │          │                 │              │         │  │
│  │  ┌───────▼─────────────────▼──────────────▼──────┐  │  │
│  │  │          ProcessManager                       │  │  │
│  │  │  - Script lifecycle                          │  │  │
│  │  │  - PID tracking                              │  │  │
│  │  │  - Stdout/stderr capture                      │  │  │
│  │  │  - Catalog parsing                            │  │  │
│  │  └───────────────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────┘  │
│                           │                                  │
│  ┌────────────────────────┼──────────────────────────────┐  │
│  │                        │                              │  │
│  │  ┌─────────────────────▼──────────────────────┐     │  │
│  │  │         Web UI (Lit WebComponents)         │     │  │
│  │  │                                             │     │  │
│  │  │  ┌────────────┐  ┌────────────┐  ┌──────┐ │     │  │
│  │  │  │SSE Client  │  │HTTP Client │  │Tiles │ │     │  │
│  │  │  └────────────┘  └────────────┘  └──────┘ │     │  │
│  │  └─────────────────────────────────────────────┘     │  │
│  │                                                   │   │
│  └───────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                           │
                           │ 1. HTTP POST /api/script/register
                           │ 2. HTTP POST /api/script/log
                           │ 3. SSE /api/stream (Go → UI)
                           │ 4. Stdio (direct, offline mode)
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
   ┌────▼────┐      ┌──────▼──────┐    ┌──────▼──────┐
   │ Bun     │      │ Python      │    │ CLI Scripts│
   │ Scripts │      │ Scripts     │    │ (External) │
   └─────────┘      └─────────────┘    └─────────────┘
```

---

## Script Catalog Format

### Catalog Location

```
cockpit/app/
  scripts/
    catalog.toml         # Main catalog
    scripts/
      backup-db/
        main.ts           # Bun script entry
        metadata.toml     # Per-script override
      health-check/
        main.py           # Python script entry
        metadata.toml
```

### Catalog Schema (TOML)

```toml
# scripts/catalog.toml
version = "1.0"

# Script definitions
[[script]]
id = "backup-db"
name = "Database Backup"
description = "Runs daily backup of production database"
type = "bun"                          # bun | python | shell
entry = "scripts/scripts/backup-db/main.ts"
protocol = "http_sse"                 # http_sse | uds_stdio | file_watch
run_mode = "oneshot"                  # oneshot | daemon
tags = ["maintenance", "daily"]
category = "Database"

# Bridge configuration
[script.bridge]
heartbeat_interval = 30              # seconds (0 = disabled)
log_batch_size = 100                  # lines (0 = no batching)

[[script]]
id = "health-monitor"
name = "Health Monitor"
description = "Monitors system health metrics"
type = "python"
entry = "scripts/scripts/health-monitor/main.py"
protocol = "http_sse"
run_mode = "daemon"
tags = ["monitoring", "continuous"]
category = "System"

[script.bridge]
heartbeat_interval = 15
log_batch_size = 50

[[script]]
id = "doctor"
name = "System Doctor"
description = "Offline diagnostics and repairs"
type = "shell"
entry = "scripts/scripts/doctor/main.sh"
protocol = "stdio"                    # Must use stdio for offline
run_mode =oneshot
tags = ["maintenance", "critical"]
category = "System"
offline_capable = true               # Can run without network

# Protocol-specific config
[script.stdio]
input_format = "json_line"            # json_line | plain_text
output_format = "json_line"
```

---

## Go Bridge Layer - Key Components

### Process Manager

```go
// internal/cockpit/manager.go
package cockpit

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
)

// ScriptMetadata from catalog
type ScriptMetadata struct {
	ID          string `toml:"id"`
	Name        string `toml:"name"`
	Type        string `toml:"type"`        // bun | python | shell
	Entry       string `toml:"entry"`
	Protocol    string `toml:"protocol"`    // http_sse | stdio | file_watch
	RunMode     string `toml:"run_mode"`    // oneshot | daemon
	Tags        []string `toml:"tags"`
	Category    string `toml:"category"`
	OfflineCapable bool `toml:"offline_capable"`

	Bridge      BridgeConfig `toml:"bridge"`
	Stdio       StdioConfig  `toml:"stdio,omitempty"`
}

type BridgeConfig struct {
	HeartbeatInterval int `toml:"heartbeat_interval"`
	LogBatchSize      int `toml:"log_batch_size"`
}

type StdioConfig struct {
	InputFormat  string `toml:"input_format"`
	OutputFormat string `toml:"output_format"`
}

// Running script instance
type ScriptInstance struct {
	ID        string
	Metadata  ScriptMetadata
	PID       int
	Status    string // running | stopped | failed | completed
	StartedAt time.Time
	ExitCode  *int
	cmd       *exec.Cmd
	cancel    context.CancelFunc
}

// ProcessManager handles all script lifecycles
type ProcessManager struct {
	mu          sync.RWMutex
	instances   map[string]*ScriptInstance
	catalog     []ScriptMetadata
	sseEmitter  *SSEEmitter
	baseDir     string
}

// Load catalog from TOML
func (pm *ProcessManager) LoadCatalog(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read catalog: %w", err)
	}

	type Catalog struct {
		Version string           `toml:"version"`
		Scripts []ScriptMetadata `toml:"script"`
	}

	var cat Catalog
	if _, err := toml.Decode(string(data), &cat); err != nil {
		return fmt.Errorf("parse catalog: %w", err)
	}

	pm.mu.Lock()
	pm.catalog = cat.Scripts
	pm.mu.Unlock()

	return nil
}

// StartScript launches a script by ID
func (pm *ProcessManager) StartScript(scriptID string) (*ScriptInstance, error) {
	pm.mu.RLock()
	metadata, ok := pm.findMetadata(scriptID)
	pm.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("script not found: %s", scriptID)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Determine interpreter based on type
	var cmdArgs []string
	switch metadata.Type {
	case "bun":
		cmdArgs = []string{"bun", "run", metadata.Entry}
	case "python":
		cmdArgs = []string{"python3", metadata.Entry}
	case "shell":
		cmdArgs = []string{"bash", metadata.Entry}
	default:
		return nil, fmt.Errorf("unsupported script type: %s", metadata.Type)
	}

	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	cmd.Dir = pm.baseDir

	// Set environment for bridge communication
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("COCKPIT_SCRIPT_ID=%s", scriptID),
		fmt.Sprintf("COCKPIT_BRIDGE_PROTOCOL=%s", metadata.Protocol),
		fmt.Sprintf("COCKPIT_BRIDGE_URL=%s", getBridgeURL()),
	)

	instance := &ScriptInstance{
		ID:        scriptID,
		Metadata:  *metadata,
		PID:       cmd.Process.Pid,
		Status:    "running",
		StartedAt: time.Now(),
		cmd:       cmd,
		cancel:    cancel,
	}

	// Capture stdout/stderr for log streaming
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create stdout pipe: %w", err)
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create stderr pipe: %w", err)
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start command: %w", err)
	}

	// Start log streaming goroutines
	go pm.streamLogs(instance, stdoutPipe, "stdout")
	go pm.streamLogs(instance, stderrPipe, "stderr")

	// Track instance
	pm.mu.Lock()
	pm.instances[scriptID] = instance
	pm.mu.Unlock()

	// Notify UI via SSE
	pm.sseEmitter.EmitScriptEvent(ScriptEvent{
		Type:     "started",
		ScriptID: scriptID,
		Timestamp: time.Now(),
	})

	// Wait for completion in background
	go pm.waitForCompletion(instance)

	return instance, nil
}

func (pm *ProcessManager) streamLogs(instance *ScriptInstance, pipe io.Reader, stream string) {
	scanner := bufio.NewScanner(pipe)
	for scanner.Scan() {
		line := scanner.Text()

		// Emit log line via SSE
		pm.sseEmitter.EmitScriptEvent(ScriptEvent{
			Type:     "log",
			ScriptID: instance.ID,
			Stream:   stream,
			Line:     line,
			Timestamp: time.Now(),
		})
	}
}

func (pm *ProcessManager) waitForCompletion(instance *ScriptInstance) {
	err := instance.cmd.Wait()

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if err != nil {
		instance.Status = "failed"
	} else {
		instance.Status = "completed"
	}

	// Emit completion event
	pm.sseEmitter.EmitScriptEvent(ScriptEvent{
		Type:     "completed",
		ScriptID: instance.ID,
		Status:   instance.Status,
		ExitCode: instance.cmd.ProcessState.ExitCode(),
		Timestamp: time.Now(),
	})
}

func (pm *ProcessManager) findMetadata(scriptID string) (*ScriptMetadata, bool) {
	for i := range pm.catalog {
		if pm.catalog[i].ID == scriptID {
			return &pm.catalog[i], true
		}
	}
	return nil, false
}
```

### SSE Emitter

```go
// internal/cockpit/sse.go
package cockpit

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// ScriptEvent represents an event from script execution
type ScriptEvent struct {
	Type      string    `json:"type"`       // started, log, completed, failed, heartbeat
	ScriptID  string    `json:"script_id"`
	Stream    string    `json:"stream"`     // stdout | stderr
	Line      string    `json:"line,omitempty"`
	Status    string    `json:"status,omitempty"`
	ExitCode  *int      `json:"exit_code,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// SSEEmitter handles Server-Sent Events for script monitoring
type SSEEmitter struct {
	mu        sync.RWMutex
	clients   map[string]chan ScriptEvent
}

func NewSSEEmitter() *SSEEmitter {
	return &SSEEmitter{
		clients: make(map[string]chan ScriptEvent),
	}
}

// RegisterClient creates a new SSE connection
func (e *SSEEmitter) RegisterClient(clientID string) <-chan ScriptEvent {
	ch := make(chan ScriptEvent, 100)

	e.mu.Lock()
	e.clients[clientID] = ch
	e.mu.Unlock()

	return ch
}

// UnregisterClient removes an SSE connection
func (e *SSEEmitter) UnregisterClient(clientID string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if ch, ok := e.clients[clientID]; ok {
		close(ch)
		delete(e.clients, clientID)
	}
}

// EmitScriptEvent broadcasts event to all clients
func (e *SSEEmitter) EmitScriptEvent(event ScriptEvent) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, ch := range e.clients {
		select {
		case ch <- event:
		default:
			// Channel full, skip this event
		}
	}
}

// StreamHandler creates SSE HTTP handler
func (e *SSEEmitter) StreamHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		clientID = fmt.Sprintf("client-%d", time.Now().UnixNano())
	}

	// SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Register client
	eventCh := e.RegisterClient(clientID)
	defer e.UnregisterClient(clientID)

	// Send initial connection event
	sendSSEEvent(w, ScriptEvent{
		Type:      "connected",
		Timestamp: time.Now(),
	})

	// Stream events
	for event := range eventCh {
		sendSSEEvent(w, event)

		// Flush immediately
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
}

func sendSSEEvent(w http.ResponseWriter, event ScriptEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "data: %s\n\n", data)
	return nil
}
```

### HTTP Handlers for Script Registration

```go
// internal/cockpit/http.go
package cockpit

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

// ScriptRegistration payload from external scripts
type ScriptRegistration struct {
	ScriptID string `json:"script_id"`
	PID      int    `json:"pid"`
	Protocol string `json:"protocol"`
}

// LogLine payload from scripts
type LogLine struct {
	ScriptID string `json:"script_id"`
	Stream   string `json:"stream"` // stdout | stderr
	Line     string `json:"line"`
}

// HTTPServer handles script bridge endpoints
type HTTPServer struct {
	pm *ProcessManager
	sse *SSEEmitter
}

func NewHTTPServer(pm *ProcessManager, sse *SSEEmitter) *HTTPServer {
	return &HTTPServer{pm: pm, sse: sse}
}

// RegisterScript handles POST /api/script/register
func (s *HTTPServer) RegisterScript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var reg ScriptRegistration
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Read body failed", http.StatusBadRequest)
		return
	}

	if err := json.Unmarshal(body, &reg); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Register external script instance
	// (simplified - in reality, would verify against catalog)
	instance := &ScriptInstance{
		ID:        reg.ScriptID,
		PID:       reg.PID,
		Status:    "running",
		StartedAt: time.Now(),
	}

	s.pm.mu.Lock()
	s.pm.instances[reg.ScriptID] = instance
	s.pm.mu.Unlock()

	// Notify UI
	s.sse.EmitScriptEvent(ScriptEvent{
		Type:      "started",
		ScriptID:  reg.ScriptID,
		Timestamp: time.Now(),
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "registered"})
}

// ReceiveLog handles POST /api/script/log
func (s *HTTPServer) ReceiveLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var logLine LogLine
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Read body failed", http.StatusBadRequest)
		return
	}

	if err := json.Unmarshal(body, &logLine); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Emit log event to UI
	s.sse.EmitScriptEvent(ScriptEvent{
		Type:      "log",
		ScriptID:  logLine.ScriptID,
		Stream:    logLine.Stream,
		Line:      logLine.Line,
		Timestamp: time.Now(),
	})

	w.WriteHeader(http.StatusOK)
}
```

---

## Bridge Client Libraries

### TypeScript Bridge for Bun Scripts

```typescript
// scripts/lib/bridge.ts
/**
 * Bridge client for Bun scripts to communicate with Cockpit
 *
 * Usage:
 *   const bridge = new ScriptBridge('my-script-id')
 *   await bridge.register()
 *   bridge.log('info', 'Script started')
 */

export interface BridgeConfig {
	scriptId: string
	bridgeUrl?: string
	protocol?: 'http' | 'stdio'
	heartbeatInterval?: number
	logBatchSize?: number
}

export interface LogEntry {
	stream: 'stdout' | 'stderr'
	line: string
	timestamp: Date
}

export class ScriptBridge {
	private scriptId: string
	private bridgeUrl: string
	private protocol: string
	private heartbeatInterval: number
	private heartbeatTimer: Timer | null = null
	private logBuffer: LogEntry[] = []
	private logBatchSize: number

	constructor(config: BridgeConfig) {
		this.scriptId = config.scriptId
		this.bridgeUrl = config.bridgeUrl ||
			(process.env.COCKPIT_BRIDGE_URL || 'http://localhost:34115')
		this.protocol = config.protocol || 'http'
		this.heartbeatInterval = config.heartbeatInterval ||
			parseInt(process.env.COCKPIT_HEARTBEAT_INTERVAL || '30')
		this.logBatchSize = config.logBatchSize ||
			parseInt(process.env.COCKPIT_LOG_BATCH_SIZE || '100')
	}

	/**
	 * Register this script with the Cockpit
	 */
	async register(): Promise<void> {
		if (this.protocol === 'stdio') {
			// Stdio mode - write registration to stdout
			console.log(JSON.stringify({
				type: 'register',
				script_id: this.scriptId,
				pid: process.pid,
			}))
			return
		}

		const response = await fetch(`${this.bridgeUrl}/api/script/register`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				script_id: this.scriptId,
				pid: process.pid,
				protocol: this.protocol,
			}),
		})

		if (!response.ok) {
			throw new Error(`Registration failed: ${response.statusText}`)
		}

		// Start heartbeat
		if (this.heartbeatInterval > 0) {
			this.startHeartbeat()
		}

		// Start log batching
		this.startLogBatcher()
	}

	/**
	 * Send log line to Cockpit
	 */
	log(stream: 'stdout' | 'stderr', line: string): void {
		const entry: LogEntry = {
			stream,
			line,
			timestamp: new Date(),
		}

		this.logBuffer.push(entry)

		if (this.logBatchSize <= 0 || this.logBuffer.length >= this.logBatchSize) {
			this.flushLogs()
		}
	}

	/**
	 * Flush buffered logs to Cockpit
	 */
	async flushLogs(): Promise<void> {
		if (this.logBuffer.length === 0) {
			return
		}

		const logs = [...this.logBuffer]
		this.logBuffer = []

		if (this.protocol === 'stdio') {
			// Write logs to stdout as JSON lines
			for (const log of logs) {
				console.log(JSON.stringify({
					type: 'log',
					script_id: this.scriptId,
					stream: log.stream,
					line: log.line,
					timestamp: log.timestamp.toISOString(),
				}))
			}
			return
		}

		try {
			for (const log of logs) {
				await fetch(`${this.bridgeUrl}/api/script/log`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({
						script_id: this.scriptId,
						stream: log.stream,
						line: log.line,
					}),
				})
			}
		} catch (error) {
			// Failed to send, re-add to buffer
			this.logBuffer.unshift(...logs)
			throw error
		}
	}

	/**
	 * Start periodic heartbeat
	 */
	private startHeartbeat(): void {
		this.heartbeatTimer = setInterval(async () => {
			try {
				await fetch(`${this.bridgeUrl}/api/script/heartbeat`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({
						script_id: this.scriptId,
						timestamp: new Date().toISOString(),
					}),
				})
			} catch (error) {
				console.error('Heartbeat failed:', error)
			}
		}, this.heartbeatInterval * 1000)
	}

	/**
	 * Start log batching loop
	 */
	private startLogBatcher(): void {
		setInterval(() => {
			if (this.logBuffer.length > 0) {
				this.flushLogs().catch((error) => {
					console.error('Log flush failed:', error)
				})
			}
		}, 5000) // Flush every 5 seconds regardless of buffer size
	}

	/**
	 * Cleanup bridge resources
	 */
	async shutdown(): Promise<void> {
		if (this.heartbeatTimer) {
			clearInterval(this.heartbeatTimer)
			this.heartbeatTimer = null
		}

		// Flush remaining logs
		await this.flushLogs()

		// Send shutdown notification
		if (this.protocol === 'http') {
			try {
				await fetch(`${this.bridgeUrl}/api/script/shutdown`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({
						script_id: this.scriptId,
					}),
				})
			} catch (error) {
				// Ignore shutdown errors
			}
		}
	}
}

// Setup graceful shutdown
if (typeof process !== 'undefined') {
	const bridge = new ScriptBridge({
		scriptId: process.env.COCKPIT_SCRIPT_ID || 'unknown',
	})

	// Register on startup
	bridge.register().catch((error) => {
		console.error('Bridge registration failed:', error)
		process.exit(1)
	})

	// Cleanup on exit
	process.on('exit', () => {
		bridge.shutdown().catch(console.error)
	})

	process.on('SIGINT', () => {
		bridge.shutdown().then(() => process.exit(0))
	})

	process.on('SIGTERM', () => {
		bridge.shutdown().then(() => process.exit(0))
	})
}
```

### Python Bridge Library

```python
# scripts/lib/bridge.py
"""
Bridge client for Python scripts to communicate with Cockpit

Usage:
    bridge = ScriptBridge('my-script-id')
    bridge.register()
    bridge.log('stdout', 'Script started')
"""

import os
import sys
import json
import time
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List
from urllib.request import Request, urlopen
from urllib.error import URLError


@dataclass
class LogEntry:
    stream: str  # 'stdout' or 'stderr'
    line: str
    timestamp: datetime


class ScriptBridge:
    def __init__(
        self,
        script_id: str,
        bridge_url: Optional[str] = None,
        protocol: str = 'http',
        heartbeat_interval: Optional[int] = None,
        log_batch_size: Optional[int] = None,
    ):
        self.script_id = script_id
        self.bridge_url = bridge_url or os.getenv(
            'COCKPIT_BRIDGE_URL', 'http://localhost:34115'
        )
        self.protocol = protocol or os.getenv('COCKPIT_BRIDGE_PROTOCOL', 'http')
        self.heartbeat_interval = heartbeat_interval or int(
            os.getenv('COCKPIT_HEARTBEAT_INTERVAL', '30')
        )
        self.log_batch_size = log_batch_size or int(
            os.getenv('COCKPIT_LOG_BATCH_SIZE', '100')
        )

        self.heartbeat_thread: Optional[threading.Thread] = None
        self.log_buffer: List[LogEntry] = []
        self.log_batcher_thread: Optional[threading.Thread] = None
        self.running = False

    def register(self) -> None:
        """Register this script with the Cockpit"""
        if self.protocol == 'stdio':
            # Stdio mode - write registration to stdout
            print(json.dumps({
                'type': 'register',
                'script_id': self.script_id,
                'pid': os.getpid(),
            }))
            return

        # HTTP mode - send registration request
        data = json.dumps({
            'script_id': self.script_id,
            'pid': os.getpid(),
            'protocol': self.protocol,
        }).encode('utf-8')

        req = Request(
            f'{self.bridge_url}/api/script/register',
            data=data,
            headers={'Content-Type': 'application/json'}
        )

        with urlopen(req) as response:
            if response.status != 200:
                raise Exception(f'Registration failed: {response.status}')

        # Start background threads
        self.running = True

        if self.heartbeat_interval > 0:
            self.start_heartbeat()

        self.start_log_batcher()

    def log(self, stream: str, line: str) -> None:
        """Send log line to Cockpit"""
        entry = LogEntry(
            stream=stream,
            line=line,
            timestamp=datetime.now()
        )

        self.log_buffer.append(entry)

        if self.log_batch_size <= 0 or len(self.log_buffer) >= self.log_batch_size:
            self.flush_logs()

    def flush_logs(self) -> None:
        """Flush buffered logs to Cockpit"""
        if not self.log_buffer:
            return

        logs = self.log_buffer.copy()
        self.log_buffer.clear()

        if self.protocol == 'stdio':
            # Write logs to stdout as JSON lines
            for log in logs:
                print(json.dumps({
                    'type': 'log',
                    'script_id': self.script_id,
                    'stream': log.stream,
                    'line': log.line,
                    'timestamp': log.timestamp.isoformat(),
                }))
            return

        # HTTP mode - send logs to bridge
        for log in logs:
            data = json.dumps({
                'script_id': self.script_id,
                'stream': log.stream,
                'line': log.line,
            }).encode('utf-8')

            try:
                req = Request(
                    f'{self.bridge_url}/api/script/log',
                    data=data,
                    headers={'Content-Type': 'application/json'}
                )
                with urlopen(req) as response:
                    if response.status != 200:
                        raise Exception(f'Log send failed: {response.status}')
            except URLError as error:
                # Failed to send, re-add to buffer
                self.log_buffer.insert(0, log)
                raise

    def start_heartbeat(self) -> None:
        """Start periodic heartbeat thread"""
        def heartbeat_loop():
            while self.running:
                time.sleep(self.heartbeat_interval)

                try:
                    data = json.dumps({
                        'script_id': self.script_id,
                        'timestamp': datetime.now().isoformat(),
                    }).encode('utf-8')

                    req = Request(
                        f'{self.bridge_url}/api/script/heartbeat',
                        data=data,
                        headers={'Content-Type': 'application/json'}
                    )
                    with urlopen(req) as response:
                        pass  # Just check success
                except URLError:
                    # Ignore heartbeat failures
                    pass

        self.heartbeat_thread = threading.Thread(
            target=heartbeat_loop,
            daemon=True
        )
        self.heartbeat_thread.start()

    def start_log_batcher(self) -> None:
        """Start log batching thread"""
        def batcher_loop():
            while self.running:
                time.sleep(5.0)  # Flush every 5 seconds

                if self.log_buffer:
                    try:
                        self.flush_logs()
                    except URLError:
                        # Already handled in flush_logs
                        pass

        self.log_batcher_thread = threading.Thread(
            target=batcher_loop,
            daemon=True
        )
        self.log_batcher_thread.start()

    def shutdown(self) -> None:
        """Cleanup bridge resources"""
        self.running = False

        if self.heartbeat_thread:
            self.heartbeat_thread.join(timeout=2.0)

        if self.log_batcher_thread:
            self.log_batcher_thread.join(timeout=2.0)

        # Flush remaining logs
        self.flush_logs()

        # Send shutdown notification (HTTP only)
        if self.protocol == 'http':
            try:
                data = json.dumps({
                    'script_id': self.script_id,
                }).encode('utf-8')

                req = Request(
                    f'{self.bridge_url}/api/script/shutdown',
                    data=data,
                    headers={'Content-Type': 'application/json'}
                )
                with urlopen(req) as response:
                    pass
            except URLError:
                # Ignore shutdown errors
                pass


# Setup graceful shutdown
if __name__ == '__main__':
    import atexit

    script_id = os.getenv('COCKPIT_SCRIPT_ID', 'unknown')
    bridge = ScriptBridge(script_id)

    try:
        bridge.register()
    except Exception as e:
        print(f'Bridge registration failed: {e}', file=sys.stderr)
        sys.exit(1)

    atexit.register(lambda: bridge.shutdown())
```

---

## Web Components Architecture

### Script Tile Component

```typescript
// frontend/src/components/script-tile.ts
import { LitElement, html, css } from 'lit'
import { customElement, property, state } from 'lit/decorators.js'
import { SSEClient } from '../lib/sse-client.js'

/**
 * Cockpit Script Tile Component
 *
 * Displays a single script as a tile with:
 * - Script name and status
 * - Start/Stop controls
 * - Real-time log output
 * - Status indicator
 */
@customElement('script-tile')
export class ScriptTile extends LitElement {
  static styles = css`
    :host {
      display: block;
      border: 1px solid #ddd;
      border-radius: 8px;
      padding: 16px;
      margin: 8px;
      background: white;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }

    .tile-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 12px;
    }

    .script-name {
      font-weight: bold;
      font-size: 16px;
    }

    .script-status {
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: bold;
    }

    .status-running { background: #4caf50; color: white; }
    .status-stopped { background: #9e9e9e; color: white; }
    .status-failed { background: #f44336; color: white; }
    .status-completed { background: #2196f3; color: white; }

    .tile-controls {
      display: flex;
      gap: 8px;
      margin-bottom: 12px;
    }

    button {
      padding: 6px 12px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-weight: bold;
    }

    .btn-start { background: #4caf50; color: white; }
    .btn-stop { background: #f44336; color: white; }
    .btn-clear { background: #ff9800; color: white; }

    button:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    .log-output {
      background: #1e1e1e;
      color: #d4d4d4;
      padding: 12px;
      border-radius: 4px;
      font-family: monospace;
      font-size: 12px;
      height: 200px;
      overflow-y: auto;
      white-space: pre-wrap;
    }

    .log-line-stdout { color: #d4d4d4; }
    .log-line-stderr { color: #ff6b6b; }

    .timestamp {
      color: #888;
      margin-right: 8px;
    }
  `

  @property({ type: String })
  scriptId = ''

  @property({ type: String })
  scriptName = ''

  @property({ type: String })
  scriptType = ''

  @state()
  status: 'stopped' | 'running' | 'failed' | 'completed' = 'stopped'

  @state()
  logs: Array<{ stream: string; line: string; timestamp: string }> = []

  @state()
  exitCode: number | null = null

  private sseClient: SSEClient | null = null
  private maxLogLines = 1000

  connectedCallback() {
    super.connectedCallback()
    this.setupSSE()
  }

  disconnectedCallback() {
    super.disconnectedCallback()
    this.teardownSSE()
  }

  private setupSSE() {
    // Connect to SSE endpoint for this script
    this.sseClient = new SSEClient(`/api/stream?script_id=${this.scriptId}`)

    this.sseClient.on('log', (data: any) => {
      if (data.script_id === this.scriptId) {
        this.addLog(data.stream, data.line, data.timestamp)
      }
    })

    this.sseClient.on('started', (data: any) => {
      if (data.script_id === this.scriptId) {
        this.status = 'running'
        this.exitCode = null
      }
    })

    this.sseClient.on('completed', (data: any) => {
      if (data.script_id === this.scriptId) {
        this.status = data.status || 'completed'
        this.exitCode = data.exit_code
      }
    })

    this.sseClient.on('failed', (data: any) => {
      if (data.script_id === this.scriptId) {
        this.status = 'failed'
        this.exitCode = data.exit_code
      }
    })

    this.sseClient.connect()
  }

  private teardownSSE() {
    if (this.sseClient) {
      this.sseClient.disconnect()
      this.sseClient = null
    }
  }

  private addLog(stream: string, line: string, timestamp: string) {
    this.logs = [
      ...this.logs,
      { stream, line, timestamp }
    ].slice(-this.maxLogLines)

    // Auto-scroll to bottom
    requestAnimationFrame(() => {
      const logContainer = this.shadowRoot?.querySelector('.log-output')
      if (logContainer) {
        logContainer.scrollTop = logContainer.scrollHeight
      }
    })
  }

  async startScript() {
    try {
      const response = await fetch(`/api/script/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ script_id: this.scriptId })
      })

      if (!response.ok) {
        throw new Error(`Failed to start script: ${response.statusText}`)
      }
    } catch (error) {
      console.error('Start script error:', error)
      alert(`Failed to start script: ${error}`)
    }
  }

  async stopScript() {
    try {
      const response = await fetch(`/api/script/stop`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ script_id: this.scriptId })
      })

      if (!response.ok) {
        throw new Error(`Failed to stop script: ${response.statusText}`)
      }
    } catch (error) {
      console.error('Stop script error:', error)
      alert(`Failed to stop script: ${error}`)
    }
  }

  clearLogs() {
    this.logs = []
  }

  render() {
    return html`
      <div class="tile-header">
        <div class="script-name">${this.scriptName}</div>
        <div class="script-status status-${this.status}">
          ${this.status.toUpperCase()}
          ${this.exitCode !== null ? ` (${this.exitCode})` : ''}
        </div>
      </div>

      <div class="tile-controls">
        <button
          class="btn-start"
          ?disabled="${this.status === 'running'}"
          @click="${this.startScript}"
        >
          Start
        </button>
        <button
          class="btn-stop"
          ?disabled="${this.status !== 'running'}"
          @click="${this.stopScript}"
        >
          Stop
        </button>
        <button class="btn-clear" @click="${this.clearLogs}">
          Clear
        </button>
      </div>

      <div class="log-output">
        ${this.logs.map(log => html`
          <div class="log-line-${log.stream}">
            <span class="timestamp">${new Date(log.timestamp).toLocaleTimeString()}</span>
            ${log.line}
          </div>
        `)}
      </div>
    `
  }
}
```

### Cockpit Dashboard Component

```typescript
// frontend/src/components/cockpit-dashboard.ts
import { LitElement, html, css } from 'lit'
import { customElement, state } from 'lit/decorators.js'

/**
 * Cockpit Dashboard Component
 *
 * Displays a grid of script tiles for all available scripts
 */
@customElement('cockpit-dashboard')
export class CockpitDashboard extends LitElement {
  static styles = css`
    :host {
      display: block;
      padding: 20px;
      background: #f5f5f5;
    }

    .dashboard-header {
      margin-bottom: 20px;
    }

    .dashboard-title {
      font-size: 24px;
      font-weight: bold;
      margin: 0;
    }

    .script-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
      gap: 16px;
    }

    .loading {
      text-align: center;
      padding: 40px;
      font-size: 18px;
      color: #666;
    }

    .error {
      background: #ffebee;
      color: #c62828;
      padding: 16px;
      border-radius: 4px;
      margin-bottom: 20px;
    }

    .category-filter {
      display: flex;
      gap: 8px;
      margin-bottom: 16px;
      flex-wrap: wrap;
    }

    .filter-btn {
      padding: 6px 12px;
      border: 1px solid #ddd;
      background: white;
      border-radius: 4px;
      cursor: pointer;
    }

    .filter-btn.active {
      background: #2196f3;
      color: white;
      border-color: #2196f3;
    }
  `

  @state()
  scripts: Array<{
    id: string
    name: string
    type: string
    category: string
    tags: string[]
  }> = []

  @state()
  loading = true

  @state()
  error: string | null = null

  @state()
  activeCategory = 'all'

  async connectedCallback() {
    super.connectedCallback()
    await this.loadScripts()
  }

  async loadScripts() {
    try {
      const response = await fetch('/api/scripts')
      if (!response.ok) {
        throw new Error(`Failed to load scripts: ${response.statusText}`)
      }

      this.scripts = await response.json()
      this.loading = false
    } catch (error) {
      this.error = (error as Error).message
      this.loading = false
    }
  }

  get filteredScripts() {
    if (this.activeCategory === 'all') {
      return this.scripts
    }
    return this.scripts.filter(s => s.category === this.activeCategory)
  }

  get categories() {
    const cats = new Set(this.scripts.map(s => s.category))
    return ['all', ...Array.from(cats)]
  }

  setCategory(category: string) {
    this.activeCategory = category
  }

  render() {
    return html`
      <div class="dashboard-header">
        <h1 class="dashboard-title">Cockpit Dashboard</h1>
      </div>

      ${this.error ? html`
        <div class="error">
          Error: ${this.error}
        </div>
      ` : ''}

      <div class="category-filter">
        ${this.categories.map(cat => html`
          <button
            class="filter-btn ${this.activeCategory === cat ? 'active' : ''}"
            @click="${() => this.setCategory(cat)}"
          >
            ${cat.toUpperCase()}
          </button>
        `)}
      </div>

      ${this.loading ? html`
        <div class="loading">Loading scripts...</div>
      ` : html`
        <div class="script-grid">
          ${this.filteredScripts.map(script => html`
            <script-tile
              script-id="${script.id}"
              script-name="${script.name}"
              script-type="${script.type}"
            ></script-tile>
          `)}
        </div>
      `}
    `
  }
}
```

### Minimal SSE Client (No Dependencies)

```typescript
// frontend/src/lib/sse-client.ts
/**
 * Minimal Server-Sent Events client
 * No external dependencies - uses browser native EventSource
 */

export type SSEEventType = string

export interface SSEEventHandler {
  (data: any): void
}

export class SSEClient {
  private eventSource: EventSource | null = null
  private eventHandlers: Map<SSEEventType, SSEEventHandler[]> = new Map()
  private url: string

  constructor(url: string) {
    this.url = url
  }

  on(event: SSEEventType, handler: SSEEventHandler) {
    if (!this.eventHandlers.has(event)) {
      this.eventHandlers.set(event, [])
    }
    this.eventHandlers.get(event)!.push(handler)
  }

  off(event: SSEEventType, handler: SSEEventHandler) {
    const handlers = this.eventHandlers.get(event)
    if (handlers) {
      const index = handlers.indexOf(handler)
      if (index > -1) {
        handlers.splice(index, 1)
      }
    }
  }

  connect() {
    if (this.eventSource) {
      this.disconnect()
    }

    this.eventSource = new EventSource(this.url)

    this.eventSource.addEventListener('message', (event) => {
      try {
        const data = JSON.parse(event.data)
        const eventType = data.type || 'message'

        const handlers = this.eventHandlers.get(eventType)
        if (handlers) {
          handlers.forEach(handler => handler(data))
        }

        // Also emit to 'message' handlers for backwards compatibility
        const messageHandlers = this.eventHandlers.get('message')
        if (messageHandlers && eventType !== 'message') {
          messageHandlers.forEach(handler => handler(data))
        }
      } catch (error) {
        console.error('Failed to parse SSE message:', error)
      }
    })

    this.eventSource.addEventListener('error', (error) => {
      console.error('SSE error:', error)
      // EventSource will auto-reconnect
    })
  }

  disconnect() {
    if (this.eventSource) {
      this.eventSource.close()
      this.eventSource = null
    }
  }
}
```

---

## Doctor/Housekeeping Bridge (Offline Mode)

### Direct Stdio Bridge Implementation

```go
// internal/cockpit/stdio_bridge.go
package cockpit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// StdioMessage represents JSON messages over stdio
type StdioMessage struct {
	Type      string `json:"type"`       // register, log, heartbeat
	ScriptID  string `json:"script_id"`
	PID       int    `json:"pid"`
	Stream    string `json:"stream"`     // stdout | stderr
	Line      string `json:"line"`
	Timestamp string `json:"timestamp"`
}

// StdioBridge handles direct stdio communication for offline-capable scripts
type StdioBridge struct {
	pm   *ProcessManager
	sse  *SSEEmitter
	mu   sync.Mutex
}

func NewStdioBridge(pm *ProcessManager, sse *SSEEmitter) *StdioBridge {
	return &StdioBridge{
		pm:  pm,
		sse: sse,
	}
}

// ProcessScript reads from stdout/stderr and forwards to SSE
func (b *StdioBridge) ProcessScript(scriptID string, stdout, stderr io.Reader) {
	// Process stdout
	go b.streamStdio(scriptID, "stdout", stdout)

	// Process stderr
	go b.streamStdio(scriptID, "stderr", stderr)
}

func (b *StdioBridge) streamStdio(scriptID, stream string, reader io.Reader) {
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := scanner.Text()

		// Check if line is JSON protocol message
		if strings.HasPrefix(line, "{") {
			var msg StdioMessage
			if err := json.Unmarshal([]byte(line), &msg); err == nil {
				b.handleProtocolMessage(msg)
				continue
			}
		}

		// Regular log line - emit to SSE
		b.sse.EmitScriptEvent(ScriptEvent{
			Type:      "log",
			ScriptID:  scriptID,
			Stream:    stream,
			Line:      line,
			Timestamp: time.Now(),
		})
	}
}

func (b *StdioBridge) handleProtocolMessage(msg StdioMessage) {
	switch msg.Type {
	case "register":
		// Register script instance
		b.mu.Lock()
		b.pm.instances[msg.ScriptID] = &ScriptInstance{
			ID:        msg.ScriptID,
			PID:       msg.PID,
			Status:    "running",
			StartedAt: time.Now(),
		}
		b.mu.Unlock()

		// Notify UI
		b.sse.EmitScriptEvent(ScriptEvent{
			Type:      "started",
			ScriptID:  msg.ScriptID,
			Timestamp: time.Now(),
		})

	case "log":
		// Log message from script
		b.sse.EmitScriptEvent(ScriptEvent{
			Type:      "log",
			ScriptID:  msg.ScriptID,
			Stream:    msg.Stream,
			Line:      msg.Line,
			Timestamp: time.Now(),
		})

	case "heartbeat":
		// Heartbeat from script
		b.sse.EmitScriptEvent(ScriptEvent{
			Type:      "heartbeat",
			ScriptID:  msg.ScriptID,
			Timestamp: time.Now(),
		})
	}
}
```

---

## Script Generation Templates

### Bun Script Template

```typescript
// scripts/templates/bun-script-template.ts
/**
 * Bun Script Template for Cockpit Integration
 *
 * Replace this file header with your script documentation
 */

import { ScriptBridge } from '../lib/bridge.js'

// Get script ID from environment or use default
const scriptId = process.env.COCKPIT_SCRIPT_ID || Bun.env.SCRIPT_ID || 'my-script'

// Create bridge instance
const bridge = new ScriptBridge({
  scriptId,
  protocol: 'http', // or 'stdio' for offline mode
  heartbeatInterval: 30,
  logBatchSize: 50,
})

// Register with Cockpit
await bridge.register()

// Main script logic
async function main() {
  bridge.log('stdout', 'Starting script execution...')

  try {
    // YOUR SCRIPT LOGIC HERE
    bridge.log('stdout', 'Processing...')

    // Example: long-running task
    for (let i = 0; i < 10; i++) {
      await Bun.sleep(1000)
      bridge.log('stdout', `Progress: ${i + 1}/10`)
    }

    bridge.log('stdout', 'Script completed successfully')
    process.exit(0)
  } catch (error) {
    bridge.log('stderr', `Error: ${error}`)
    process.exit(1)
  }
}

// Run main function
main().catch((error) => {
  bridge.log('stderr', `Fatal error: ${error}`)
  process.exit(1)
})
```

### Python Script Template

```python
# scripts/templates/python-script-template.py
"""
Python Script Template for Cockpit Integration

Replace this file header with your script documentation
"""

import sys
import os
import time
import asyncio
from lib.bridge import ScriptBridge

# Get script ID from environment
script_id = os.getenv('COCKPIT_SCRIPT_ID') or 'my-script'

# Create bridge instance
bridge = ScriptBridge(
    script_id=script_id,
    protocol='http',  # or 'stdio' for offline mode
    heartbeat_interval=30,
    log_batch_size=50,
)

# Register with Cockpit
bridge.register()

def main():
    bridge.log('stdout', 'Starting script execution...')

    try:
        # YOUR SCRIPT LOGIC HERE
        bridge.log('stdout', 'Processing...')

        # Example: long-running task
        for i in range(10):
            time.sleep(1)
            bridge.log('stdout', f'Progress: {i + 1}/10')

        bridge.log('stdout', 'Script completed successfully')
        sys.exit(0)
    except Exception as error:
        bridge.log('stderr', f'Error: {error}')
        sys.exit(1)

if __name__ == '__main__':
    main()
```

---

## Key Integration Points

### Wails3 Main Integration

```go
// main.go - Integration with existing Wails app
package main

import (
	"log"
	"net/http"

	"cockpit/app/internal/cockpit"
	"github.com/wailsapp/wails/v3/pkg/application"
)

type CockpitService struct {
	pm  *cockpit.ProcessManager
	sse *cockpit.SSEEmitter
}

func NewCockpitService() *CockpitService {
	pm := &cockpit.ProcessManager{
		baseDir: "./scripts",
	}

	sse := cockpit.NewSSEEmitter()
	httpServer := cockpit.NewHTTPServer(pm, sse)

	// Setup HTTP server for script bridge
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/api/stream", sse.StreamHandler)
		mux.HandleFunc("/api/script/register", httpServer.RegisterScript)
		mux.HandleFunc("/api/script/log", httpServer.ReceiveLog)
		mux.HandleFunc("/api/scripts", httpServer.ListScripts)

		log.Println("Cockpit bridge server listening on :34115")
		log.Fatal(http.ListenAndServe(":34115", mux))
	}()

	// Load catalog
	if err := pm.LoadCatalog("scripts/catalog.toml"); err != nil {
		log.Printf("Warning: Failed to load catalog: %v", err)
	}

	return &CockpitService{
		pm:  pm,
		sse: sse,
	}
}

// Wails service methods

func (s *CockpitService) StartScript(scriptID string) error {
	_, err := s.pm.StartScript(scriptID)
	return err
}

func (s *CockpitService) StopScript(scriptID string) error {
	return s.pm.StopScript(scriptID)
}

func (s *CockpitService) GetScripts() ([]cockpit.ScriptMetadata, error) {
	s.pm.mu.RLock()
	defer s.pm.mu.RUnlock()

	// Return copy of catalog
	scripts := make([]cockpit.ScriptMetadata, len(s.pm.catalog))
	copy(scripts, s.pm.catalog)
	return scripts, nil
}

func main() {
	app := application.New(application.Options{
		Name:        "SafeYolo_Cockpit",
		Description: "Script orchestration cockpit",
		Services: []application.Service{
			application.NewService(NewCockpitService()),
		},
		// ... existing Wails setup
	})

	// ... rest of main.go
}
```

---

## Security Considerations

1. **Script isolation**: Run scripts as separate processes with minimal privileges
2. **Bridge authentication**: Consider adding shared secret for HTTP endpoints
3. **Input validation**: Validate all script IDs and parameters
4. **CORS restrictions**: Limit CORS to specific origins if needed
5. **Rate limiting**: Add rate limiting to HTTP endpoints
6. **Script sandboxing**: Consider containerization for untrusted scripts

---

## Summary of Recommendations

1. **Primary bridge**: HTTP + SSE (minimal dependencies, native browser support)
2. **Backup bridge**: Stdio for offline/housekeeping scripts
3. **Catalog format**: TOML with per-script metadata
4. **UI framework**: Lit WebComponents (minimal dependencies, easy generation)
5. **Go role**: Pure orchestration, no business logic
6. **Protocol flexibility**: Support multiple protocols per script requirements
7. **Generation templates**: Provide templates for Bun, Python, and shell scripts
8. **Bridge libraries**: TypeScript and Python client libraries for easy integration

---

## Next Steps

1. Implement Go ProcessManager and SSEEmitter
2. Create HTTP bridge server
3. Implement TypeScript and Python bridge client libraries
4. Create Lit web components (ScriptTile, Dashboard)
5. Set up script catalog TOML schema
6. Implement script generation CLI tool
7. Add doctor/housekeeping stdio bridge
8. Implement security measures (authentication, rate limiting)
