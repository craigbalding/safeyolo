#!/usr/bin/env bun
import { spawn } from 'bun'

const args = Bun.argv.slice(2) // Skip [bun, script.ts]

// Try to find explicit split (in case user did '-- --')
let splitIndex = args.indexOf('--')

// If no '--' found, assume the first argument that DOESN'T start with '-' is the command
if (splitIndex === -1) {
  splitIndex = args.findIndex((arg) => !arg.startsWith('-'))
}

// If we still can't find a command, error out
if (splitIndex === -1) {
  console.error(
    'Error: Could not determine command. Usage: ./runner.ts [flags] -- [command]',
  )
  process.exit(1)
}

// Separate Script Flags vs Command
// If we found a "--", the command is everything AFTER it.
// If we found a command name (heuristic), the command starts THERE.
const scriptFlags = args.slice(0, splitIndex)
// If the split was on "--", we skip it (+1). If it was on "ls", we keep it.
const commandStartIndex = args[splitIndex] === '--'
  ? splitIndex + 1
  : splitIndex
const command = args.slice(commandStartIndex)

if (command.length === 0) {
  console.error('Error: No command specified.')
  process.exit(1)
}

const ws = new WebSocket('ws://localhost:34115/terminal')

ws.onopen = () => {
  const proc = spawn(command, {
    stdin: 'pipe',
    stdout: 'pipe', // PTY merges stderr into stdout usually
    terminal: {
      cols: 80, // Default start size, Wails will update this
      rows: 24,
      data(term, data) {
        ws.send(data)
      },
    },
  })

  ws.onmessage = (event) => {
    if (typeof event.data === 'string') {
      try {
        const msg = JSON.parse(event.data)
        if (msg.type === 'resize' && proc.terminal) {
          proc.terminal.resize(msg.cols, msg.rows)
        }
      } catch (e) { /* ignore garbage */ }
    } else {
      // Binary message = User Input (Keystrokes from UI)
      // Write directly to the process stdin
      if (proc.stdin) {
        proc.stdin.write(event.data)
        proc.stdin.flush()
      }
    }
  }

  proc.exited.then((code) => {
    ws.close()
    process.exit(code)
  })

  ws.onclose = () => {
    proc.kill()
    process.exit(0)
  }
}

ws.onerror = (err) => {
  console.error('Failed to connect to Wails app. Is it running?')
  process.exit(1)
}
