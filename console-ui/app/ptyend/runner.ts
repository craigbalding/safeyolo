#!/usr/bin/env bun
import { spawn } from 'bun'
import { parseArgs, type ParseArgsOptionsConfig } from 'node:util'

const options = {
    socket: { type: 'string', default: '/tmp/safeyolo-runner.sock' },
    cols: { type: 'string', default: '80' },
    rows: { type: 'string', default: '24' },
    tcp: { type: 'boolean', default: false },
} satisfies ParseArgsOptionsConfig

const dashIndex = Bun.argv.indexOf('---')
if (dashIndex === -1) {
  console.error('Error: Usage: ./runner.ts [flags] --- [command]')
  process.exit(1)
}

// Everything between script path and '---' are runner flags
// Everything after '---' is the command
const runnerArgs = Bun.argv.slice(2, dashIndex)  // From index 2 (after bun + script) up to '--'
const commandArgs = Bun.argv.slice(dashIndex + 1)
if (commandArgs.length === 0) {
  console.error('Error: No command provided after --')
  process.exit(1)
}

const { values } = parseArgs({
  args: runnerArgs,
  options,
  strict: true,
  allowPositionals: false,
})

// values.socket, values.cols, values.rows, values.tcp
// commandArgs[0] is the command, rest are its args

const ws = new WebSocket(`ws+unix://${values.socket}`)
// const ws = new WebSocket('ws://localhost:34115/terminal')

ws.onopen = () => {
  const proc = spawn(commandArgs, {
    stdin: 'pipe',
    stdout: 'pipe', // PTY merges stderr into stdout usually
    terminal: {
      cols: parseInt(values.cols), // Default start size, Wails will update this
      rows: parseInt(values.rows),
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
