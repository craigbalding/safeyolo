#!/usr/bin/env bun
import { spawn } from 'bun'
import { parseArgs, type ParseArgsOptionsConfig } from 'node:util'

const options = {
  socket: { type: 'string', default: '/tmp/safeyolo-runner.sock' },
  cols: { type: 'string', default: '80' },
  rows: { type: 'string', default: '24' },
} satisfies ParseArgsOptionsConfig

const dashIndex = Bun.argv.indexOf('---')
if (dashIndex === -1) {
  console.error('Error: Usage: ./runner.ts [flags] --- [command]')
  process.exit(1)
}

const runnerArgs = Bun.argv.slice(2, dashIndex)
const commandArgs = Bun.argv.slice(dashIndex + 1)
if (commandArgs.length === 0) {
  console.error('Error: No command provided after ---')
  process.exit(1)
}

const { values } = parseArgs({
  args: runnerArgs,
  options,
  strict: true,
  allowPositionals: false,
})

let globalProc: any
const cols = parseInt(values.cols, 10)
const rows = parseInt(values.rows, 10)

Bun.connect({
  unix: values.socket,
  socket: {
    data(sock, data) {
      if (!globalProc) return
      const decoder = new TextDecoder()
      try {
        const msg = JSON.parse(decoder.decode(data))
        if (msg.type === 'resize' && globalProc.terminal) {
          globalProc.terminal.resize(msg.cols ?? cols, msg.rows ?? rows)
        }
      } catch {
        if (globalProc.stdin) {
          globalProc.stdin.write(data)
          globalProc.stdin.flush()
        }
      }
    },
    open(sock) {
      globalProc = spawn(commandArgs, {
        stdin: 'pipe',
        stdout: 'pipe',
        terminal: {
          cols,
          rows,
          data(term, data) {
            sock.write(data)
          },
        },
      })

      globalProc.exited.then((code) => {
        sock.end()
        process.exit(code ?? 0)
      }).catch((err) => {
        console.error('Proc error:', err)
        process.exit(1)
      })
    },
    close() {
      process.exit(0)
    },
    error(err) {
      console.error('Failed to connect to socket. Is Go backend running?')
      process.exit(1)
    },
  },
})
