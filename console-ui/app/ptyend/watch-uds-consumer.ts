#!/usr/bin/env bun
/// <reference types="bun" />
/**
 * POC: SafeYolo Watch UDS Consumer
 *
 * This script spawns 'safeyolo watch' as a child process with UDS socket support,
 * connects to the socket, and consumes/streams JSONL events.
 *
 * Usage:
 *   bun run poc_watch_uds_consumer.ts
 */

import { spawn } from 'bun'

const us_ = 'safeyolo'
const me_ = 'SafeYolo watch UDS consumer'
const _pathtoSock = `${(Bun.env.SY_UDS_DIR || '/tmp').replace(/\/$/, '')}/` +
  `${us_}_${Bun.env.SY_UDS_WATCH_SOCKET_ID || 'watch-unnamed'}.sock`
const defaults_ = {
  pathtoSock: _pathtoSock,
  watchCmd: us_,
  watchArgs: ['watch', '--socket', _pathtoSock, '--log-only', '--all'],
} as const

const err_: [undefined | string, string] = [undefined, `unexpected error`]
const getErr = (err?: unknown) => `${me_} failed: ${err || err_[0] || err_[1]}`

interface SafeYoloEvent {
  ts: string
  event: string
  host?: string
  path?: string
  method?: string
  decision?: string
  reason?: string
  rule?: string
  fingerprint?: string
  status_code?: number
  client_ip?: string
  [key: string]: unknown
}

/**
 * LineReader handles partial line buffering for streaming JSONL.
 */
class LineReader {
  private buffer = ''

  feed(data: Uint8Array): string[] {
    const text = new TextDecoder().decode(data)
    this.buffer += text
    const lines: string[] = []

    let idx: number
    while ((idx = this.buffer.indexOf('\n')) !== -1) {
      const line = this.buffer.slice(0, idx).trim()
      if (line) lines.push(line)
      this.buffer = this.buffer.slice(idx + 1)
    }

    return lines
  }
}

/**
 * Format event for display
 */
function formatEvent(event: SafeYoloEvent): string {
  const ts = event.ts?.split('T')[1]?.slice(0, 8) || '??:??:??'
  const evt = event.event || 'unknown'
  const host = event.host || '-'
  const decision = event.decision || ''

  const reset = '\x1b[0m'
  const decisionColor = decision === 'block'
    ? '\x1b[31m' // red
    : decision === 'warn'
    ? '\x1b[33m' // yellow
    : '\x1b[36m' // cyan

  let output = `[${ts}] ${decisionColor}${evt}${reset} host=${host}`
  if (decision) output += ` decision=${decision}`
  if (event.rule) output += ` rule=${event.rule}`
  if (event.reason) output += ` reason=${event.reason}`

  return output
}

try {
  if (!import.meta.main) {
    throw 'Not a library'
  }

  console.log('='.repeat(60))
  console.log(me_)
  console.log('='.repeat(60))
  console.log()

  // Clean up any stale socket
  try {
    await Bun.file(defaults_.pathtoSock).delete()
  } catch {
    // File may not exist, that's fine
  }

  // Spawn the watch process
  console.log(`[Spawn] Starting: ${defaults_.watchCmd} ${defaults_.watchArgs.join(' ')}`)
  const watchProc = spawn({
    cmd: [defaults_.watchCmd, ...defaults_.watchArgs],
    stdout: 'inherit',
    stderr: 'inherit',
    terminal: true,
  })

  // Wait a moment for socket to be created
  await new Promise((r) => setTimeout(r, 500))

  // Check if socket exists
  const socketExists = await Bun.file(defaults_.pathtoSock).exists()
  if (!socketExists) {
    throw `Socket not created at ${defaults_.pathtoSock}. Is safeyolo installed?`
  }

  // Connect and consume
  const lineReader = new LineReader()
  let eventCount = 0

  const socket = await Bun.connect({
    unix: defaults_.pathtoSock,
    socket: {
      open() {
        console.log('[UDS] Connected! Streaming events...\n')
      },
      data(_socket, data: Uint8Array) {
        const lines = lineReader.feed(data)

        for (const line of lines) {
          try {
            const event: SafeYoloEvent = JSON.parse(line)
            eventCount++
            console.log(formatEvent(event))
          } catch {
            console.error(`[malformed] ${line.slice(0, 100)}`)
          }
        }
      },
      error(_socket, error) {
        throw `Socket error: ${error.message}`
      },
      close() {
        console.log(`\n[UDS] Socket closed. Received ${eventCount} events.`)
      },
    },
  })

  // Wait for process exit
  const exitCode = await watchProc.exited
  socket.end()

  // Cleanup socket file
  try {
    await Bun.file(defaults_.pathtoSock).delete()
  } catch {
    // Ignore cleanup errors
  }

  process.exit(exitCode)
} catch (err: unknown) {
  console.error(getErr(err))
  process.exit(1)
}
