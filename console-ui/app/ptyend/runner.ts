#!/usr/bin/env bun
import { spawn } from 'bun'
import { parseArgs, type ParseArgsOptionsConfig } from 'node:util'
import { createHash } from 'node:crypto'

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

// WebSocket frame opcodes
const OPCODE_TEXT = 0x01
const OPCODE_BINARY = 0x02
const OPCODE_CLOSE = 0x08
const OPCODE_PING = 0x09
const OPCODE_PONG = 0x0a

interface WSFrame {
  opcode: number
  payload: Uint8Array
}

function encodeWSFrame(
  opcode: number,
  payload: Uint8Array | string,
): Uint8Array {
  const payloadBuf = typeof payload === 'string'
    ? new TextEncoder().encode(payload)
    : payload
  const len = payloadBuf.length
  let frame: Uint8Array

  if (len < 126) {
    frame = new Uint8Array(2 + len)
    frame[0] = 0x80 | opcode // FIN=1, opcode
    frame[1] = len
    frame.set(payloadBuf, 2)
  } else if (len < 65536) {
    frame = new Uint8Array(4 + len)
    frame[0] = 0x80 | opcode
    frame[1] = 126
    const view = new DataView(frame.buffer)
    view.setUint16(2, len, false)
    frame.set(payloadBuf, 4)
  } else {
    frame = new Uint8Array(10 + len)
    frame[0] = 0x80 | opcode
    frame[1] = 127
    const view = new DataView(frame.buffer)
    view.setBigUint64(2, BigInt(len), false)
    frame.set(payloadBuf, 10)
  }
  return frame
}

function decodeWSFrames(
  data: Uint8Array,
): { frames: WSFrame[]; remainder: Uint8Array } {
  const frames: WSFrame[] = []
  let offset = 0

  while (offset < data.length) {
    if (offset + 2 > data.length) break

    const byte1 = data[offset]
    const byte2 = data[offset + 1]
    const opcode = byte1 & 0x0f
    const masked = !!(byte2 & 0x80)
    let payloadLen = byte2 & 0x7f
    let headerLen = 2

    if (payloadLen === 126) {
      if (offset + 4 > data.length) break
      const view = new DataView(data.buffer, data.byteOffset)
      payloadLen = view.getUint16(offset + 2, false)
      headerLen = 4
    } else if (payloadLen === 127) {
      if (offset + 10 > data.length) break
      const view = new DataView(data.buffer, data.byteOffset)
      payloadLen = Number(view.getBigUint64(offset + 2, false))
      headerLen = 10
    }

    const maskLen = masked ? 4 : 0
    if (offset + headerLen + maskLen + payloadLen > data.length) break

    let payload = data.slice(
      offset + headerLen + maskLen,
      offset + headerLen + maskLen + payloadLen,
    )

    if (masked) {
      const mask = data.slice(offset + headerLen, offset + headerLen + 4)
      const unmasked = new Uint8Array(payload.length)
      for (let i = 0; i < payload.length; i++) {
        unmasked[i] = payload[i]! ^ mask[i % 4]!
      }
      payload = unmasked
    }

    frames.push({ opcode, payload })
    offset += headerLen + maskLen + payloadLen
  }

  return { frames, remainder: data.slice(offset) }
}

function connectWebSocketOverUDS(
  socketPath: string,
  onOpen: () => void,
  onMessage: (data: Uint8Array | string) => void,
  onClose: () => void,
  onError: (err: Error) => void,
) {
  let socket: ReturnType<typeof Bun.connect>
  let connected = false
  let receiveBuffer = new Uint8Array(0)

  const key = createHash('sha1').update(
    `${Math.random().toString(36)}${Date.now()}`,
  ).digest('base64')
  const expectedAccept = createHash('sha1').update(
    `${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`,
  ).digest('base64')

  socket = Bun.connect({
    unix: socketPath,
    socket: {
      data(socket, data) {
        if (!connected) {
          // Handle HTTP upgrade response
          const response = new TextDecoder().decode(data)
          if (
            response.includes('101 Switching Protocols') &&
            response.includes(`Sec-WebSocket-Accept: ${expectedAccept}`)
          ) {
            connected = true
            onOpen()
          } else {
            onError(new Error('WebSocket upgrade failed'))
            socket.end()
          }
          return
        }

        // Handle WebSocket frames
        const newBuffer = new Uint8Array(receiveBuffer.length + data.length)
        newBuffer.set(receiveBuffer)
        newBuffer.set(data, receiveBuffer.length)
        receiveBuffer = newBuffer
        const { frames, remainder } = decodeWSFrames(receiveBuffer)
        receiveBuffer = remainder

        for (const frame of frames) {
          if (frame.opcode === OPCODE_TEXT) {
            onMessage(new TextDecoder().decode(frame.payload))
          } else if (frame.opcode === OPCODE_BINARY) {
            onMessage(frame.payload)
          } else if (frame.opcode === OPCODE_CLOSE) {
            socket.end()
            onClose()
          } else if (frame.opcode === OPCODE_PING) {
            socket.write(encodeWSFrame(OPCODE_PONG, new Uint8Array(0)))
          }
        }
      },
      open(socket) {
        // Send WebSocket upgrade request
        const upgradeRequest = [
          'GET /terminal HTTP/1.1',
          'Host: localhost',
          'Upgrade: websocket',
          'Connection: Upgrade',
          `Sec-WebSocket-Key: ${key}`,
          'Sec-WebSocket-Version: 13',
          '',
          '',
        ].join('\r\n')
        socket.write(new TextEncoder().encode(upgradeRequest))
      },
      close() {
        onClose()
      },
      error(socket, error) {
        onError(error)
      },
    },
  })

  return {
    send(data: Uint8Array | string) {
      const opcode = typeof data === 'string' ? OPCODE_TEXT : OPCODE_BINARY
      socket.then((s) => s.write(encodeWSFrame(opcode, data)))
    },
    close() {
      socket.then((s) => {
        s.write(encodeWSFrame(OPCODE_CLOSE, new Uint8Array(0)))
        s.end()
      })
    },
  }
}

function connectWebSocketOverTCP(
  url: string,
  onOpen: () => void,
  onMessage: (data: Uint8Array | string) => void,
  onClose: () => void,
  onError: (err: Error) => void,
) {
  const ws = new WebSocket(url)

  ws.onopen = onOpen
  ws.onmessage = (event) => {
    if (event.data instanceof Blob) {
      event.data.arrayBuffer().then((buf) => onMessage(new Uint8Array(buf)))
    } else {
      onMessage(event.data)
    }
  }
  ws.onclose = onClose
  ws.onerror = (err) => onError(new Error('WebSocket error'))

  return {
    send(data: Uint8Array | string) {
      ws.send(data)
    },
    close() {
      ws.close()
    },
  }
}

// Connect using appropriate transport
const wsConn = values.tcp
  ? connectWebSocketOverTCP(
    `ws://${values.socket}`,
    onOpen,
    onMessage,
    onClose,
    onError,
  )
  : connectWebSocketOverUDS(
    values.socket,
    onOpen,
    onMessage,
    onClose,
    onError,
  )

function onOpen() {
  const proc = spawn(commandArgs, {
    stdin: 'pipe',
    stdout: 'pipe',
    terminal: {
      cols: parseInt(values.cols),
      rows: parseInt(values.rows),
      data(term, data) {
        wsConn.send(data)
      },
    },
  })

  function onMessage(data: Uint8Array | string) {
    if (typeof data === 'string') {
      try {
        const msg = JSON.parse(data)
        if (msg.type === 'resize' && proc.terminal) {
          proc.terminal.resize(msg.cols, msg.rows)
        }
      } catch (e) { /* ignore garbage */ }
    } else {
      if (proc.stdin) {
        proc.stdin.write(data)
        proc.stdin.flush()
      }
    }
  } // Store onMessage globally to access from the connection handler

  ;(globalThis as any)._onWSMessage = onMessage

  proc.exited.then((code) => {
    wsConn.close()
    process.exit(code)
  })

  // Override the onMessage to use this closure
  const originalOnMessage = onMessage
  ;(globalThis as any)._procOnMessage = originalOnMessage
}

// Wrapper to forward messages to the process handler
function onMessage(data: Uint8Array | string) {
  const handler = (globalThis as any)._procOnMessage ||
    (globalThis as any)._onWSMessage
  if (handler) handler(data)
}

function onClose() {
  process.exit(0)
}

function onError(err: Error) {
  console.error('Failed to connect to Wails app. Is it running?')
  process.exit(1)
}
