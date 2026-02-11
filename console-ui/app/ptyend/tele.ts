#!/usr/bin/env bun
import { spawn } from 'bun'
import { parseArgs, type ParseArgsOptionsConfig } from 'node:util'

const me_ = 'SafeYolo tele client'
const err_: [undefined | string, string] = [undefined, `${me_} failed`]
const getErr = (err?: unknown) => `${me_} failed: ${err || err_[0] || err_[1]}`

try {
  if (!import.meta.main) {
    throw `Not a library`
  }

  const options = {
    socket: { type: 'string', default: '/tmp/safeyolo-runner.sock' },
    cols: { type: 'string', default: '80' },
    rows: { type: 'string', default: '24' },
    tcp: { type: 'boolean', default: false },
  } satisfies ParseArgsOptionsConfig

  const dashIndex = Bun.argv.indexOf('---')
  if (dashIndex === -1) {
    throw `\nUsage: ./runner.ts [flags] --- [command]`
  }

  const runnerArgs = Bun.argv.slice(2, dashIndex)
  const commandArgs = Bun.argv.slice(dashIndex + 1)
  if (commandArgs.length === 0) {
    throw `\nNo command provided after ---`
  }

  const { values } = parseArgs({
    args: runnerArgs,
    options,
    strict: true,
    allowPositionals: false,
  })

  // Simple length-prefixed frame protocol, [1 byte type][4 bytes length][data]
  const TYPE_OUTPUT = 0x00 // pty stdout -> socket
  const TYPE_INPUT = 0x01 // socket -> pty stdin
  const TYPE_RESIZE = 0x02 // socket -> pty resize

  let proc: ReturnType<typeof spawn>
  let socket: Bun.Socket

  try {
    socket = await Bun.connect(getClientObj())
    proc = spawn(commandArgs, {
      stdin: 'pipe',
      stdout: 'pipe',
      terminal: {
        cols: parseInt(values.cols),
        rows: parseInt(values.rows),
        data(_, data: Uint8Array) {
          socket.write(encodeFrame(TYPE_OUTPUT, data))
        },
      },
    })
    const procExitCode = await proc.exited
    socket.end()
    process.exit(procExitCode)
  } catch (err: unknown) {
    throw `${err}`
  }

  function getClientObj(): Bun.UnixSocketOptions {
    return {
      unix: values.socket,
      socket: {
        data(_socket, data: Uint8Array) {
          let offset = 0
          while (typeof proc !== 'undefined' && offset < data.length) {
            if (offset + 5 > data.length) break

            const type = data[offset]!
            const view = new DataView(data.buffer, data.byteOffset)
            const length = view.getUint32(offset + 1, false)

            if (offset + 5 + length > data.length) break

            const pyl = data.slice(offset + 5, offset + 5 + length)

            if (
              type === TYPE_INPUT && proc?.stdin &&
              typeof proc?.stdin === 'object'
            ) {
              proc.stdin.write(pyl)
              proc.stdin.flush()
            } else if (type === TYPE_RESIZE && proc?.terminal) {
              try {
                const msg = JSON.parse(new TextDecoder().decode(pyl))
                if (msg.cols && msg.rows) {
                  proc.terminal.resize(msg.cols, msg.rows)
                }
              } catch { /* ignore invalid resize */ }
            }

            offset += 5 + length
          }
        },
        close() {
          process.exit(0)
        },
        error(_socket, error) {
          throw `Connection error: ${error.message}`
        },
      },
    }
  }
} catch (err: unknown) {
  console.log(getErr(err))
  process.exit(1)
}

function encodeFrame(type: number, data: Uint8Array): Uint8Array {
  const frame = new Uint8Array(5 + data.length)
  frame[0] = type
  const view = new DataView(frame.buffer)
  view.setUint32(1, data.length, false) // big-endian
  frame.set(data, 5)
  return frame
}
