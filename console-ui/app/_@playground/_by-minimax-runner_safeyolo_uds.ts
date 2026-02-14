/**
 * POC: Connect to SafeYolo watch UDS socket and stream JSONL events.
 *
 * Usage:
 *   bun run runner_safeyolo_uds.ts
 *
 * Prerequisites:
 *   - SafeYolo running with: safeyolo watch --socket /tmp/safeyolo.sock
 */

const SOCKET_PATH = process.env.SAFEYOLO_SOCKET || "/tmp/safeyolo.sock";

interface SafeYoloEvent {
  ts: string;
  event: string;
  host?: string;
  path?: string;
  decision?: string;
  reason?: string;
  rule?: string;
  fingerprint?: string;
  [key: string]: unknown;
}

class LineReader {
  private buffer = "";

  feed(data: Uint8Array): string[] {
    const text = new TextDecoder().decode(data);
    this.buffer += text;
    const lines: string[] = [];

    let idx: number;
    while ((idx = this.buffer.indexOf("\n")) !== -1) {
      lines.push(this.buffer.slice(0, idx));
      this.buffer = this.buffer.slice(idx + 1);
    }

    return lines;
  }
}

async function main() {
  console.log(`[UDS Consumer] Connecting to ${SOCKET_PATH}...`);

  const lineReader = new LineReader();

  let resolveReady: () => void;
  const readyPromise = new Promise<void>((resolve) => {
    resolveReady = resolve;
  });

  const socket = await Bun.connect({
    unix: SOCKET_PATH,
    socket: {
      open(socket) {
        console.log("[UDS Consumer] Connected! Streaming events...\n");
        resolveReady();
      },
      data(socket, data: Uint8Array) {
        const lines = lineReader.feed(data);

        for (const line of lines) {
          if (!line.trim()) continue;

          try {
            const event: SafeYoloEvent = JSON.parse(line);

            const ts = event.ts?.split("T")[1]?.slice(0, 8) || "??:??:??";
            const evt = event.event || "unknown";
            const host = event.host || "-";
            const decision = event.decision || "";

            const decisionColor =
              decision === "block" ? "\x1b[31m" : decision === "warn" ? "\x1b[33m" : "\x1b[36m";
            const reset = "\x1b[0m";

            console.log(
              `[${ts}] ${decisionColor}${evt}${reset} host=${host} ${decision ? `decision=${decision}` : ""}`
            );

            if (event.decision === "block") {
              console.log(`         ↳ rule=${event.rule} reason=${event.reason}`);
            }
          } catch {
            console.log(`[malformed] ${line.slice(0, 100)}...`);
          }
        }
      },
      error(socket, error) {
        console.error(`\n[UDS Consumer] Socket error: ${error}`);
      },
      close(socket) {
        console.log("\n[UDS Consumer] Socket closed by server");
      },
    },
  });

  await readyPromise;

  // Keep process alive until socket closes
  await new Promise<void>((resolve) => {
    const checkInterval = setInterval(() => {
      if (socket.readyState <= 0) {
        clearInterval(checkInterval);
        resolve();
      }
    }, 100);
  });
}

main().catch(console.error);
