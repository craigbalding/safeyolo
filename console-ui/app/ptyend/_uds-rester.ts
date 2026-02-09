#!/usr/bin/env bun
async function getSocketPath(): Promise<string> {
  // Priority: XDG_RUNTIME_DIR (systemd, most modern), then home, then tmp
  const base = process.env.XDG_RUNTIME_DIR 
    || `${process.env.HOME}/.cache`
    || `/tmp`;
    
  // Test writability
  try {
    const testFile = `${base}/.wails3-test-${Date.now()}`;
    await Bun.write(testFile, "");
    await Bun.file(testFile).delete();
    return `${base}/wails3-${crypto.randomUUID()}.sock`;
  } catch {
    // Fallback to TCP if UDS fails
    console.error("UDS unavailable, use --tcp flag");
    process.exit(1);
  }
}