// Run with: node cli/tests/run_pi_coord_extension.mjs /path/to/pi-coding-agent
// Uses Pi's installed TypeScript loader and tool definitions. Registration,
// HTTP, and token reads are synthetic; this does not invoke a model.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = fileURLToPath(new URL("../../", import.meta.url));
const piPackage = process.argv[2];
assert.ok(piPackage, "Pass the installed pi-coding-agent package directory");
const requirePi = createRequire(resolve(piPackage, "package.json"));
const { createJiti } = requirePi("jiti");
const jiti = createJiti(import.meta.url, { alias: {
  "@earendil-works/pi-coding-agent": resolve(piPackage, "dist/core/extensions/types.js"),
  "@earendil-works/pi-ai": resolve(piPackage, "node_modules/@earendil-works/pi-ai/dist/compat.js"),
} });

await test("native Pi Coord tools", async (t) => {
  const originalRead = fs.readFile;
  const originalFetch = globalThis.fetch;
  let tokenReads = 0;
  const calls = [];
  let response = {};
  fs.readFile = async (path, ...args) => {
    if (path === "/app/agent_token") {
      tokenReads++;
      return "fixture-token\n";
    }
    return originalRead(path, ...args);
  };
  syncBuiltinESMExports();
  globalThis.fetch = async (url, options) => {
    calls.push({ url: String(url), options });
    assert.equal(options.headers.Authorization, "Bearer fixture-token");
    assert.ok(options.signal instanceof AbortSignal);
    options.signal.throwIfAborted();
    return response;
  };
  try {
    const register = await jiti.import(resolve(root, "contrib/pi-coord-extension.ts"), { default: true });
    const tools = new Map();
    register({ registerTool(tool) { tools.set(tool.name, tool); } });
    assert.deepEqual([...tools.keys()].sort(), ["read_room", "send"]);
    const read = tools.get("read_room");
    const send = tools.get("send");
    const page = {
      messages: [{ sequence: 42, sender_kind: "agent", sender_agent_name: "lens",
        body: "CHANGES_REQUIRED target=https://example.test/review/old\nSpecific earlier finding" }],
      next_cursor: 42, has_more: true, history_truncated: false, oldest_available_at: null,
    };

    await t.test("exact prior finding is visible in model content, not only details", async () => {
      response = { ok: true, json: async () => page };
      const result = await read.execute("read-1", { room_name: "backlog", since_sequence: 41, limit: 1 });
      assert.equal(calls.at(-1).url, "http://_safeyolo.proxy.internal/api/coord/rooms/backlog/messages?since=41&limit=1");
      assert.equal(calls.at(-1).options.method, "GET");
      assert.equal(calls.at(-1).options.body, undefined);
      assert.deepEqual(JSON.parse(result.content[0].text), page);
      assert.deepEqual(result.details, page);
    });
    await t.test("defaults, escaped room, and retention metadata survive", async () => {
      const retained = { ...page, messages: [], history_truncated: true, oldest_available_at: "2026-09-05" };
      response = { ok: true, json: async () => retained };
      const result = await read.execute("read-2", { room_name: "room/name" });
      assert.equal(calls.at(-1).url, "http://_safeyolo.proxy.internal/api/coord/rooms/room%2Fname/messages?since=0&limit=50");
      assert.deepEqual(JSON.parse(result.content[0].text), retained);
    });
    await t.test("failed reads and malformed JSON are errors, not missing history", async () => {
      response = { ok: false, status: 403 };
      await assert.rejects(read.execute("read-3", { room_name: "backlog" }), /HTTP 403/);
      response = { ok: true, json: async () => { throw new SyntaxError("invalid JSON"); } };
      await assert.rejects(read.execute("read-4", { room_name: "backlog" }), /invalid JSON/);
      const abort = new AbortController();
      abort.abort();
      await assert.rejects(read.execute("read-5", { room_name: "backlog" }, abort.signal), { name: "AbortError" });
    });
    await t.test("send preserves its canonical response and targeting", async () => {
      const sent = { envelope: { body: "DONE", sequence: 43 }, attention_status: "ready" };
      response = { ok: true, json: async () => sent };
      const result = await send.execute("send-1", { room_name: "backlog", body: "DONE", notify: ["relay"] });
      assert.equal(calls.at(-1).options.method, "POST");
      assert.deepEqual(JSON.parse(calls.at(-1).options.body), {
        body: "DONE", declared_content_type: "text/markdown", notify: ["relay"],
      });
      assert.deepEqual(result.details, sent);
    });
    assert.equal(tokenReads, calls.length, "each request reads its current token");
  } finally {
    fs.readFile = originalRead;
    syncBuiltinESMExports();
    globalThis.fetch = originalFetch;
  }
});
