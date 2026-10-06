/** Direct Coord messaging and history tools for Pi factory workers. */

import { spawn } from "node:child_process";

import { Type } from "@earendil-works/pi-ai";
import { defineTool, type ExtensionAPI } from "@earendil-works/pi-coding-agent";

function coordRequest(tool: string, args: unknown, signal?: AbortSignal): Promise<unknown> {
    signal?.throwIfAborted();
    return new Promise((resolve, reject) => {
        // One native command owns proxy routing and reads the current token.
        // Pi's extension retains its existing tool/event protocol only.
        const child = spawn("/home/agent/.safeyolo/safeyolo-coord", ["call", tool], {
            stdio: ["pipe", "pipe", "pipe"], signal,
        });
        let stdout = "";
        let stderr = "";
        child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
        child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
        child.on("error", reject);
        child.on("close", (code) => {
            if (code !== 0) { reject(new Error(stderr.trim() || `Native Coord ${tool} failed; inspect history before repeating an uncertain send`)); return; }
            try { resolve(JSON.parse(stdout)); } catch (error) { reject(error); }
        });
        child.stdin.on("error", reject);
        child.stdin.end(JSON.stringify(args));
    });
}

const sendTool = defineTool({
	name: "send",
	label: "Coord send",
	description:
		"Send one canonical message to a SafeYolo Coord room using this agent's transport identity.",
	promptSnippet: "Send a canonical message or factory transition to a SafeYolo Coord room",
	promptGuidelines: [
		"Use send for every Coord handoff or terminal response required by the bound factory role.",
		"Use the exact room, body, and notify targets required by the supervisor checkpoint and role contract.",
	],
	parameters: Type.Object({
		room_name: Type.String({ description: "Configured Coord room name" }),
		body: Type.String({ description: "Complete message body" }),
		declared_content_type: Type.Optional(
			Type.String({ description: "Content type; defaults to text/markdown" }),
		),
		notify: Type.Optional(
			Type.Union([
				Type.Literal("none"),
				Type.Literal("room"),
				Type.Array(Type.String()),
			]),
		),
	}),

	async execute(_toolCallId, params, signal) {
        const result = await coordRequest("send", params, signal);
		return {
			content: [{ type: "text", text: "Coord message sent." }],
			details: result,
		};
	},
});

const readRoomTool = defineTool({
	name: "read_room",
	label: "Coord room history",
	description:
		"Read retained messages, including your own sends, from a SafeYolo Coord room you can receive. Returns canonical sender identities, message sequences, and pagination metadata.",
	promptSnippet: "Recover specific prior decisions or findings from Coord room history",
	promptGuidelines: [
		"Use the supplied checkpoint first. Read history only when useful context is missing, not on every wake.",
		"For a known message sequence N, use since_sequence=N-1 and limit=1; verify the returned sequence and canonical sender.",
		"Follow next_cursor only for further history pages when needed. This does not change the supervisor attention cursor or assign work.",
	],
	parameters: Type.Object({
		room_name: Type.String({ description: "Coord room name" }),
		since_sequence: Type.Optional(Type.Integer({
			minimum: 0,
			description: "Read messages after this room sequence (default: 0)",
		})),
		limit: Type.Optional(Type.Integer({
			minimum: 1,
			description: "Requested page size (default: 50); the server applies its page bounds",
		})),
	}),
	async execute(_toolCallId, params, signal) {
        const result = await coordRequest("read_room", params, signal);
		return { content: [{ type: "text", text: JSON.stringify(result) }], details: result };
	},
});

export default function (pi: ExtensionAPI) {
	pi.registerTool(sendTool);
	pi.registerTool(readRoomTool);
}
