/** Direct Coord messaging and history tools for Pi factory workers. */

import { readFile } from "node:fs/promises";

import { Type } from "@earendil-works/pi-ai";
import { defineTool, type ExtensionAPI } from "@earendil-works/pi-coding-agent";

const AGENT_API = "http://_safeyolo.proxy.internal";

async function coordRequest(path: string, init: RequestInit, signal?: AbortSignal) {
	const token = (await readFile("/app/agent_token", "utf8")).trim();
	const timeout = AbortSignal.timeout(30_000);
	const response = await fetch(`${AGENT_API}${path}`, {
		...init,
		headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
		signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
	});
	if (!response.ok) {
		throw new Error(`Coord ${init.method ?? "GET"} failed with HTTP ${response.status}`);
	}
	return response.json();
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
		const result = await coordRequest(
			`/api/coord/rooms/${encodeURIComponent(params.room_name)}/send`,
			{
				method: "POST",
				body: JSON.stringify({
					body: params.body,
					declared_content_type: params.declared_content_type ?? "text/markdown",
					notify: params.notify ?? "none",
				}),
			},
			signal,
		);
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
		const query = new URLSearchParams({
			since: String(params.since_sequence ?? 0),
			limit: String(params.limit ?? 50),
		});
		const result = await coordRequest(
			`/api/coord/rooms/${encodeURIComponent(params.room_name)}/messages?${query}`,
			{ method: "GET" },
			signal,
		);
		return { content: [{ type: "text", text: JSON.stringify(result) }], details: result };
	},
});

export default function (pi: ExtensionAPI) {
	pi.registerTool(sendTool);
	pi.registerTool(readRoomTool);
}
