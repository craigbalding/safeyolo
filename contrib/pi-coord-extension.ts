/** Direct Coord send tool for Pi factory workers. */

import { readFile } from "node:fs/promises";

import { Type } from "@earendil-works/pi-ai";
import { defineTool, type ExtensionAPI } from "@earendil-works/pi-coding-agent";

const AGENT_API = "http://_safeyolo.proxy.internal";

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
		const token = (await readFile("/app/agent_token", "utf8")).trim();
		const timeout = AbortSignal.timeout(30_000);
		const requestSignal = signal ? AbortSignal.any([signal, timeout]) : timeout;
		const response = await fetch(
			`${AGENT_API}/api/coord/rooms/${encodeURIComponent(params.room_name)}/send`,
			{
				method: "POST",
				headers: {
					Authorization: `Bearer ${token}`,
					"Content-Type": "application/json",
				},
				body: JSON.stringify({
					body: params.body,
					declared_content_type: params.declared_content_type ?? "text/markdown",
					notify: params.notify ?? "none",
				}),
				signal: requestSignal,
			},
		);
		const text = await response.text();
		let result: unknown;
		try {
			result = JSON.parse(text);
		} catch {
			result = { error: text.slice(0, 300) || "invalid JSON response" };
		}
		if (!response.ok) {
			throw new Error(`Coord send failed with HTTP ${response.status}`);
		}
		return {
			content: [{ type: "text", text: "Coord message sent." }],
			details: result,
		};
	},
});

export default function (pi: ExtensionAPI) {
	pi.registerTool(sendTool);
}
