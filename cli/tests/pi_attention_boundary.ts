/** A controlled native tool boundary for real Pi attention probes. */
import { existsSync, watch } from "node:fs";
import { dirname } from "node:path";
import { Type } from "@earendil-works/pi-ai";
import { defineTool, type ExtensionAPI } from "@earendil-works/pi-coding-agent";

export default function (pi: ExtensionAPI) {
    pi.registerTool(defineTool({
        name: "attention_boundary",
        label: "Attention proof boundary",
        description: "Wait for the test driver to release a native tool boundary.",
        parameters: Type.Object({}),
        async execute(_id, _params, signal) {
            signal?.throwIfAborted();
            const release = process.env.SAFEYOLO_ATTENTION_RELEASE_FILE;
            if (!release) throw new Error("The attention test driver must select its release file");
            await new Promise<void>((resolve, reject) => {
                const finish = () => { watcher.close(); signal?.removeEventListener("abort", abort); resolve(); };
                const abort = () => { watcher.close(); reject(new Error("Attention boundary aborted")); };
                const watcher = watch(dirname(release), () => { if (existsSync(release)) finish(); });
                signal?.addEventListener("abort", abort, { once: true });
                if (existsSync(release)) finish();
            });
            return { content: [{ type: "text", text: "attention boundary released" }], details: {} };
        },
    }));
}
