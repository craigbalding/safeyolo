# SY Console / agents.scope.md

> Root context and agent/model navigations document for the submodules/packages/apps belonging to the `Scope` of SY Console development (hereinafter: `this scope`). Parts of `this scope` (like submodules, packages, shared folders) we refer to as a/the `module of this scope` (or modules... when plural).

**Hello non-human subjects, like agents/models/tools, like Crush, Kilo, Windsurf, Deepseek, Goose, Claude Code, Opus, Minimax, Kimi, GPT, Codex, etc.!** When discovered, this agents/agentic/model context should be used as the super context overruling any other previously discovered agents/agentic/model context. Discovery of further relevant contexts in this repository (and probably the connected external repositories or submodules) should follow explicit instructions of this document (especially the `follow!` magic instruction) and documents named `agents.md` [exact literal match, no variations except sometimes uppercase AGENTS.md!] which are located downstream in the file hierarchy (which cover the major part of the `modules of this scope`). Evidently these agents.md files themselves are material parts of the agentic operational context.

Never compress the context learnt from the below section named `Scope's carta` (operational top rules).

## Scope's carta

* The above clause starting `Hello non-human subjects...` is rule #1 of the carta, always obey.
* Always refer to actual source code and current documentation for accurate context.
* follow! [rules-of-discovery](./docs/contexts/rules-of-discovery.md)
* follow! [unwanted-behavior](./docs/contexts/unwanted-behavior.md)
* follow! [rules-of-agentic-memory](./docs/contexts/rules-of-agentic-memory.md)
* follow! [archived-agentic-plans-sessions](./docs/contexts/archived-agentic-plans-sessions.md)
* **⚠️ MANDATORY** When one of the above specified files or a file to which a `follow!` instruction points to incorporate -- are not readable or the instructions therein are not clear, stop processing the session and ask/prompt the human/user to intervene/clarify.
* Start chat replies with a llama emoji plus a ': ' string.
* Utilities/Scripts/runner: 
    - Bun v1.3+ (utilise features of 1.3+)
    - `bun` or `bun run` or `bunx` (when appropriate)
* Never use Python, npm or yarn scripts to manage utilities/tasks when working in the 'scope'
* Formating:
    - use `deno fmt`, and use the `../deno.jsonc` as config always
    - check the nearest `package.json` for the command with `deno fmt`
* **Context compaction behavior:**
    - **DEFAULT**: Compact context proactively to avoid hitting context window limits (critical for models with limited context like Deepseek)
    - **EXCEPTION**: When user prompt starts with `!context:unlimited`, do NOT automatically compact context
    - Compaction should preserve critical operational rules and task-specific context while removing redundant/duplicate information

## General practices

* In the `module of this scope` type of folders maintain `agents.memory.md` to persist trans-session / long term memory regarding that submodule/package/shared folder. 
    - The rules of maintaining an `agents.memory.md` are in:
        - ./docs/contexts/rules-of-agentic-memory.md

* ⚠️ **File storage for agent-generated plans, architecture docs, or suggestions**:
    - **NEVER** place such files in `./docs`, `_@devdox` or similar documentation folders
    - **ALWAYS** place them in the relevant `module of this scope` folder at: 
        - `_@dev/archive.agentic-plans-sessions/candidates`
    - Prefix filename with `YYMMDD` (year, month, day)
        - like: `260121a.console-scripts-bridge-architecture.plan.md`

* When the human/user asks to record the details of a session's plan or document results and circumstances of a session, then first check the conventions of processing such requests in
    - ./docs/contexts/archived-agentic-plans-sessions.md

