# 🤖 Agent Context entry point for /cockpit/app, a Wails3 app island submodule

<!-- import: ../agents.md -->

## ⚠️ CRITICAL: Context Loading Sequence
**You must perform the following context injection before answering any prompt in this directory:**

1.  **LOAD PARENT CONTEXT:** Before proceeding, read and fully integrate the instructions found in the file at `../agents.md` (relative to this file).
    * *Why:* Those are the primary rules for submodule/app (critical context for the 'Cockpit' scope which includes the current app).
    * *Instruction:* Treat the contents of `../agents.md` as the **base layer** of context/instructions.

2.  **APPLY LOCAL CONTEXT:** Apply the rules defined in *this* file (below) on top of the base layer. This one provides specific context governing the Wails3 'app' (a module of the scope).

3. Apply other context files according to the instructions of discovery defined by the above ones (specifically following the conditional rule of `follow!`)

4. ./agents.memory.md - persistant memory collected during the previous sessions

5. /agents.md - the root context explaining the superscope, not critical for most tasks unless otherwise instructed

Ignore /CLAUDE.md if present

---

CRITICAL: Instructions below should only be processed when the rules/conventions defined and referenced in the ../agents.md were processed.

## Local module instructions

* TypeScript conventions:
    - follow! [`conventions/typescript-standards.md`](../docs/conventions/typescript-standards.md)
