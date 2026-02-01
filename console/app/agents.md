# 🤖 Agent Context entry point for the SY Console Wails3 app, an island submodule

<!-- import: ../agents.scope.md -->

## ⚠️ CRITICAL: Context Loading Sequence

**You must perform the following context injection before answering any prompt
in this directory:**

1. **LOAD PARENT CONTEXT:** Before proceeding, read and fully integrate the
   instructions found in the file at `../agents.scope.md` (relative to this
   file).
   - _Why:_ Those are the primary rules for submodule/app (critical context for
     the 'Console' scope which includes the current app).
   - _Instruction:_ Treat the contents of `../agents.scope.md` as the **base
     layer** of context/instructions.

2. **APPLY LOCAL CONTEXT:** Apply the rules defined in _this_ file (below) on
   top of the base layer. This one provides specific context governing the
   Wails3 'app' (a module of the scope).

3. Apply other context files according to the instructions of discovery defined
   by the above ones (specifically following the conditional rule of `follow!`)

4. ./agents.memory.md - persistent memory collected during the previous sessions

5. /agents.md - the root context explaining the superscope, not critical for
   most tasks unless otherwise instructed

Ignore /CLAUDE.md if present

---

CRITICAL: Instructions below should only be processed when the rules/conventions
defined and referenced in the ../agents.scope.md were processed.

## Local module instructions

- ⚠️ **TypeScript conventions (MANDATORY before generating any TS/JS code)**:
  - follow!
    [`conventions/typescript-standards.md`](../docs/conventions/typescript-standards.md)
  - Key reminders (read full file for complete rules):
    - Prefer `type` over `interface`
    - No semicolons unless necessary
    - Single quotes over double quotes
    - Space between function name and parentheses
