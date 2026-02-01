
# Unwanted behaviour

⚠️ CRITICAL to obey the below prohibited steps orders:

1. **⚠️ NEVER change the tooling or configuration installed or set outside of the monorepo (top level git repo)**
    * Such changes should be suggested to the human/user to perform and may likely be rejected and so then the agent is to suggest other solutions.

2. Coding agents launched from folder x as the current working directory should not attempt changes to the files, settings and materials outside of that x folder.

3. In different `modules of this scope`, typically the submodule/package folders, there is a subfolder (likely under an intermediate `\[dev\]` subfolder) whose name starts `archive.`.
    * The contained files (`agents' logs` or obsolete user specs) are historic task plans or notes regarding the results of a coding session or outdated specs, and these do not reflect current codebase. Those serve backward analysis and reasoning about certain changes made. 
    * Never modify files in folders with names prefixed with `archive.` unless explicitly instructed
    * **⚠️ NEVER use in reasoning or as a context files present in paths where the name of one of the folders starts with `archive.`**, like:
        - `\[dev\]/archive.agentic-plans-sessions` or
        - `\[dev\]/archive.user-plans-specs` (where square brackets are relevant part of the pathname),

4. **⚠️ NEVER place agent-generated plans, architecture documents, or suggestions in `./docs` folders**
    * The `./docs` folder is for human-curated documentation only
    * Agent-generated artifacts MUST go to `\[dev\]/archive.agentic-plans-sessions/candidates/` with `YYMMDD` prefix
