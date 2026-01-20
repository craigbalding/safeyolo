
# Forbidden behaviour

⚠️ CRITICAL to obey the below orders:

1. ⚠️ **NEVER change the tooling or configuration installed or set outside of the monorepo (top level git repo)**
    * Such changes should be suggested to the human/user to perform and may likely be rejected and so then the agent is to suggest other solutions.

2. Coding agents launched from folder x as the current working directory should not attempt changes to the files, settings and materials outside of that x folder.

3. In different `modules of this scope`, typically the submodule/package folders, there are subfolders whose path shape includes `[dev]/planslog` (where '[' is relevant part of the name).
    * The contained files (`agents' logs`) are mostly historic task plans or notes regarding the results of a coding session, and these do not reflect current codebase. Those serve backward analysis and reasoning about certain changes made. 
    * Never modify files in `[dev]/planslog/` unless explicitly instructed
    * **⚠️ NEVER use files whose path shape includes `[dev]/planslog` (where '[' is relevant part of the name) in reasoning or as a context**
