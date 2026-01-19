
# Forbidden behaviour

1. Never change the tooling or configuration installed or set outside of the monorepo (top level git repo)
    * Such changes should be suggested to the human/user to perform and may likely be rejected and so then the agent is to suggest other solutions.

1. Coding agents launched from folder x as the current working directory should not attempt changes to the files, settings and materials outside of that x folder.

1. In different `modules of this scope`, typically the submodule/package folders, there are subfolders whose path shape includes `[dev]/planslog/` (where '[' is relevant part of the name).
    * The contained files (`agents' logs`) are mostly historic task plans or notes regarding the results of a coding session, and these do not reflect current codebase. Those serve backward analysis and reasoning about certain changes made. 
    * Never modify files in `[dev]/planslog/` unless explicitly instructed
    * Never use files in `[dev]/planslog/` in reasoning or as a context
