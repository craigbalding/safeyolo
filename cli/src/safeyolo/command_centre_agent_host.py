"""Fixed host agent operations for the native Command Centre Admin routes."""

from __future__ import annotations

import json
import logging
import sys
from contextlib import redirect_stdout

from .agent_lifecycle import AgentLifecycleError, list_agent_runtimes, start_agent, stop_agent

log = logging.getLogger(__name__)


def main() -> int:
    """Write one JSON result for a fixed operation selected by the native proxy."""
    arguments = sys.argv[1:]
    if arguments == ["list"]:
        operation = "list"
        agent_id = None
    elif len(arguments) == 2 and arguments[0] in {"start", "start-interactive", "stop"}:
        operation, agent_id = arguments
    else:
        print(json.dumps({"error": "invalid host operation", "status_code": 400}))
        return 0

    try:
        # The retained CLI helpers may print progress. Keep stdout as one JSON
        # response so the native route never mistakes progress for agent state.
        with redirect_stdout(sys.stderr):
            if operation == "list":
                result = {"agents": [agent.to_dict() for agent in list_agent_runtimes()]}
            elif operation == "stop":
                result = stop_agent(agent_id).to_dict()
            else:
                result = start_agent(agent_id, interactive=operation == "start-interactive").to_dict()
    except AgentLifecycleError as exc:
        result = {"error": str(exc), "status_code": exc.status_code}
    except Exception as exc:
        log.exception("Command Centre host agent operation failed")
        result = {"error": f"Agent operation failed: {type(exc).__name__}", "status_code": 500}

    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
