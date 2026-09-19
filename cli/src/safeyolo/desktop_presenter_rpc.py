"""Fixed-argument host operation used by the native Rust proxy."""

from __future__ import annotations

import argparse
import json
import sys

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent-id", required=True)
    args = parser.parse_args()
    agent_id = args.agent_id
    if (
        not agent_id
        or len(agent_id) > 128
        or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for char in agent_id)
    ):
        print(json.dumps({"error": "invalid agent id"}))
        return 4
    try:
        from .desktop_presenter import DesktopPresentationError, DesktopPresenter
        from .agents_store import get_or_mint_agent_id
    except Exception as exc:  # noqa: BLE001 - unavailable host dependencies
        print(json.dumps({"error": type(exc).__name__}))
        return 3
    try:
        presenter = DesktopPresenter()
        try:
            result = presenter.present(agent_id)
        except DesktopPresentationError as exc:
            # Native listener identity is the configured agent name, while
            # the retained presenter accepts its durable agent_id. Resolve
            # that mapping only inside the trusted host boundary.
            if str(exc) != "Agent not found":
                raise
            try:
                result = presenter.present(get_or_mint_agent_id(agent_id))
            except KeyError:
                raise exc
    except DesktopPresentationError as exc:
        print(json.dumps({"error": str(exc)}))
        return 2 if str(exc) == "Agent not found" else 3
    except Exception as exc:  # noqa: BLE001 - boundary returns a typed failure
        print(json.dumps({"error": type(exc).__name__}))
        return 3
    print(json.dumps(result.to_dict(), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
