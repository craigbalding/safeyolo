"""Fixed-argument host operation used by the native Rust proxy.

The native boundary runs this module as a small line-oriented daemon. Keeping
one :class:`DesktopPresenter` alive is part of the protocol: its managed
preview sessions are owned by that process and therefore remain available
after an individual request has completed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import TextIO


def _valid_agent_id(agent_id: object) -> bool:
    return (
        isinstance(agent_id, str)
        and bool(agent_id)
        and len(agent_id) <= 128
        and all(char in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for char in agent_id)
    )


def _load_dependencies():
    try:
        from .agents_store import get_or_mint_agent_id
        from .desktop_presenter import DesktopPresentationError, DesktopPresenter
    except Exception as exc:  # noqa: BLE001 - unavailable host dependencies
        return None, None, None, {"error": type(exc).__name__, "kind": "unavailable"}
    return DesktopPresentationError, DesktopPresenter, get_or_mint_agent_id, None


def _present(
    agent_id: str,
    presenter,
    desktop_presentation_error,
    get_or_mint_agent_id,
) -> tuple[dict, int]:
    if not _valid_agent_id(agent_id):
        return {"error": "invalid agent id", "kind": "invalid"}, 4
    try:
        result = presenter.present(agent_id)
    except desktop_presentation_error as exc:
        # Native listener identity is the configured agent name, while the
        # retained presenter accepts its durable agent_id. Resolve that
        # mapping only inside this trusted host boundary.
        if str(exc) != "Agent not found":
            raise
        try:
            result = presenter.present(get_or_mint_agent_id(agent_id))
        except KeyError:
            raise exc
    except Exception as exc:  # noqa: BLE001 - boundary returns a typed failure
        return {"error": type(exc).__name__, "kind": "failed"}, 3
    return result.to_dict(), 0


def _write_response(stream: TextIO, response: dict) -> None:
    stream.write(json.dumps(response, separators=(",", ":")) + "\n")
    stream.flush()


def _serve_presenter_requests(
    input_stream: TextIO,
    output_stream: TextIO,
    presenter,
    desktop_presentation_error,
    get_or_mint_agent_id,
) -> bool:
    """Return whether the proxy requested an orderly shutdown."""
    for line in input_stream:
        if not line.strip():
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            _write_response(output_stream, {"error": "invalid request", "kind": "protocol"})
            continue
        if isinstance(request, dict) and request.get("shutdown") is True:
            return True
        if not isinstance(request, dict) or not _valid_agent_id(request.get("agent_id")):
            _write_response(output_stream, {"error": "invalid agent id", "kind": "invalid"})
            continue
        try:
            response, _status = _present(
                request["agent_id"],
                presenter,
                desktop_presentation_error,
                get_or_mint_agent_id,
            )
        except desktop_presentation_error as exc:
            response = {
                "error": str(exc),
                "kind": "not_found" if str(exc) == "Agent not found" else "failed",
            }
        except Exception as exc:  # noqa: BLE001 - boundary returns a typed failure
            response = {"error": type(exc).__name__, "kind": "failed"}
        _write_response(output_stream, response)
    return False


def daemon_main(input_stream: TextIO | None = None, output_stream: TextIO | None = None) -> int:
    """Serve validated requests until the Rust proxy asks the owner to stop."""
    input_stream = sys.stdin if input_stream is None else input_stream
    output_stream = sys.stdout if output_stream is None else output_stream
    desktop_presentation_error, desktop_presenter, get_or_mint_agent_id, load_error = _load_dependencies()
    if load_error is not None:
        # Keep the child alive long enough to return a typed unavailable result
        # for every request; the Rust caller can then classify the failure.
        for line in input_stream:
            if line.strip():
                try:
                    request = json.loads(line)
                except json.JSONDecodeError:
                    _write_response(output_stream, {"error": "invalid request", "kind": "protocol"})
                    continue
                if isinstance(request, dict) and request.get("shutdown") is True:
                    _write_response(output_stream, {"status": "stopped"})
                    return 0
                _write_response(output_stream, load_error)
        return 0

    presenter = desktop_presenter()
    try:
        shutdown_requested = _serve_presenter_requests(
            input_stream, output_stream, presenter, desktop_presentation_error, get_or_mint_agent_id
        )
    finally:
        # Shutdown, proxy disconnect and unexpected protocol failures all
        # release the managed previews and their close-audit events.
        presenter.close_all()
    if shutdown_requested:
        _write_response(output_stream, {"status": "stopped"})
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent-id")
    parser.add_argument("--daemon", action="store_true")
    args = parser.parse_args()
    if args.daemon:
        # The guest launcher and other host operations inherit fd 1. Keep the
        # original pipe only for JSON responses; send incidental child output
        # to stderr so it cannot become a bogus response to the Rust proxy.
        sys.stdout.flush()
        response_fd = os.dup(sys.stdout.fileno())
        os.dup2(sys.stderr.fileno(), sys.stdout.fileno())
        with os.fdopen(response_fd, "w", encoding=sys.stdout.encoding or "utf-8") as responses:
            return daemon_main(output_stream=responses)
    if args.agent_id is None:
        parser.error("the following arguments are required: --agent-id")
    desktop_presentation_error, desktop_presenter, get_or_mint_agent_id, load_error = _load_dependencies()
    if load_error is not None:
        print(json.dumps(load_error, separators=(",", ":")))
        return 3
    try:
        response, status = _present(
            args.agent_id,
            desktop_presenter(),
            desktop_presentation_error,
            get_or_mint_agent_id,
        )
    except desktop_presentation_error as exc:
        response = {
            "error": str(exc),
            "kind": "not_found" if str(exc) == "Agent not found" else "failed",
        }
        status = 2 if str(exc) == "Agent not found" else 3
    print(json.dumps(response, separators=(",", ":")))
    return status


if __name__ == "__main__":
    sys.exit(main())
