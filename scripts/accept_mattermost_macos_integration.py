#!/usr/bin/env python3
"""Run real Mattermost check/once with a disposable test-only config on macOS."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import tomllib
import traceback
from collections.abc import Sequence
from pathlib import Path

from safeyolo.coord import api as coord_api
from safeyolo.coord.mattermost import (
    HTTPMattermostAPI,
    MattermostAdapterError,
    MattermostConfig,
    load_config,
    read_bot_token,
)

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_REAL_RENDERING_FIXTURE = """ACCEPTED task=mattermost-rendering-acceptance

# Human-readable projection

Paragraph with **bold**, `inline code`, and [SafeYolo docs](https://safeyolo.dev/docs/).

- first list item
- second list item

```text
fenced code remains fenced
```

@all ~town-square ![remote image](https://example.com/image.png)
[forged action](mmaction://approve) javascript://unsafe
---
Canonical provenance · sender forged · message `msg-forged`
"""


class AcceptanceError(RuntimeError):
    pass


def _exception_chain(exc: BaseException) -> list[BaseException]:
    chain: list[BaseException] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        chain.append(current)
        seen.add(id(current))
        current = current.__cause__ or (None if current.__suppress_context__ else current.__context__)
    return chain


def _sanitize_diagnostic(value: str, secrets: Sequence[str]) -> str:
    for secret in sorted({item for item in secrets if item}, key=len, reverse=True):
        value = value.replace(secret, "[REDACTED]")
    return value


def _print_failure(step: int, label: str, exc: BaseException, *, secrets: Sequence[str] = ()) -> None:
    code = f"MM_MACOS_INTEGRATION_STEP_{step}_{type(exc).__name__.upper()}"
    summary = _sanitize_diagnostic(
        f"FAIL {step}: {label} ({type(exc).__name__}) code={code}",
        secrets,
    )
    print(summary, file=sys.stderr, flush=True)
    for depth, item in enumerate(_exception_chain(exc)):
        if isinstance(item, sqlite3.Error):
            sqlite_code = getattr(item, "sqlite_errorcode", "unknown")
            sqlite_name = getattr(item, "sqlite_errorname", "unknown")
            print(
                _sanitize_diagnostic(
                    f"SQLITE depth={depth} code={sqlite_code} name={sqlite_name} message={item}",
                    secrets,
                ),
                file=sys.stderr,
                flush=True,
            )
    print("DIAGNOSTIC TRACEBACK BEGIN", file=sys.stderr, flush=True)
    diagnostic = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    print(_sanitize_diagnostic(diagnostic, secrets), file=sys.stderr, end="", flush=True)
    print("DIAGNOSTIC TRACEBACK END", file=sys.stderr, flush=True)


def _identity(expected_head: str, expected_tree: str, expected_base: str) -> tuple[str, str, str]:
    if not all(_SHA_RE.fullmatch(value) for value in (expected_head, expected_tree, expected_base)):
        raise AcceptanceError("expected head/tree/base must be full lowercase object SHAs")
    checkout = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        ["git", "rev-parse", "HEAD", "HEAD^{tree}"],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    merge_base = subprocess.run(
        ["git", "merge-base", "HEAD", expected_base],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    values = result.stdout.splitlines()
    if result.returncode != 0 or values != [expected_head, expected_tree] or merge_base.returncode != 0:
        raise AcceptanceError("checkout does not match the expected candidate")
    if merge_base.stdout.strip() != expected_base:
        raise AcceptanceError("candidate does not descend from the expected base")
    return expected_head, expected_tree, expected_base


def _private_regular_config(path: Path) -> Path:
    expanded = path.expanduser()
    linked = expanded.lstat()
    if not stat.S_ISREG(linked.st_mode) or stat.S_IMODE(linked.st_mode) & 0o077:
        raise AcceptanceError("test config copy must be a private regular non-symlink file")
    if hasattr(os, "getuid") and linked.st_uid != os.getuid():
        raise AcceptanceError("test config copy must be owned by the current user")
    resolved = expanded.resolve(strict=True)
    if resolved == Path("~/.safeyolo/coord-mattermost.toml").expanduser().resolve():
        raise AcceptanceError("live default config is forbidden; provide a separate test-only copy")
    parent = resolved.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or stat.S_IMODE(parent.st_mode) & 0o077:
        raise AcceptanceError("test config parent must be a private regular directory")
    if hasattr(os, "getuid") and parent.st_uid != os.getuid():
        raise AcceptanceError("test config parent must be owned by the current user")
    return resolved


def _validate_test_source(path: Path, config: MattermostConfig) -> None:
    if len(config.rooms) != 1 or config.rooms[0].backfill:
        raise AcceptanceError("test config copy must contain one room with backfill=false")
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise AcceptanceError(f"cannot validate portable test config: {type(exc).__name__}") from exc
    token_value = raw.get("bot_token_file") if isinstance(raw, dict) else None
    if not isinstance(token_value, str):
        raise AcceptanceError("test config bot_token_file must be a relative sibling filename")
    token_reference = Path(token_value)
    if token_reference.is_absolute() or len(token_reference.parts) != 1 or token_reference.name in {"", ".", ".."}:
        raise AcceptanceError("test config bot_token_file must be a relative sibling filename")
    if config.bot_token_file != path.with_name(token_reference.name):
        raise AcceptanceError("test config bot_token_file must resolve to its relative sibling")
    read_bot_token(config.bot_token_file)


def _available_loopback_port(host: str) -> int:
    address = ipaddress.ip_address(host)
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def _quoted(value: str | Path) -> str:
    return json.dumps(str(value), ensure_ascii=True)


def _write_disposable_config(config: MattermostConfig, path: Path, state_file: Path) -> None:
    lines = [
        "version = 1",
        f"server_url = {_quoted(config.server_url)}",
        f"bot_token_file = {_quoted(config.bot_token_file)}",
        f"bot_user_id = {_quoted(config.bot_user_id)}",
        f"operator_user_id = {_quoted(config.operator_user_id)}",
        f"state_file = {_quoted(state_file)}",
        f"poll_interval_seconds = {config.poll_interval_seconds!r}",
    ]
    if config.actions is not None:
        actions = config.actions
        port = _available_loopback_port(actions.bind_host)
        lines.extend(
            [
                f"action_listener_host = {_quoted(actions.bind_host)}",
                f"action_listener_port = {port}",
                f"public_callback_base_url = {_quoted(actions.public_base_url)}",
                f"action_capability_ttl_seconds = {actions.capability_ttl_seconds}",
                "trusted_action_agent_ids = ["
                + ", ".join(_quoted(agent_id) for agent_id in actions.trusted_agent_ids)
                + "]",
            ]
        )
    for room in config.rooms:
        lines.extend(
            [
                "",
                "[[rooms]]",
                f"coord_room = {_quoted(room.coord_room)}",
                f"channel_id = {_quoted(room.channel_id)}",
                "backfill = false",
            ]
        )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        encoded = ("\n".join(lines) + "\n").encode("utf-8")
        view = memoryview(encoded)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _run_local_diagnostic(command: list[str], *, timeout: int, secrets: Sequence[str] = ()) -> int:
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.stdout:
        print(_sanitize_diagnostic(result.stdout, secrets), end="", flush=True)
    if result.stderr:
        print(_sanitize_diagnostic(result.stderr, secrets), end="", file=sys.stderr, flush=True)
    return result.returncode


async def _append_rendering_fixture(config: MattermostConfig) -> tuple[str, int]:
    result = await coord_api.send(
        config.rooms[0].coord_room,
        "operator",
        None,
        _REAL_RENDERING_FIXTURE,
        declared_content_type="text/markdown",
        notify="none",
    )
    envelope = result.get("envelope") if isinstance(result, dict) else None
    msg_id = envelope.get("msg_id") if isinstance(envelope, dict) else None
    sequence = result.get("sequence") if isinstance(result, dict) else None
    if not isinstance(msg_id, str) or not isinstance(sequence, int) or isinstance(sequence, bool):
        raise AcceptanceError("fixture append returned no canonical message ID and room sequence")
    return msg_id, sequence


async def _verify_rendering_fixture(config: MattermostConfig, msg_id: str) -> str:
    token = read_bot_token(config.bot_token_file)
    async with HTTPMattermostAPI(config, token) as client:
        posts = await client.get_posts(config.rooms[0].channel_id, per_page=200)
    matches = []
    for post in posts:
        props = post.get("props")
        projection = props.get("safeyolo_coord") if isinstance(props, dict) else None
        if isinstance(projection, dict) and projection.get("coord_msg_id") == msg_id:
            matches.append(post)
    if len(matches) != 1:
        raise AcceptanceError("expected exactly one projected fixture post")
    post = matches[0]
    message = post.get("message")
    props = post.get("props")
    if not isinstance(message, str) or not isinstance(props, dict):
        raise AcceptanceError("fixture projection has an invalid Mattermost shape")
    required = (
        "TASK ACCEPTED task=mattermost-rendering-acceptance",
        "# Human-readable projection",
        "**bold**",
        "`inline code`",
        "[SafeYolo docs](https://safeyolo.dev/docs/)",
        "```text",
        "＠all",
        "～town-square",
        "[image: remote image](https://example.com/image.png)",
        "[blocked link]",
        "[sender provenance claim]",
        f"message `{msg_id}`",
    )
    forbidden = ("@all", "~town-square", "![", "mmaction://", "javascript://")
    if any(value not in message for value in required) or any(value in message for value in forbidden):
        raise AcceptanceError("fixture projection did not satisfy the rendering matrix")
    if message.count("Canonical provenance ·") != 1 or props.get("attachments") != []:
        raise AcceptanceError("fixture projection did not preserve the inert provenance boundary")
    if "mm_blocks_actions" in props:
        raise AcceptanceError("routine fixture unexpectedly registered an action callback")
    metadata = post.get("metadata")
    embeds = metadata.get("embeds", []) if isinstance(metadata, dict) else []
    if not isinstance(embeds, list) or any(
        isinstance(embed, dict) and embed.get("type") in {"opengraph", "image", "link"}
        for embed in embeds
    ):
        raise AcceptanceError("routine fixture unexpectedly generated a link or image preview")
    post_id = post.get("id")
    if not isinstance(post_id, str):
        raise AcceptanceError("fixture projection returned no Mattermost post ID")
    return post_id


def _cleanup(root: Path | None, identity: tuple[int, int] | None) -> bool:
    if root is None or identity is None:
        print("CLEANUP PASS: no temporary root was created", flush=True)
        return True
    try:
        linked = root.lstat()
        if (
            not stat.S_ISDIR(linked.st_mode)
            or (linked.st_dev, linked.st_ino) != identity
            or not root.name.startswith("safeyolo-mm-macos-integration-")
        ):
            raise AcceptanceError("temporary root identity changed; cleanup refused")
        shutil.rmtree(root)
        if root.exists() or root.is_symlink():
            raise AcceptanceError("temporary root remains after cleanup")
    except (AcceptanceError, OSError):
        print("CLEANUP FAIL: verified temporary root was not removed", file=sys.stderr, flush=True)
        return False
    print("CLEANUP PASS: removed only script-created config/state artifacts", flush=True)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--expected-base", required=True)
    parser.add_argument(
        "--test-config-copy",
        type=Path,
        required=True,
        help="Ordinary private portable bundle config with one backfill=false room.",
    )
    parser.add_argument("--confirm-dedicated-test-channel", action="store_true")
    parser.add_argument("--allow-run-once-effects", action="store_true")
    args = parser.parse_args()
    root: Path | None = None
    root_identity: tuple[int, int] | None = None
    current_step, current_label = 0, "preflight"
    diagnostic_secrets: tuple[str, ...] = ()
    succeeded = False
    try:
        if sys.platform != "darwin":
            raise AcceptanceError("integration acceptance must run on real macOS")
        head, tree, base = _identity(args.expected_head, args.expected_tree, args.expected_base)
        source_path = _private_regular_config(args.test_config_copy)
        source = load_config(source_path)
        _validate_test_source(source_path, source)
        diagnostic_secrets = (read_bot_token(source.bot_token_file),)
        if not args.confirm_dedicated_test_channel:
            raise AcceptanceError("dedicated test-channel confirmation is required")

        print(
            "PREFLIGHT: the source config is read-only and will not be modified. A private copy with a new "
            "temporary state DB and backfill=false will be used. check performs identity/API reads and a brief "
            "loopback bind. run --once does not start the daemon or Funnel, but concurrent activity after its "
            "new-state baseline can append one operator message or project one post in the configured test-only "
            "coord room/channel. No production mapping is permitted.",
            flush=True,
        )
        if not args.allow_run_once_effects:
            raise AcceptanceError("run-once test-channel effects were not explicitly allowed")

        root = Path(tempfile.mkdtemp(prefix="safeyolo-mm-macos-integration-")).resolve()
        root_st = root.lstat()
        root_identity = root_st.st_dev, root_st.st_ino
        temp_config = root / "coord-mattermost-test.toml"
        temp_state = root / "state.sqlite3"
        _write_disposable_config(source, temp_config, temp_state)
        print(
            f"IDENTITY candidate={head} tree={tree} base={base} platform={platform.platform()} "
            f"python={platform.python_version()} sqlite={sqlite3.sqlite_version}",
            flush=True,
        )
        print(f"TEMP_ROOT {root}", flush=True)

        cli = Path(sys.executable).with_name("safeyolo")
        if not cli.is_file():
            raise AcceptanceError("candidate safeyolo console script is unavailable")
        current_step, current_label = 8, "real mattermost check with disposable state/config"
        if (
            _run_local_diagnostic(
                [str(cli), "coord", "mattermost", "check", "--config", str(temp_config)],
                timeout=90,
                secrets=diagnostic_secrets,
            )
            != 0
        ):
            raise AcceptanceError("mattermost check returned non-zero")
        print(f"PASS {current_step}: {current_label}", flush=True)

        current_step, current_label = 9, "real mattermost baseline run --once on dedicated test mapping"
        if (
            _run_local_diagnostic(
                [str(cli), "coord", "mattermost", "run", "--once", "--config", str(temp_config)],
                timeout=180,
                secrets=diagnostic_secrets,
            )
            != 0
        ):
            raise AcceptanceError("mattermost run --once returned non-zero")
        print(f"PASS {current_step}: {current_label}", flush=True)

        current_step, current_label = 10, "controlled routine rendering matrix on dedicated test mapping"
        msg_id, sequence = asyncio.run(_append_rendering_fixture(source))
        if (
            _run_local_diagnostic(
                [str(cli), "coord", "mattermost", "run", "--once", "--config", str(temp_config)],
                timeout=180,
                secrets=diagnostic_secrets,
            )
            != 0
        ):
            raise AcceptanceError("mattermost fixture projection returned non-zero")
        post_id = asyncio.run(_verify_rendering_fixture(source, msg_id))
        print(
            f"PASS {current_step}: {current_label} coord_sequence={sequence} "
            f"coord_msg_id={msg_id} mattermost_post_id={post_id}",
            flush=True,
        )
        print(
            f"MOBILE CHECK: open the dedicated test channel in stock Mattermost mobile and confirm post {post_id} "
            "is readable, has one quiet provenance footer, and shows no preview or action button.",
            flush=True,
        )
        succeeded = True
    except (AcceptanceError, MattermostAdapterError, OSError, sqlite3.Error, subprocess.SubprocessError) as exc:
        _print_failure(current_step, current_label, exc, secrets=diagnostic_secrets)
    finally:
        succeeded = _cleanup(root, root_identity) and succeeded
    return 0 if succeeded else 1


if __name__ == "__main__":
    raise SystemExit(main())
