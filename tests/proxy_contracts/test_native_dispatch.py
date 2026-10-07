"""Native Dispatch requests in one disposable installed Coord/NATS instance.

This reuses the selected G5 driver and runs product commands without a Python
import path. No site publication, installed scheduler or live campaign occurs.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path

import pytest

from tests.proxy_contracts import test_native_coord_operator as operator_coord
from tests.proxy_contracts.test_native_coord_operator import (
    ROOM,
    agent_send,
    cli,
    history,
    stream_control,
)

REPO = Path(__file__).resolve().parents[2]
instance = operator_coord.instance


@pytest.fixture
def dispatch_instance(instance):
    with instance.policy.open("a") as policy:
        policy.write("\n[agents.relay]\nagent_id='ag-cccccccccccccccccccccccccccccccc'\n")
    grant = instance.cli("coord", "grant", ROOM, "relay")
    assert grant.returncode == 0, grant.stderr
    return instance


def trigger(instance, date="2026-06-01", *options):
    return cli(instance, "dispatch-trigger", ROOM, "--date", date, *options)


def ledger(instance):
    return instance.root / "data/coord/dispatch-schedule.json"


def test_native_request_authority_duplicate_and_durable_restart(dispatch_instance):
    instance = dispatch_instance
    delivered = trigger(instance)
    assert delivered.returncode == 0 and "delivered" in delivered.stdout, delivered.stderr
    messages = history(instance)
    assert len(messages) == 1
    message = messages[0]
    assert message["sender_kind"] == "operator" and message["sender_agent_id"] is None
    assert message["body"].startswith("TASK relay Produce SafeYolo Dispatch content")
    assert "weekly 2026-W22 (2026-05-25 through 2026-05-31)" in message["body"]
    assert "monthly 2026-05 (2026-05-01 through 2026-05-31)" in message["body"]
    assert message["attention_intent"] == {
        "mode": "targeted", "agent_ids": ["ag-cccccccccccccccccccccccccccccccc"],
    }
    repeated = trigger(instance)
    assert repeated.returncode == 0 and "already-delivered" in repeated.stdout, repeated.stderr
    assert len(history(instance)) == 1
    saved = ledger(instance).read_bytes()
    assert instance.cli("coord", "stop").returncode == 0
    restarted = instance.cli("coord", "start", "--client-port", str(instance.nats["client_port"]),
                             "--monitor-port", str(instance.nats["monitor_port"]))
    assert restarted.returncode == 0, restarted.stderr
    repeated = trigger(instance)
    assert repeated.returncode == 0 and "already-delivered" in repeated.stdout, repeated.stderr
    assert ledger(instance).read_bytes() == saved
    assert history(instance)[0]["msg_id"] == message["msg_id"]
    changed = trigger(instance, "2026-06-01", "--publication-mode", "automatic")
    assert changed.returncode != 0 and "different room or schedule settings" in changed.stderr
    assert len(history(instance)) == 1
    forged = agent_send(instance, "guest attribution control", sender_kind="operator")
    assert forged["envelope"]["sender_kind"] == "agent"
    before = asyncio.run(stream_control(instance))
    with sqlite3.connect(instance.root / "data/coord/v0.db") as connection:
        connection.execute("UPDATE memberships SET revoked_at=1800000000000 "
                           "WHERE principal_kind='operator' AND revoked_at IS NULL")
    refused = trigger(instance, "2026-06-02")
    assert refused.returncode != 0
    assert asyncio.run(stream_control(instance)) == before


def test_withheld_ack_reconciles_same_envelope_without_second_publication(dispatch_instance):
    instance = dispatch_instance
    asyncio.run(stream_control(instance, no_ack=True))
    unknown = trigger(instance)
    assert unknown.returncode != 0 and "UNKNOWN" in unknown.stderr, unknown.stderr
    assert asyncio.run(stream_control(instance)) == 1
    record = json.loads(ledger(instance).read_text())["tasks"]["dispatch-production/2026-06-01"]
    assert record["attempted"] and record["status"] == "pending" and record["sequence"] is None
    assert instance.cli("coord", "stop").returncode == 0
    resumed = instance.cli("coord", "start", "--client-port", str(instance.nats["client_port"]),
                           "--monitor-port", str(instance.nats["monitor_port"]))
    assert resumed.returncode == 0, resumed.stderr
    asyncio.run(stream_control(instance, no_ack=False))
    reconciled = trigger(instance)
    assert reconciled.returncode == 0 and "reconciled" in reconciled.stdout, reconciled.stderr
    assert asyncio.run(stream_control(instance)) == 1
    messages = history(instance)
    assert messages[0]["msg_id"] == record["prepared"]["envelope"]["msg_id"]
    assert messages[0]["sender_kind"] == "operator"
    assert trigger(instance, "2026-06-02").returncode == 0
    assert asyncio.run(stream_control(instance)) == 2


async def purge_room(instance):
    import nats

    credential = (instance.root / "data/coord/nats/creds").read_text().strip()
    connection = await nats.connect(f"nats://127.0.0.1:{instance.nats['client_port']}",
                                    user="safeyolo", password=credential)
    try:
        js = connection.jetstream()
        stream = next(stream for stream in await js.streams_info()
                      if stream.config.name.startswith("ROOM_"))
        await js.purge_stream(stream.config.name)
    finally:
        await connection.close()


def test_absent_unknown_publication_is_never_automatically_replayed(dispatch_instance):
    instance = dispatch_instance
    asyncio.run(stream_control(instance, no_ack=True))
    unknown = trigger(instance)
    assert unknown.returncode != 0 and "UNKNOWN" in unknown.stderr
    saved = ledger(instance).read_bytes()
    asyncio.run(purge_room(instance))
    asyncio.run(stream_control(instance, no_ack=False))
    repeated = trigger(instance)
    assert repeated.returncode != 0 and "unknown" in repeated.stderr.lower(), repeated.stderr
    assert ledger(instance).read_bytes() == saved
    assert asyncio.run(stream_control(instance)) == 0


def test_invalid_request_and_corrupt_ledger_do_not_publish(dispatch_instance):
    instance = dispatch_instance
    for date in ("20260829", "2026-W35-6", "2026-8-29", "2026-02-29"):
        assert trigger(instance, date).returncode != 0
    assert trigger(instance, "2026-06-01", "--weekly-on", "never").returncode != 0
    assert trigger(instance, "2026-06-01", "--publication-mode", "maybe").returncode != 0
    assert not ledger(instance).exists()
    assert asyncio.run(stream_control(instance)) == 0
    ledger(instance).write_text('{"version":1,"version":1,"tasks":{}}')
    saved = ledger(instance).read_bytes()
    assert trigger(instance).returncode != 0
    assert ledger(instance).read_bytes() == saved
    assert asyncio.run(stream_control(instance)) == 0


def test_installed_generation_and_site_consumers(dispatch_instance, tmp_path):
    instance = dispatch_instance
    source = REPO / "site/_sources/dispatch/2026-08-29.json"
    root = tmp_path / "rendered"
    generated = instance.cli("dispatch", "generate", str(source), "--output-root", str(root))
    assert generated.returncode == 0, generated.stderr
    for relative in ("dispatch/2026-08-29.md", "topics/coord.md"):
        assert (root / relative).read_bytes() == (REPO / "site" / relative).read_bytes()
    checked = instance.cli("dispatch", "generate", str(source), "--output-root", str(root), "--check")
    assert checked.returncode == 0, checked.stderr
    site = instance.cli("dispatch", "check-site", "--site-root", str(REPO / "site"))
    assert site.returncode == 0, site.stderr
    page = root / "dispatch/2026-08-29.md"
    page.write_text("stale\n")
    refused = instance.cli("dispatch", "generate", str(source), "--output-root", str(root), "--check")
    assert refused.returncode != 0 and page.read_text() == "stale\n"
    absent = tmp_path / "absent"
    refused = instance.cli("dispatch", "generate", str(source), "--output-root", str(absent), "--check")
    assert refused.returncode != 0 and not absent.exists()
