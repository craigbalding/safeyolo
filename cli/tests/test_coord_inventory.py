"""Stage-3 authoritative room inventory contracts."""

from __future__ import annotations

import asyncio
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from safeyolo.agents_store import remove_agent, save_agent
from safeyolo.coord import api, inventory, nats_client, store
from safeyolo.coord import nats_runtime as nr
from safeyolo.coord.kernel import OperationConflictError

AGENTS = {
    "alice": "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "bob": "ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "codey": "ag-cccccccccccccccccccccccccccccccc",
}


def _run(coro):
    return asyncio.run(coro)


def _agent_meta(agent_id: str, *, capability: str | None = None) -> dict:
    metadata = {
        "agent_id": agent_id,
        "folder": "/sensitive/workspace/path",
        "host_script": "/sensitive/harness.sh",
    }
    if capability is not None:
        service, name = capability.split(":", 1)
        metadata["services"] = {
            service: {
                "capability": name,
                "token": "credential-name-must-never-leak",
                "account": "persona-must-never-leak",
                "route": "/admin/secret",
            }
        }
    return metadata


def _grant(room: str, agent_id: str, *, permissions=None, operation_id=None):
    return api.grant(
        room,
        "agent",
        agent_id,
        permissions=permissions,
        operation_id=operation_id or f"op-grant-{room}-{agent_id}",
    )


@pytest.fixture
def inventory_env(nats_env, monkeypatch):
    config_dir = nats_env / "config"
    config_dir.mkdir()
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))
    monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(nats_env / "logs"))
    for name, agent_id in AGENTS.items():
        save_agent(name, _agent_meta(agent_id))
    nr.start_server(ready_timeout=8.0)
    nats_client.reset_for_tests()
    inventory.clear_provider_adapters()
    api.bootstrap()
    yield nats_env
    inventory.clear_provider_adapters()


def _seed_v4_schema() -> None:
    with store.connect_unchecked() as conn:
        conn.execute("BEGIN IMMEDIATE")
        store._migrate_0_to_1(conn, None)
        store._migrate_1_to_2(conn, None)
        store._migrate_2_to_3(conn, None)
        store._migrate_3_to_4(conn, None)
        conn.execute("PRAGMA user_version = 4")
        conn.execute(
            "INSERT INTO rooms(room_id, name, created_at) VALUES ('rm-v4', 'v4', 1)"
        )
        conn.execute("COMMIT")


def test_v4_inventory_migration_is_transactional_and_retryable(isolated_coord):
    _seed_v4_schema()
    statements = 0

    def fail_after_first(_statement):
        nonlocal statements
        statements += 1
        raise RuntimeError("injected stage-3 migration failure")

    with pytest.raises(RuntimeError, match="stage-3"):
        store.init_schema(_after_statement=fail_after_first)
    assert statements == 1
    with store.connect_unchecked() as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 4
        assert "coord_capability_advertisements" not in {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table'"
            )
        }

    store.init_schema()
    with store.connect() as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 5
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table'"
            )
        }
    assert {
        "coord_capability_advertisements",
        "coord_resource_advertisements",
        "coord_capability_declarations",
    } <= tables


def test_current_grant_and_advertisement_intersection_has_no_coord_cache(
    inventory_env,
):
    _run(api.create_room("grants"))
    _grant("grants", AGENTS["bob"])
    save_agent(
        "bob",
        {
            **_agent_meta(
                AGENTS["bob"], capability="rundeck:acceptance_runner"
            ),
            "services": {
                "rundeck": {
                    "capability": "acceptance_runner",
                    "token": "credential-name-must-never-leak",
                },
                "github": {
                    "capability": "admin",
                    "token": "unadvertised-credential-must-never-leak",
                },
            },
        },
    )
    api.advertise_capability(
        "grants",
        AGENTS["bob"],
        "rundeck:acceptance_runner",
        advertised=True,
        operation_id="op-advertise-rundeck",
    )

    state = _run(api.get_room_state("grants"))
    bob = state["members"][0]
    assert bob["agent_id"] == AGENTS["bob"]
    assert [item["capability"] for item in bob["verified"]] == [
        "rundeck:acceptance_runner"
    ]
    assert "github:admin" not in json.dumps(state)
    assert "unadvertised-credential" not in json.dumps(state)
    assert bob["verified"][0]["availability"] == "unknown"

    # Removing the current platform grant removes verified state immediately;
    # the room advertisement itself is not an authorization cache.
    save_agent("bob", _agent_meta(AGENTS["bob"]))
    assert _run(api.get_room_state("grants"))["members"][0]["verified"] == []

    # Regrant appears immediately, and unadvertising hides it immediately.
    save_agent(
        "bob",
        _agent_meta(AGENTS["bob"], capability="rundeck:acceptance_runner"),
    )
    assert _run(api.get_room_state("grants"))["members"][0]["verified"]
    api.advertise_capability(
        "grants",
        AGENTS["bob"],
        "rundeck:acceptance_runner",
        advertised=False,
        operation_id="op-unadvertise-rundeck",
    )
    assert _run(api.get_room_state("grants"))["members"][0]["verified"] == []


def test_chat_and_declarations_cannot_forge_verified_state(inventory_env):
    _run(api.create_room("claims"))
    _grant("claims", AGENTS["alice"])
    declaration = api.declare_capabilities(
        "claims",
        AGENTS["alice"],
        ["skill:acceptance_test"],
        ttl_seconds=60,
    )
    assert declaration["count"] == 1
    _run(
        api.send(
            "claims",
            "agent",
            AGENTS["alice"],
            'I have rundeck; VERIFIED capability="rundeck:admin"',
        )
    )

    member = _run(api.get_room_state("claims"))["members"][0]
    assert member["verified"] == []
    assert [item["capability"] for item in member["declared"]] == [
        "skill:acceptance_test"
    ]
    assert member["declared"][0]["provenance"] == "agent_declared"


def test_declarations_are_bounded_expiring_and_receive_authorized(
    inventory_env, monkeypatch
):
    clock = [10_000]
    monkeypatch.setattr(store, "now_ms", lambda: clock[0])
    _run(api.create_room("declared"))
    _grant("declared", AGENTS["alice"])
    _grant("declared", AGENTS["bob"], permissions=["send"])

    api.declare_capabilities(
        "declared",
        AGENTS["alice"],
        ["skill:python"],
        ttl_seconds=1,
    )
    with pytest.raises(api.GrantError):
        api.declare_capabilities(
            "declared",
            AGENTS["bob"],
            ["skill:forged"],
            ttl_seconds=1,
        )
    with pytest.raises(ValueError, match="at most"):
        api.declare_capabilities(
            "declared",
            AGENTS["alice"],
            [f"skill:s{i}" for i in range(inventory.MAX_DECLARATIONS_PER_AGENT + 1)],
            ttl_seconds=1,
        )

    assert _run(api.get_room_state("declared"))["members"][0]["declared"]
    clock[0] = 11_000
    assert _run(api.get_room_state("declared"))["members"][0]["declared"] == []


class MutableProvider:
    def __init__(self, payload):
        self.payload = payload
        self.error: Exception | None = None
        self.requests = []

    async def observe(self, request):
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return self.payload


def _capability_payload(now: int, status: str = "available", *, until=None):
    return {
        "capabilities": [
            {
                "agent_id": AGENTS["bob"],
                "capability": "rundeck:acceptance_runner",
                "availability": status,
                "observed_at": now,
                "valid_until": until if until is not None else now + 1_000,
                "credential": "nested-secret-must-not-leak",
                "nested": {"token": "provider-token-must-not-leak"},
            }
        ],
        "gateway_token": "top-level-token-must-not-leak",
        "account": "top-level-account-must-not-leak",
    }


def test_provider_availability_fresh_stale_unavailable_failure_and_redaction(
    inventory_env, monkeypatch
):
    clock = [20_000]
    monkeypatch.setattr(store, "now_ms", lambda: clock[0])
    _run(api.create_room("provider"))
    _grant("provider", AGENTS["bob"])
    save_agent(
        "bob",
        _agent_meta(AGENTS["bob"], capability="rundeck:acceptance_runner"),
    )
    api.advertise_capability(
        "provider",
        AGENTS["bob"],
        "rundeck:acceptance_runner",
        advertised=True,
        operation_id="op-provider-ad",
    )
    adapter = MutableProvider(_capability_payload(clock[0]))
    inventory.register_provider_adapter("rundeck", adapter)

    available = _run(api.get_room_state("provider"))["members"][0]["verified"][0]
    assert available["availability"] == "available"
    assert available["freshness"] == "fresh"
    serialized = json.dumps(available)
    assert "secret" not in serialized
    assert "token" not in serialized
    assert "account" not in serialized
    request = adapter.requests[-1]
    assert request.capabilities == (
        (AGENTS["bob"], "rundeck:acceptance_runner"),
    )
    assert not hasattr(request, "credentials")

    adapter.payload = _capability_payload(19_000, until=20_000)
    stale = _run(api.get_room_state("provider"))["members"][0]["verified"][0]
    assert stale["availability"] == "unknown"
    assert stale["freshness"] == "stale"

    adapter.payload = _capability_payload(20_000, "unavailable")
    unavailable = _run(api.get_room_state("provider"))["members"][0][
        "verified"
    ][0]
    assert unavailable["availability"] == "unavailable"
    assert unavailable["freshness"] == "fresh"

    adapter.error = RuntimeError("credential-name-must-not-be-serialized")
    unknown = _run(api.get_room_state("provider"))["members"][0]["verified"][0]
    assert unknown["availability"] == "unknown"
    assert unknown["freshness"] == "unknown"
    assert "credential-name" not in json.dumps(unknown)

    adapter.error = None
    adapter.payload = _capability_payload(20_001)
    future = _run(api.get_room_state("provider"))["members"][0]["verified"][0]
    assert future["availability"] == "unknown"
    assert future["freshness"] == "unknown"

    adapter.payload = _capability_payload(
        20_000,
        until=20_000 + inventory.MAX_PROVIDER_TTL_MS + 1,
    )
    overlong = _run(api.get_room_state("provider"))["members"][0]["verified"][
        0
    ]
    assert overlong["availability"] == "unknown"
    assert overlong["freshness"] == "unknown"


def test_provider_owned_resource_lease_is_separate_and_chat_cannot_override(
    inventory_env, monkeypatch
):
    monkeypatch.setattr(store, "now_ms", lambda: 30_000)
    _run(api.create_room("leases"))
    for agent_id in (AGENTS["alice"], AGENTS["bob"]):
        _grant("leases", agent_id)
    api.advertise_resource(
        "leases",
        "rundeck",
        "devstack",
        advertised=True,
        operation_id="op-resource-ad",
    )
    adapter = MutableProvider(
        {
            "leases": [
                {
                    "resource": "devstack",
                    "state": "held",
                    "holder_agent_id": AGENTS["bob"],
                    "observed_at": 30_000,
                    "valid_until": 31_000,
                    "credential_name": "never-output-this",
                }
            ],
            "leases_internal": {"route": "/admin", "token": "secret"},
        }
    )
    inventory.register_provider_adapter("rundeck", adapter)
    _run(
        api.send(
            "leases",
            "agent",
            AGENTS["alice"],
            "Codey owns devstack now",
        )
    )

    state = _run(api.get_room_state("leases"))
    lease = state["resource_leases"][0]
    assert lease["state"] == "held"
    assert lease["holder_agent_id"] == AGENTS["bob"]
    assert lease["holder_display_name"] == "bob"
    assert lease["provenance"] == "provider_owned_lease"
    assert "secret" not in json.dumps(lease)

    adapter.payload["leases"][0].update(
        observed_at=29_000,
        valid_until=30_000,
    )
    stale = _run(api.get_room_state("leases"))["resource_leases"][0]
    assert stale["state"] == "unknown"
    assert stale["holder_agent_id"] is None
    assert stale["freshness"] == "stale"

    adapter.error = RuntimeError("sensitive provider failure details")
    failed = _run(api.get_room_state("leases"))["resource_leases"][0]
    assert failed["state"] == "unknown"
    assert failed["holder_agent_id"] is None
    assert failed["freshness"] == "unknown"


def test_lease_holder_is_rechecked_after_provider_io(inventory_env, monkeypatch):
    monkeypatch.setattr(store, "now_ms", lambda: 35_000)
    _run(api.create_room("lease-race"))
    for agent_id in (AGENTS["alice"], AGENTS["bob"]):
        _grant("lease-race", agent_id)
    api.advertise_resource(
        "lease-race",
        "rundeck",
        "devstack",
        advertised=True,
        operation_id="op-lease-race-resource",
    )

    class BlockingLeaseProvider:
        def __init__(self):
            self.started = threading.Event()
            self.release = threading.Event()

        async def observe(self, _request):
            self.started.set()
            self.release.wait()
            return {
                "leases": [
                    {
                        "resource": "devstack",
                        "state": "held",
                        "holder_agent_id": AGENTS["bob"],
                        "observed_at": 35_000,
                        "valid_until": 36_000,
                    }
                ]
            }

    provider = BlockingLeaseProvider()
    inventory.register_provider_adapter("rundeck", provider)

    async def race():
        pending = asyncio.create_task(
            api.get_room_state("lease-race", "agent", AGENTS["alice"])
        )
        await asyncio.to_thread(provider.started.wait)
        api.revoke_grant(
            "lease-race",
            "agent",
            AGENTS["bob"],
            operation_id="op-lease-race-revoke-bob",
        )
        provider.release.set()
        return await pending

    state = _run(race())
    assert [member["agent_id"] for member in state["members"]] == [AGENTS["alice"]]
    lease = state["resource_leases"][0]
    assert lease["state"] == "unknown"
    assert lease["holder_agent_id"] is None
    assert lease["holder_display_name"] is None
    assert lease["freshness"] == "unknown"


def test_rename_preserves_identity_and_remove_readd_is_distinct(inventory_env):
    _run(api.create_room("identity"))
    _grant("identity", AGENTS["bob"])
    original = _run(api.get_room_state("identity"))["members"][0]
    assert original["display_name"] == "bob"

    metadata = _agent_meta(AGENTS["bob"])
    remove_agent("bob")
    save_agent("robert", metadata)
    renamed = _run(api.get_room_state("identity"))["members"][0]
    assert renamed["agent_id"] == original["agent_id"]
    assert renamed["display_name"] == "robert"

    remove_agent("robert")
    replacement_id = "ag-dddddddddddddddddddddddddddddddd"
    save_agent("bob", _agent_meta(replacement_id))
    _grant("identity", replacement_id, operation_id="op-grant-replacement")
    members = _run(api.get_room_state("identity"))["members"]
    assert {member["agent_id"] for member in members} == {
        AGENTS["bob"],
        replacement_id,
    }
    old = next(member for member in members if member["agent_id"] == AGENTS["bob"])
    new = next(member for member in members if member["agent_id"] == replacement_id)
    assert old["configured"] is False
    assert old["display_name"] is None
    assert new["configured"] is True
    assert new["display_name"] == "bob"


class BlockingProvider:
    def __init__(self):
        self.started = threading.Event()
        self.release = threading.Event()

    async def observe(self, _request):
        self.started.set()
        self.release.wait()
        return _capability_payload(store.now_ms())


def test_authorization_rechecked_after_provider_io_and_send_only_denied(
    inventory_env,
):
    _run(api.create_room("auth"))
    _grant("auth", AGENTS["alice"])
    _grant("auth", AGENTS["bob"], permissions=["send"])
    save_agent(
        "alice",
        _agent_meta(AGENTS["alice"], capability="rundeck:acceptance_runner"),
    )
    api.advertise_capability(
        "auth",
        AGENTS["alice"],
        "rundeck:acceptance_runner",
        advertised=True,
        operation_id="op-auth-ad",
    )
    provider = BlockingProvider()
    inventory.register_provider_adapter("rundeck", provider)

    with pytest.raises(api.GrantError):
        _run(api.get_room_state("auth", "agent", AGENTS["bob"]))
    with pytest.raises(api.NoMembershipError):
        _run(api.get_room_state("auth", "agent", AGENTS["codey"]))

    async def race():
        pending = asyncio.create_task(
            api.get_room_state("auth", "agent", AGENTS["alice"])
        )
        await asyncio.to_thread(provider.started.wait)
        api.revoke_grant(
            "auth",
            "agent",
            AGENTS["alice"],
            operation_id="op-auth-revoke",
        )
        provider.release.set()
        with pytest.raises(api.NoMembershipError):
            await pending

    _run(race())


def test_sqlite_authorization_and_inventory_inputs_share_one_snapshot(
    inventory_env, monkeypatch
):
    _run(api.create_room("snapshot"))
    _grant("snapshot", AGENTS["alice"])
    api.advertise_resource(
        "snapshot",
        "rundeck",
        "devstack",
        advertised=True,
        operation_id="op-snapshot-resource",
    )
    real_read = inventory.read_snapshot
    interleaved = False

    def revoke_before_state_read(conn, room_id):
        nonlocal interleaved
        if not interleaved:
            interleaved = True
            api.revoke_grant(
                "snapshot",
                "agent",
                AGENTS["alice"],
                operation_id="op-snapshot-revoke",
            )
            api.advertise_resource(
                "snapshot",
                "rundeck",
                "devstack",
                advertised=False,
                operation_id="op-snapshot-resource-remove",
            )
        return real_read(conn, room_id)

    monkeypatch.setattr(inventory, "read_snapshot", revoke_before_state_read)
    _room_id, snapshot, _brief = api._inventory_snapshot(
        "snapshot",
        "agent",
        AGENTS["alice"],
    )
    assert snapshot.members[0][0] == AGENTS["alice"]
    assert snapshot.resource_advertisements == (("rundeck", "devstack"),)

    monkeypatch.setattr(inventory, "read_snapshot", real_read)
    with pytest.raises(api.NoMembershipError):
        api._inventory_snapshot("snapshot", "agent", AGENTS["alice"])


def test_policy_grant_and_sqlite_advertisement_share_final_linearization(
    inventory_env, monkeypatch
):
    _run(api.create_room("cross-store"))
    _grant("cross-store", AGENTS["bob"])
    save_agent(
        "bob",
        _agent_meta(AGENTS["bob"], capability="rundeck:acceptance_runner"),
    )

    real_snapshot = api._inventory_snapshot
    snapshot_calls = 0
    writer_started = threading.Event()
    writer_done = threading.Event()
    writer: threading.Thread | None = None

    def interleaved_snapshot(*args, **kwargs):
        nonlocal snapshot_calls, writer
        snapshot_calls += 1
        if snapshot_calls == 2:

            def revoke_then_advertise():
                writer_started.set()
                save_agent("bob", _agent_meta(AGENTS["bob"]))
                api.advertise_capability(
                    "cross-store",
                    AGENTS["bob"],
                    "rundeck:acceptance_runner",
                    advertised=True,
                    operation_id="op-cross-store-ad",
                )
                writer_done.set()

            writer = threading.Thread(target=revoke_then_advertise)
            writer.start()
            assert writer_started.wait(timeout=1)
            # The final policy lock prevents the ordered revoke+advertise from
            # completing before the SQLite snapshot. Without it, the response
            # manufactures an intersection that never existed.
            writer_done.wait(timeout=0.2)
        return real_snapshot(*args, **kwargs)

    monkeypatch.setattr(api, "_inventory_snapshot", interleaved_snapshot)
    state = _run(api.get_room_state("cross-store"))
    assert writer is not None
    writer.join(timeout=2)
    assert writer_done.is_set()
    assert state["members"][0]["verified"] == []
    assert _run(api.get_room_state("cross-store"))["members"][0]["verified"] == []


def test_advertisement_operation_replay_validation_and_restart(inventory_env):
    _run(api.create_room("durable"))
    _grant("durable", AGENTS["alice"])
    save_agent(
        "alice",
        _agent_meta(AGENTS["alice"], capability="github:write_pr"),
    )
    first = api.advertise_capability(
        "durable",
        AGENTS["alice"],
        "github:write_pr",
        advertised=True,
        operation_id="op-durable-ad",
    )
    api.declare_capabilities(
        "durable",
        AGENTS["alice"],
        ["skill:python"],
        ttl_seconds=60,
    )
    assert api.advertise_capability(
        "durable",
        AGENTS["alice"],
        "github:write_pr",
        advertised=True,
        operation_id="op-durable-ad",
    ) == first
    with pytest.raises(OperationConflictError):
        api.advertise_capability(
            "durable",
            AGENTS["alice"],
            "github:other",
            advertised=True,
            operation_id="op-durable-ad",
        )
    with pytest.raises(ValueError, match="sensitive"):
        api.advertise_capability(
            "durable",
            AGENTS["alice"],
            "github:api_token",
            advertised=True,
            operation_id="op-sensitive-ad",
        )

    nr.stop_server()
    nats_client.reset_for_tests()
    nr.start_server(ready_timeout=8.0)
    with store.connect() as conn:
        assert conn.execute(
            "SELECT count(*) FROM coord_capability_advertisements"
        ).fetchone()[0] == 1
    member = _run(api.get_room_state("durable"))["members"][0]
    assert member["verified"][0]["capability"] == "github:write_pr"
    assert member["declared"][0]["capability"] == "skill:python"


def test_malformed_oversized_and_concurrent_provider_reads_fail_closed(
    inventory_env, monkeypatch
):
    monkeypatch.setattr(store, "now_ms", lambda: 40_000)
    _run(api.create_room("provider-races"))
    _grant("provider-races", AGENTS["bob"])
    save_agent(
        "bob",
        _agent_meta(AGENTS["bob"], capability="rundeck:acceptance_runner"),
    )
    api.advertise_capability(
        "provider-races",
        AGENTS["bob"],
        "rundeck:acceptance_runner",
        advertised=True,
        operation_id="op-provider-races-ad",
    )

    class SequencedProvider:
        def __init__(self):
            self.calls = 0

        async def observe(self, _request):
            self.calls += 1
            if self.calls == 1:
                await asyncio.sleep(0.02)
                return _capability_payload(40_000, "available")
            return _capability_payload(40_000, "unavailable")

    sequenced = SequencedProvider()
    inventory.register_provider_adapter("rundeck", sequenced)

    async def concurrent_reads():
        first, second = await asyncio.gather(
            api.get_room_state("provider-races"),
            api.get_room_state("provider-races"),
        )
        return {
            first["members"][0]["verified"][0]["availability"],
            second["members"][0]["verified"][0]["availability"],
        }

    assert _run(concurrent_reads()) == {"available", "unavailable"}

    sequenced.calls = 0
    sequenced.observe = lambda _request: asyncio.sleep(  # type: ignore[method-assign]
        0, result={"capabilities": "malformed"}
    )
    malformed = _run(api.get_room_state("provider-races"))["members"][0][
        "verified"
    ][0]
    assert malformed["availability"] == "unknown"

    oversized = MutableProvider(
        {
            "capabilities": [
                {"ignored": index}
                for index in range(inventory.MAX_PROVIDER_RESULT_ENTRIES + 1)
            ]
        }
    )
    inventory.register_provider_adapter("rundeck", oversized)
    unknown = _run(api.get_room_state("provider-races"))["members"][0][
        "verified"
    ][0]
    assert unknown["availability"] == "unknown"

    slow_finished = threading.Event()

    class SlowProvider:
        async def observe(self, _request):
            try:
                await asyncio.sleep(0.05)
                return _capability_payload(40_000)
            finally:
                slow_finished.set()

    inventory.register_provider_adapter("rundeck", SlowProvider())
    monkeypatch.setattr(inventory, "PROVIDER_TIMEOUT_SECONDS", 0.01)
    timed_out = _run(api.get_room_state("provider-races"))["members"][0][
        "verified"
    ][0]
    assert timed_out["availability"] == "unknown"
    assert timed_out["freshness"] == "unknown"
    assert slow_finished.wait(timeout=1)

    blocking_finished = threading.Event()

    class BadBlockingProvider:
        async def observe(self, _request):
            try:
                time.sleep(0.2)
                return _capability_payload(40_000)
            finally:
                blocking_finished.set()

    inventory.register_provider_adapter("rundeck", BadBlockingProvider())

    async def measured_read():
        started = time.monotonic()
        result = await api.get_room_state("provider-races")
        return time.monotonic() - started, result

    elapsed, blocked = _run(measured_read())
    assert elapsed < 0.1
    blocked_capability = blocked["members"][0]["verified"][0]
    assert blocked_capability["availability"] == "unknown"
    assert blocked_capability["freshness"] == "unknown"
    assert blocking_finished.wait(timeout=1)


def test_max_blocking_providers_cannot_starve_authoritative_state_reads(
    inventory_env, monkeypatch
):
    _run(api.create_room("provider-starvation"))
    _grant("provider-starvation", AGENTS["alice"])
    finished: list[threading.Event] = []
    release = threading.Event()

    for index in range(inventory.MAX_PROVIDER_COUNT):
        provider = f"provider{index}"
        api.advertise_resource(
            "provider-starvation",
            provider,
            "runner",
            advertised=True,
            operation_id=f"op-starvation-{index}",
        )
        provider_finished = threading.Event()
        finished.append(provider_finished)

        class BlockingAdapter:
            async def observe(self, _request, *, done=provider_finished):
                try:
                    release.wait(timeout=0.4)
                    return {"leases": []}
                finally:
                    done.set()

        inventory.register_provider_adapter(provider, BlockingAdapter())

    monkeypatch.setattr(inventory, "PROVIDER_TIMEOUT_SECONDS", 0.01)

    async def measured_read():
        # Reproduce the shared-pool size that the previous implementation
        # exhausted: all provider jobs occupied it, then the untimed final
        # authoritative snapshot queued behind them.
        asyncio.get_running_loop().set_default_executor(
            ThreadPoolExecutor(max_workers=inventory.MAX_PROVIDER_COUNT)
        )
        started = time.monotonic()
        result = await api.get_room_state("provider-starvation")
        return time.monotonic() - started, result

    elapsed, state = _run(measured_read())
    assert elapsed < 0.2
    assert len(state["resource_leases"]) == inventory.MAX_PROVIDER_COUNT
    assert {lease["state"] for lease in state["resource_leases"]} == {"unknown"}

    # All 16 abandoned workers are still occupied. A repeated read must not
    # spawn another wave or wait for them; the global cap returns unknown and
    # leaves the authoritative executor available.
    repeated_started = time.monotonic()
    repeated = _run(api.get_room_state("provider-starvation"))
    assert time.monotonic() - repeated_started < 0.2
    assert {lease["state"] for lease in repeated["resource_leases"]} == {
        "unknown"
    }
    release.set()
    assert all(event.wait(timeout=1) for event in finished)


def test_room_state_rejects_unbounded_canonical_input(inventory_env):
    room_id = _run(api.create_room("bounds"))
    _grant("bounds", AGENTS["alice"])
    with store.connect() as conn:
        conn.executemany(
            """INSERT INTO coord_capability_advertisements
               (room_id, agent_id, capability, operation_id, created_at)
               VALUES (?, ?, ?, 'op-bounds', 1)""",
            [
                (room_id, AGENTS["alice"], f"svc:cap{index}")
                for index in range(
                    inventory.MAX_CAPABILITY_ADVERTISEMENTS + 1
                )
            ],
        )

    with pytest.raises(inventory.InventoryBoundsError, match="advertisement"):
        _run(api.get_room_state("bounds"))


def test_advertisement_mutations_enforce_room_and_provider_bounds(
    inventory_env, monkeypatch
):
    _run(api.create_room("mutation-bounds"))
    _grant("mutation-bounds", AGENTS["alice"])
    monkeypatch.setattr(inventory, "MAX_CAPABILITY_ADVERTISEMENTS", 1)

    api.advertise_capability(
        "mutation-bounds",
        AGENTS["alice"],
        "svc:first",
        advertised=True,
        operation_id="op-mutation-bound-first",
    )
    with pytest.raises(inventory.InventoryBoundsError, match="advertisement"):
        api.advertise_capability(
            "mutation-bounds",
            AGENTS["alice"],
            "svc:second",
            advertised=True,
            operation_id="op-mutation-bound-second",
        )
    with store.connect() as conn:
        assert conn.execute(
            "SELECT count(*) FROM coord_capability_advertisements"
        ).fetchone()[0] == 1

    monkeypatch.setattr(inventory, "MAX_PROVIDER_COUNT", 1)
    with pytest.raises(inventory.InventoryBoundsError, match="providers"):
        api.advertise_resource(
            "mutation-bounds",
            "other",
            "runner",
            advertised=True,
            operation_id="op-mutation-bound-provider",
        )
    with store.connect() as conn:
        assert conn.execute(
            "SELECT count(*) FROM coord_resource_advertisements"
        ).fetchone()[0] == 0


def test_provider_adapter_contract_requires_async_observation():
    class BlockingAdapter:
        def observe(self, _request):
            return {}

    with pytest.raises(TypeError, match="async observe"):
        inventory.register_provider_adapter("provider", BlockingAdapter())
