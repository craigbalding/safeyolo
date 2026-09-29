"""Shared policy file mutation remains serialized after proxy cutover."""

import tomlkit

POLICY = """\
budget = 1000000

[hosts]
"blocked.example" = { egress = "deny" }
"*" = { egress = "deny", unknown_creds = "prompt" }

[agents.atlas]
egress = "deny"
"""


def test_policy_host_lock_is_shared_with_other_writers(tmp_path, monkeypatch):
    from safeyolo.commands.policy_host import host_add
    from safeyolo.policy.toml_roundtrip import locked_policy_mutate, update_host_field

    path = tmp_path / "policy.toml"
    path.write_text(POLICY)
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))

    locked_policy_mutate(
        path,
        lambda document: update_host_field(
            document, "first.example", "rate", 100000
        ),
    )
    host_add("second.example", rate=100000, agent=None, expires=None)

    hosts = tomlkit.parse(path.read_text()).unwrap()["hosts"]
    assert {"first.example", "second.example"} <= hosts.keys()
    assert hosts["blocked.example"]["egress"] == "deny"
