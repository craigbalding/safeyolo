"""Pure listener edits preserve native JSON outside the requested changes."""

import json

import pytest

from safeyolo.rust_listener_json import update_listeners


def test_unrelated_native_values_retain_exact_numeric_and_duplicate_text():
    untouched = '"test_context_declared_ttl": {"value":1e400,"value":1.23456789012345678901234567890e-400}'
    source = '{\n  ' + untouched + ',\n  "listeners":[]\n}\n'
    result = update_listeners(source, [], [{"agent_id": "alice", "socket_path": "/owned/alice.sock"}], "new")
    assert untouched in result
    assert "Infinity" not in result
    assert result.startswith('{\n  ' + untouched + ',\n  "listeners":')
    assert result.endswith('\n,"reload_id":"new"}\n')
    assert json.loads(result)["reload_id"] == "new"


def test_duplicate_native_members_are_preserved_for_native_validation():
    source = '{"network_guard_block":true,"network_guard_block":false,"listeners":[0],"listeners":[]}'
    result = update_listeners(source, [], [], "new")
    assert result == source[:-1] + ',"reload_id":"new"}'


def test_retained_custom_entry_keeps_duplicates_and_nested_escaped_text():
    custom = r'{"agent_id":"alice","agent_id":"bob","socket_path":"/owned/a\\b.sock","extra":{"text":"} ] \\\"","x":[1e400,{}]}}'
    managed = '{"agent_id":"old","socket_path":"/owned/old.sock"}'
    source = '{"listeners":[' + managed + ',\n ' + custom + '],"untouched":"} , ]"}'
    original = json.loads(source)["listeners"]
    added = {"agent_id": "new", "socket_path": "/owned/new.sock", "source_id": "127.0.0.2"}
    result = update_listeners(source, original, [original[1], added])
    assert result == '{"listeners":[' + custom + ',' + json.dumps(added) + '],"untouched":"} , ]"}'


def test_retention_uses_identity_not_equal_dictionary_values():
    first = '{ "agent_id" : "alice", "socket_path":"/owned/a.sock" }'
    second = '{"socket_path":"/owned/a.sock","agent_id":"alice"}'
    source = '{"listeners":[' + first + ',' + second + ']}'
    original = json.loads(source)["listeners"]
    assert original[0] == original[1]
    assert update_listeners(source, original, [original[1]]) == '{"listeners":[' + second + ']}'


def test_remove_all_listeners_and_replace_only_last_reload_id():
    source = '{ "reload_id":"first", "listeners":[{"agent_id":"old"}], "reload_id" : {"old":[1,2]} }'
    original = json.loads(source)["listeners"]
    assert update_listeners(source, original, [], 'next"id') == (
        '{ "reload_id":"first", "listeners":[], "reload_id" : "next\\\"id" }'
    )


def test_omitted_reload_id_leaves_its_raw_value_untouched():
    source = '{"listeners": [], "reload_id" : [1e400,{"a":1,"a":2}]}\t'
    assert update_listeners(source, [], []) == source


def test_escaped_listener_key_and_surrounding_whitespace_are_retained():
    source = ' \r\n{ "list\\u0065ners" : [\n], "other":false }\t'
    assert update_listeners(source, [], []) == ' \r\n{ "list\\u0065ners" : [], "other":false }\t'


@pytest.mark.parametrize("source", ["", "[]", "null", "1", '{}', '{"listeners":null}',
                                   '{"listeners":[]', '{"listeners":[],}', '{"listeners":[]} false'])
def test_malformed_or_non_object_configuration_is_not_silently_repaired(source):
    with pytest.raises(ValueError):
        update_listeners(source, [], [], "new")


def test_wrong_original_array_length_is_rejected():
    with pytest.raises(ValueError, match="Original listeners"):
        update_listeners('{"listeners":[{}]}', [], [])
