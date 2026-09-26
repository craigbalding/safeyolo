# Worked probe: decisions on one reused connection

Use this shape when an earlier request could contaminate routing, authorization, attribution, or parsing of the next request on the **same** client connection. The real-proxy probe in `factory-hypothesis-probes-20260926/reused_connection.py` exercised PR #775. Its property was: a denied or approval-needed request cannot authorize or corrupt a later permitted request, and neither blocked request reaches its origin.

The fixture had three local origins with distinct policy decisions: `allowed`, `denied`, and `approval`. First establish that a request to `allowed` succeeds and reaches that origin. Make it the first operation in every generated sequence as a continuing positive control. Keep the same Unix socket for the whole sequence; use a fresh socket between Hypothesis examples.

```python
@settings(max_examples=36, deadline=None)
@given(
    blocker=st.sampled_from(["denied", "approval"]),
    middle=st.lists(
        st.sampled_from(["allowed", "denied", "approval"]), max_size=2
    ),
)
def blocked_step_cannot_poison_later_requests(blocker, middle):
    names = ["allowed", blocker, *middle, "allowed"]
    initial_allowed = len(allowed.requests)
    request_ids = []
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(5)
        stream.connect(proxy.paths["alice"])
        for index, name in enumerate(names):
            status, headers, body = _reused_request(
                stream, f"127.0.0.1:{ports[name]}",
                f"/probe/{index}".encode(), forged_agent="bob",
            )
            assert status == {"allowed": 200, "denied": 403, "approval": 428}[name]
            assert (body == b"hello") == (name == "allowed")
            assert len(allowed.requests) == (
                initial_allowed + names[:index + 1].count("allowed")
            )
            assert denied.accepts == approval.accepts == 0
            lowered = {key.lower(): value for key, value in headers.items()}
            request_ids.append(lowered["x-safeyolo-request-id"])
            assert len(set(request_ids)) == len(request_ids)
    rows = [
        row for row in proxy.events("proxy.request")
        if row["request_id"] in request_ids
    ]
    assert len(rows) == len(names)
    assert len({row["connection_id"] for row in rows}) == 1
    assert all(row["agent"] == "alice" for row in rows)
```

The actual probe also checked `X-Blocked-By: network-guard` on blocked steps and that the allowed origin received the expected credential header when one was deliberately included. Add that dimension only when credential carryover is the question. For route-decision isolation, the earlier generator's six random credential bits and random path tag spent cases on values that did not change the decision. Keep attribution forgery fixed as a challenge, not random noise. Check the caller response **and** origin effects after each operation; checking only the final response can miss a leak in the middle of the sequence.
