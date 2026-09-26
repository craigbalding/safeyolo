# Worked probe: encoded gateway query aliases

Use this shape when a gateway binds a query value to a capability and a second spelling of the same key might change which value is authorized. The real-proxy probe in `factory-hypothesis-probes-20260926/gateway_aliases.py` exercised PR #766 against Python and Rust. Its failure condition was specific: a duplicate decoded `account` key must be denied before the origin receives a request or a vault credential.

Build the existing service, vault, policy, and origin fixtures first. A `403` for every generated request proves little if the fixture never enabled the gateway. Establish a permitted control through **the same proxy**:

```python
base = f"http://127.0.0.1:{origin.server_address[1]}"
headers = {"Authorization": f"Bearer {_gateway_token(proxy)}"}
status, _, _ = request(
    proxy.paths["alice"], base + "/v1/items?account=alpha", headers=headers
)
assert status == 200 and origin.accepts == 1
assert _authorization(_wire(origin.requests[-1])) == [
    f"Bearer {VAULT_CREDENTIAL}".encode()
]
```

Then vary only the bytes and order that can change the binding decision. Retain both copies of the key in the raw URL; a dictionary or URL builder could collapse or normalize them before the proxy sees them.

```python
@settings(max_examples=84, deadline=None)
@given(
    position=st.integers(0, len("account") - 1),
    hex_upper=st.booleans(),
    alias_first=st.booleans(),
    alias_value=st.sampled_from(["alpha", "beta", "%61lpha", ""]),
)
def duplicate_decoded_name_never_reaches_vault(
    position, hex_upper, alias_first, alias_value
):
    key = "account"
    hex_byte = f"{ord(key[position]):02X}" if hex_upper else f"{ord(key[position]):02x}"
    alias = key[:position] + "%" + hex_byte + key[position + 1:]
    pairs = ["account=alpha", f"{alias}={alias_value}"]
    if alias_first:
        pairs.reverse()
    before = origin.accepts
    status, _, body = request(
        proxy.paths["alice"], base + "/v1/items?" + "&".join(pairs),
        headers=headers,
    )
    assert status == 403
    assert origin.accepts == before
    assert "TRANSPORT_AMBIGUOUS_ENCODING" in json.loads(body)["reason_codes"]
```

Replay the generated cases against both backends and compare the promised rejection and upstream effect. Keep a separate valid encoded-value control when rejection must remain narrow: a single canonical `%XX` spelling of the **value** was accepted and reached the origin; a noncanonical lowercase spelling was rejected. That probe is in `gateway_positive.py`. Do not turn unrelated encodings, random query markers, or arbitrary request IDs into generator dimensions without a decision they could change.
