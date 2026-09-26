# Proxy review examples

These examples describe test shapes, not a new harness. Use the repository's existing acceptance runner and real proxy/sinkhole boundary. A pure parser test can help isolate a failure, but it does not establish proxy behavior.

## Query and header normalization

**Property:** the routed destination and credential treatment follow the documented canonical interpretation, even when fields have alternative representations. A denied request reaches no upstream sinkhole.

Begin with one valid request. Generate query pairs as an ordered list so duplicate keys survive construction. Vary a relevant key's case and percent encoding, a value's empty/encoded form, and whether the same authority field appears in a header or body. Start with one change at a time; cross two dimensions when their interaction is the suspected defect. Send raw bytes where the parser boundary matters instead of using a URL builder that silently normalizes them. Inspect what the upstream sinkhole actually received, as well as the client response. For parity, feed the identical raw request to Python and Rust.

One useful strategy shape is `st.lists(st.tuples(key_strategy, value_strategy), min_size=0, max_size=4)` with an `@example` containing two copies of the authority-bearing key. Add generated values beyond the examples: `st.text` from a constrained relevant alphabet or `st.binary` for raw-wire paths. Keep invalid syntax only when rejection itself is the property.

## Credential classification and authorization

**Property:** an actual credential in the guarded position triggers the specified decision; similar-looking noncredentials do not, and rejected material is not forwarded or logged in cleartext.

Choose the sensor before generating placements. In current SafeYolo, credential guard classifies request **headers** using the provider catalogue and an entropy fallback; the enabled pattern scanner (DLP) can inspect URL, headers, and body. A body-only probe cannot establish credential-guard behavior. Generate synthetic token-like text with variable prefix, length, delimiter, casing, surrounding prose, and placement relevant to that sensor. Keep separate valid-positive and valid-negative strategies so a run is not dominated by malformed noise. Check a known valid shape first, then vary exact length and boundaries; DLP should identify valid-shaped credentials without treating invalid fragments as that provider. Check the decision and the upstream/log effect. If testing an authorization rule, substitute the principal or scope independently of the object ID, then explicitly test their combination. A 428, 403, or 200 response by itself does not prove the property. Do not put real service credentials in generated cases or failure reports.

## Reused connections and ordered messages

**Property:** a decision or parser error for one request does not improperly authorize, route, or corrupt the next request on the same connection; the proxy closes or recovers as specified.

Use `st.lists(operation_strategy, min_size=2, max_size=5)` or a Hypothesis state machine when the valid next operation depends on earlier state. Include a valid baseline request, then generate short variations such as valid→invalid→valid, two different destinations, slow consumer→normal consumer, or partial frame→complete frame. Use a single real connection for each generated sequence and a fresh connection between examples. Assert after **each** operation using both caller observations and sinkhole or connection state. A list of independent new connections cannot test state leakage.

These are input-space examples, not automatic requirements for every PR. Pure presenter lifetime, build portability, and resource accounting may need event or measurement probes instead. A structured field or meaningful request order is the reason to reach for Hypothesis.
