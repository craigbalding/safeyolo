"""Hypothesis strategies that favor meaningful variation over format trivia."""

from __future__ import annotations

from hypothesis import strategies as st

from experiments.policy_assurance.harness import PolicyWorld, make_world

_LEADING = st.sampled_from(tuple("abcdefghijklmnopqrstuvwxyz"))
_ASCII_LABEL = st.builds(
    lambda first, rest: first + rest,
    _LEADING,
    st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", max_size=13),
)

# Unicode, punycode, case changes, and child domains are always added by the
# decision harness. Keeping the generated base names in one grammar avoids a
# Hypothesis shrinker edge case when switching between sampled and free-form
# strings inside a unique list.
_HOST = st.builds(
    lambda left, right, tld: f"{left}.{right}.{tld}",
    _ASCII_LABEL,
    _ASCII_LABEL,
    st.sampled_from(("com", "net", "dev", "test", "example")),
)

_AGENT = st.builds(
    lambda first, rest: first + rest,
    _LEADING,
    st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-_", max_size=15),
)

_CREDENTIAL = st.builds(
    lambda first, rest: first + rest,
    _LEADING,
    st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-_", max_size=11),
)


@st.composite
def policy_worlds(draw) -> PolicyWorld:
    agents = draw(st.lists(_AGENT, min_size=3, max_size=5, unique=True))
    hosts = draw(st.lists(_HOST, min_size=4, max_size=7, unique=True))
    credentials = draw(st.lists(_CREDENTIAL, min_size=3, max_size=5, unique=True))
    return make_world(agents, hosts, credentials)


agent_names = _AGENT
host_names = _HOST
credential_names = _CREDENTIAL
