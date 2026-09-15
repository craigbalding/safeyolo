"""Finite scalar Request.pretty_url -> urllib logger projection, no sockets."""

import argparse
import json
from pathlib import Path
from urllib.parse import urlparse

from mitmproxy import http
from mitmproxy.net.http import url


def controls():
    base = {
        "scheme": "http",
        "host": "Destination.INVALID",
        "port": 8123,
        "path": "/a;b/c;d?query=yes#fragment",
        "host_header": None,
        "authority": None,
        "http2": False,
    }
    cases = []

    def add(name, **changes):
        cases.append({"name": name, "input": dict(base, **changes)})

    add("destination_fallback")
    add("empty_host_fallback", host_header="")
    add("h1_ignores_authority", authority="ignored.invalid:443")
    add("h2_authority_priority", http2=True, authority="Authority.INVALID:9000", host_header="ignored.invalid")
    add("h2_empty_authority_fallback", http2=True, authority="", host_header="Host.INVALID")
    add("h2_missing_both", http2=True)
    add("https_default", scheme="https", port=443, path="/", host_header="Host.INVALID")
    add("unknown_scheme", scheme="custom", host_header="Host.INVALID", path="/x;y")
    for name, header in [
        ("ordinary", "Host.INVALID"),
        ("port", "Host.INVALID:1234"),
        ("port_zero", "Host.INVALID:0"),
        ("port_unicode", "Host.INVALID:８０"),
        ("port_overflow", "Host.INVALID:65536"),
        ("port_empty", "Host.INVALID:"),
        ("port_negative", "Host.INVALID:-1"),
        ("port_noninteger", "Host.INVALID:bad"),
        ("ipv6_brackets", "[2001:DB8::1]:8080"),
        ("ipv6_unbracketed", "2001:DB8::1"),
        ("ipv6_loopback", "[::1]"),
        ("ipv6_scope", "[FE80::1%ZoneABC]:80"),
        ("ipv6_bad_scope", "[fe80::1%]:80"),
        ("bracket_ipv4", "[127.0.0.1]"),
        ("bracket_name", "[owned.invalid]"),
        ("ipvfuture", "[v1.future]"),
        ("ipvfuture_bad", "[vQ.future]"),
        ("bracket_open", "[::1"),
        ("bracket_close", "::1]"),
        ("bracket_prefix", "before[::1]"),
        ("bracket_suffix", "[::1]tail"),
        ("userinfo", "user@Host.INVALID"),
        ("userinfo_multiple", "a@b@Host.INVALID:80"),
        ("slash_host", "left.invalid/injected"),
        ("query_host", "left.invalid?injected"),
        ("fragment_host", "left.invalid#injected"),
        ("space_host", " Host.INVALID "),
        ("tab_crlf_host", "Ho\tst.IN\rVAL\nID"),
        ("port_terminal_lf", "Host.INVALID:80\n"),
        ("unicode_host", "BÜCHER.INVALID"),
        ("unicode_sigma", "ΟΣ.INVALID"),
        ("percent_zone", "HOST%ZoneABC"),
        ("nfkc_slash", "owned／invalid"),
        ("nfkc_colon", "owned：80"),
        ("nfkc_at", "owned＠invalid"),
        ("nfkc_account", "℀.invalid"),
        ("nfkc_benign", "ＣＡＦÉ.invalid"),
        ("duplicate_joined_host", "one.invalid, two.invalid"),
    ]:
        add(name, host_header=header)
    for name, path in [
        ("star", "*"),
        ("empty_path", ""),
        ("relative_path", "relative;x"),
        ("semicolon_last", "/one;p/two;q;rest"),
        ("semicolon_earlier", "/one;p/two"),
        ("query_first", "?q=/x;y#frag"),
        ("fragment_first", "#frag?query"),
        ("unsafe_path", "/a\tb\rc\nd;param?x=y"),
        ("no_percent_decode", "/%3B/%2F;drop"),
        ("unicode_path", "/é/中文;drop"),
        ("trailing_space", "/path "),
        ("control_path", "/a\x00b\x1fc"),
    ]:
        add(name, path=path, host_header="Host.INVALID")
    add("unicode_final_sigma", host_header="ΟΣ")
    add("unicode_version_gap", host_header="Ɤ.invalid")
    return cases


def observe(case):
    values = case["input"]
    headers = http.Headers()
    if values["host_header"] is not None:
        headers["Host"] = values["host_header"]
    request = http.Request(
        values["host"],
        values["port"],
        b"GET",
        values["scheme"].encode(),
        (values["authority"] or "").encode(),
        values["path"].encode(),
        b"HTTP/2.0" if values["http2"] else b"HTTP/1.1",
        headers,
        b"",
        None,
        0.0,
        0.0,
    )
    result = dict(case)
    if case["name"] == "unicode_version_gap":
        result["native_gap"] = "Compatibility"
    result["selected_header"] = request.host_header
    if request.host_header:
        result["parsed_authority"] = list(url.parse_authority(request.host_header, check=False))
    result["pretty_url"] = request.pretty_url
    try:
        parsed = urlparse(request.pretty_url)
        result["result"] = {"host": parsed.hostname or "", "path": parsed.path}
    except ValueError:
        result["error"] = "Parse"
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    options = parser.parse_args()
    rows = [observe(case) for case in controls()]
    assert len(rows) <= 60
    fixture = Path(__file__).with_name("traffic_url_source.json")
    if options.check:
        assert rows == json.loads(fixture.read_text())
        print(f"{len(rows)} actual scalar pretty-URL rows match")
    else:
        fixture.write_text(json.dumps(rows, indent=2, ensure_ascii=True) + "\n")


if __name__ == "__main__":
    main()
