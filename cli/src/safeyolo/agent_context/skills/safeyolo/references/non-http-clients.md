# Run non-HTTP clients in agent sandboxes

Use the client's supported proxy mode first. When a protocol needs more, an
external relay or gateway can provide the missing transport.

- [Choose a transport](#choose-a-transport)
- [Example: baresip media through TURN](#example-baresip-media-through-turn)
- [Other practical adapters](#other-practical-adapters)
- [Agent runbook](#agent-runbook)

## Choose a transport

In standard isolated SafeYolo sandboxes, external connections use the
configured Hypertext Transfer Protocol (HTTP) proxy. CONNECT carries
Transmission Control Protocol (TCP) streams. Direct User Datagram Protocol
(UDP) and Domain Name System (DNS) egress are unavailable. See the
[networking model](https://github.com/craigbalding/safeyolo/blob/master/docs/networking-vsock-uds.md).

Check these conditions before choosing a service:

- **Client support:** `HTTP_PROXY` does not make arbitrary sockets use the
  proxy. Use explicit client support or a loopback adapter that issues CONNECT.
  Sending the remote hostname in CONNECT lets the proxy resolve it. Separate
  client DNS lookups still need a solution.
- **Protocol handling:** SafeYolo classifies bytes after CONNECT. Binary
  protocols can use opaque forwarding; text that resembles an HTTP request
  can enter the HTTP parser and fail. A successful CONNECT is not proof of
  application compatibility. Opaque payloads do not receive HTTP inspection or
  credential scanning. See the [classifier](https://github.com/craigbalding/safeyolo/blob/master/proxy/src/tunnels.rs)
  and [CONNECT handling](https://github.com/craigbalding/safeyolo/blob/master/proxy/src/http.rs).
- **Encryption:** Transport Layer Security (TLS) does not imply HTTPS.
  When TLS starts immediately after CONNECT, non-HTTP payloads need the operator's
  [TLS passthrough setting](https://github.com/craigbalding/safeyolo/blob/master/docs/TLS_CERTIFICATE.md#certificate-pinning-and-passthrough).
  Trusting SafeYolo's certificate alone does not make the payload HTTP.
  Passthrough still needs destination permission and does not inspect payloads.
- **Every connection:** Inventory signalling, data, media, discovery and
  callbacks separately. Prefer a protocol's TCP option or HTTPS/WebSocket
  interface when available. Ordinary CONNECT cannot carry a UDP-only mode.

## Example: baresip media through TURN

Session Initiation Protocol (SIP) signalling can work while Real-time
Transport Protocol (RTP) audio fails. Traversal Using Relays around Network
Address Translation (TURN) lets baresip send media to a relay over TCP; the
relay exchanges UDP with the remote media server. The signalling and relay
accounts can be independent.

This topology was reported working in SafeYolo. The commands below are a
reference recipe; live third-party integrations were not rerun for this guide.
Verify the installed client and the actual call.

Before starting, you need:

- Working baresip SIP signalling, `socat`, and a baresip build with the
  [TURN module's TCP support](https://github.com/baresip/baresip/blob/main/modules/turn/turn.c).
- Temporary username/password credentials from your own
  [Twilio Network Traversal Service (NTS) account](https://www.twilio.com/docs/stun-turn/api).
  Generate them outside the sandbox with that account's authorized credentials;
  supply only the temporary NTS credentials to baresip. The client's SIP
  credentials are insufficient. NTS credentials expire after at most 24 hours.
  Your account [pays for relay use](https://www.twilio.com/docs/stun-turn/faq);
  the client's Twilio administrator is not required.
- Permission for the relay hostname and port. This example uses Twilio's
  [plain TCP endpoint on port 3478](https://www.twilio.com/docs/stun-turn/regions).
  Use the hostname from the returned TCP TURN endpoint. Changing only the port
  to 443 does not enable TLS in the client. A TLS variant also needs the
  passthrough configuration above and verification of the relay's certificate.
  Port 3478 adds no TLS encryption; media confidentiality depends on the call's
  own encryption.

Run the forwarder in a dedicated terminal **inside the agent sandbox**, from
any directory. Replace `PROXY_HOST` and `PROXY_PORT` with the host and port in
the existing `HTTP_PROXY` value; this recipe expects an `http://` proxy.
Replace `TURN_HOST` with the returned relay hostname. Local port `13478` must
be unused. The listener binds only to loopback and stays in the foreground.

```sh
socat -d -d \
  TCP4-LISTEN:13478,bind=127.0.0.1,reuseaddr,fork \
  PROXY:PROXY_HOST:TURN_HOST:3478,proxyport=PROXY_PORT
```

The [socat PROXY address](https://manpages.debian.org/trixie/socat/socat.1.en.html)
sends the relay hostname to the proxy without local DNS. `fork` accepts the
separate media/control connections.

In the same sandbox, use the profile directory from your working baresip
invocation (`-f DIR` if set; normally `~/.baresip` on Linux). Edits to its
`config` and `accounts` files persist across restarts. Add this line to that
`config` if absent:

```text
module turn.so
```

Set or replace these parameters on the existing working line in baresip's
active `accounts` file. Replace `NTS_USERNAME` and `NTS_PASSWORD` with the
temporary credentials. Keep that file private and out of commits and logs.
Use `medianat=turn`; the [Interactive Connectivity Establishment (ICE) module](https://github.com/baresip/baresip/blob/main/modules/ice/ice.c)
uses a different TURN path that still requests UDP.

```text
;medianat=turn;stunserver="turn:127.0.0.1:13478?transport=tcp";stunuser=NTS_USERNAME;stunpass=NTS_PASSWORD
```

Restart baresip and place a test call. Success means relay allocations,
external relay addresses/ports in the Session Description Protocol (SDP), and
audio in both directions. SIP registration or CONNECT success alone is
insufficient. Renew expired NTS credentials before another session.

End the call and exit baresip, then press Ctrl-C in the forwarder terminal.
Avoid process-name-wide cleanup such as `pkill socat`; other forwarding
processes may use the same executable.

## Other practical adapters

These are candidates with documented transport support, not a SafeYolo
compatibility matrix. Check the installed version, proxy support, DNS startup
and TLS handling before relying on one.

| Need | Adapter and sandbox-side transport | Requirement or tradeoff |
| --- | --- | --- |
| A fixed UDP service, such as syslog or StatsD | [wstunnel](https://github.com/erebe/wstunnel): local UDP socket to secure WebSocket (`wss://`), with `--http-proxy` and `--tls-verify-certificate` | Run its server outside the sandbox. Use datagram framing; a raw UDP-to-TCP pipe loses message boundaries. TCP retransmission can delay later packets. |
| Private database or shell access | [Tailscale userspace networking](https://tailscale.com/docs/concepts/userspace-networking) with a local SOCKS5 proxy and [TCP relay fallback](https://tailscale.com/docs/reference/faq/firewall-ports) | Requires access to the destination network. Configure the daemon's upstream proxy separately from the application's local proxy. No kernel tunnel device is needed. |
| Incoming webhooks or callbacks | [ngrok](https://ngrok.com/docs/gateway/agent/config/v3#proxy_url): outbound TLS tunnel using `proxy_url` | Publishes a reachable endpoint. Account for authentication, additional service endpoints and non-HTTP TLS passthrough. |
| An application that insists on DNS queries | [dnscrypt-proxy](https://github.com/DNSCrypt/dnscrypt-proxy/blob/master/dnscrypt-proxy/example-dnscrypt-proxy.toml): local resolver to DNS over HTTPS (DoH) | Use `http_proxy` with a DoH resolver and `http3 = false`. Ensure startup does not require external DNS. Name resolution does not supply a route for application traffic. |
| A remote desktop or terminal | [Apache Guacamole](https://guacamole.apache.org/): browser access to an external gateway | The gateway reaches the desktop or shell. The target application executes outside the sandbox. |

## Agent runbook

1. **Inventory:** record the client/version, each connection's destination and
   transport, DNS needs, credentials, callbacks and an application-level success
   check. Keep the working signalling path when only media needs repair.
2. **Select:** prefer built-in proxy/TCP support, then a protocol-aware relay,
   then an adapter. Record who operates the relay, what data it receives and
   who pays. The relay's onward reach is not constrained by SafeYolo's outer
   hostname permission; use the relay's own access controls for that scope.
3. **Configure:** preserve the supplied proxy and certificate environment.
   Use the public certificate authority (CA) certificate; keep the host's
   private signing key outside the sandbox. Keep certificate verification
   enabled, including for passthrough.
   Bind local adapters to loopback. Keep credentials out of command arguments
   and reports. If access or passthrough is missing, follow
   [troubleshooting and escalation](troubleshooting.md). Do not substitute a
   relay for an explicit denial.
4. **Verify:** check the application result in both directions. Report the
   observed result, remaining failures and untested assumptions separately.
   SafeYolo health, an open socket and a relay allocation each prove less than
   a completed call, query or callback.
5. **Clean up:** stop only temporary processes you started. Remove temporary
   credentials and test endpoints; preserve services requested for ongoing use.
