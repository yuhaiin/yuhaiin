# Explicit traffic interception

The existing common TCP handler supports TUN, SOCKS, Mixed, HTTP CONNECT,
TProxy/Redir, WireGuard and other inbounds that call `netapi.Handler`. No inbound
has its own copy of the HTTP engine. With no active interception entries the hook
returns without allocating or reading the stream. UDP/QUIC is unchanged.

Choose a Gateway and an existing stable inbound ID in **Interception**. Modes:

| Mode | Behavior |
| --- | --- |
| `off` | Existing forwarding |
| `http_only` | Admit HTTP/1.1 plaintext; leave TLS/binary streams intact |
| `tls_passthrough` | Existing encrypted forwarding; no HTTP path/header visibility |
| `https_mitm` | Admit HTTP and explicitly allowlisted HTTPS using the local CA |

Source CIDRs, destination ports, process paths, domains, and excluded domains
further constrain admission. An excluded inbound has no active interception
entry. MITM requires a nonempty domain allowlist and a generated/imported CA.
Generate the CA in TLS/CA first, and install its public root only on authorized
clients. [explicit-mitm.json](examples/explicit-mitm.json) illustrates a TUN with
stable ID `tun`, allowing only `app.example.com` and excluding a pinned subdomain.
Use your actual inbound ID and preserve existing config/revisions when saving.

For plaintext only, change the example mode to `http_only`. For encrypted
passthrough, use `tls_passthrough`; HTTP policies cannot inspect those requests.
Listener `termination` is separate: it uses an ordinary configured site
certificate, not the MITM CA.

TLS probes use the public `crypto/tls` ClientHello callback, a bounded 64 KiB
capture, and a write sink. Probe alerts never reach the client. All captured and
read-ahead bytes are replayed before passthrough or the real MITM handshake.
ALPN must advertise HTTP/1.1 or h2 for MITM. Missing SNI can use a recovered DNS
name or an IP SAN. ECH offers and unsupported ALPN follow `unknownTls`
(`passthrough` by default, or `reject`) before a real server handshake is sent.
Once real MITM handshake bytes are sent, failure closes the connection; there is
no misleading fallback to the original TLS session.

Client certificate authentication, pinned clients, clients rejecting user CAs,
non-HTTP TLS and ECH plaintext are not bypassed. Pinning/trust failures fail the
client handshake. An upstream requesting a client certificate fails unless its
existing outbound chain independently owns that authentication; Gateway does
not impersonate the client's private key. Exclude such traffic in advance.
No HTTP/3 decryption, forced UDP 443 blocking, or silent HTTP/3 downgrade occurs.

The original destination and immutable inbound/source context accompany every
request. Forwarding uses that admitted destination rather than a client-chosen
arbitrary authority. Internal outbound sockets are tracked to reject recursive
Gateway/inbound reentry, including a backend alias resolving to a listener. These
checks supplement existing Route security; they do not globally bypass Route.
