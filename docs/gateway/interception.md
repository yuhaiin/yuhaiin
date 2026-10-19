# Explicit traffic interception

The existing common TCP handler supports TUN, SOCKS, Mixed, HTTP CONNECT,
TProxy/Redir, WireGuard and other inbounds that call `netapi.Handler`. No inbound
has its own copy of the HTTP engine. The existing L4 Route selects the Gateway
first; unmatched connections do not enter its protocol probe. With no Gateway
routing actions, the hook returns without allocation or reads. UDP/QUIC is unchanged.
See [Route handoff](route-handoff.md) for configuration and fallback semantics.

Create a matching **Routing -> HTTP Gateway** action and choose its Gateway.
Then choose that Gateway and a stable inbound ID in **Interception**. Modes:

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

## Reproduce on a privileged Linux test machine

These steps are a manual test procedure, not a claim that TUN/TProxy/Redir or
WireGuard device setup was exercised in this change. Use an isolated VM with
root/CAP_NET_ADMIN and a saved copy of its network configuration.

1. Start the application with a temporary state directory. In the existing
   Inbound editor create the desired TUN, TProxy, Redir or WireGuard inbound and
   complete its existing OS route/firewall/peer setup. Record its stable ID.
   Confirm ordinary TCP and UDP forwarding work with interception `off` first.
2. Create an interception-only Gateway (`listen` empty). Give it a default
   `respond` action with body `gateway-ok`; attach an enabled Path prefix
   `/ads/` rule with `block` status 204. Generate its CA and download the public
   certificate to `./gateway-ca.pem`. In Interception select the test inbound,
   mode `https_mitm`, domains `app.example.com`, ports 80 and 443. Save/activate.
   In existing Routing create a rule matching the synthetic destination
   `198.18.0.2/32`, TCP ports 80/443 and this inbound, with HTTP Gateway action
   selecting this Gateway. Apply it before general catch-all routing rules.
3. From the client captured by that inbound, run:

   ```sh
   curl --noproxy '*' --resolve app.example.com:80:198.18.0.2 \
     --max-time 10 http://app.example.com/health
   curl --noproxy '*' --resolve app.example.com:443:198.18.0.2 \
     --cacert ./gateway-ca.pem --max-time 10 https://app.example.com/health
   curl --noproxy '*' --resolve app.example.com:443:198.18.0.2 \
     --cacert ./gateway-ca.pem --max-time 10 -o /dev/null -w '%{http_code}\n' \
     https://app.example.com/ads/banner.js
   ```

   The first two responses must contain `gateway-ok`; the last must be 204.
   `198.18.0.2` is a synthetic destination: route it through the test inbound;
   there is no required upstream server because these actions respond locally.
   For a SOCKS/Mixed check, replace `--noproxy '*'` with
   `--socks5 127.0.0.1:1080` (use the configured client-side proxy address).
4. Repeat HTTPS without `--cacert`: it must fail trust verification. Exclude
   `app.example.com` or switch to `off`: a fresh request to the synthetic
   destination must no longer receive the Gateway's local response. Existing
   decrypted sessions are closed when an admission constraint excludes them.
5. Replace the default action with `forward`, use a real controlled destination,
   and verify its actual certificate and response. Compare TCP and UDP before
   and after disabling interception. Restore the VM network configuration.

Repeat independently for each supported inbound and for a remote WireGuard
client, preserving that client's source IP. Inspect Gateway counters and existing
Connections to confirm the intended inbound/outbound. An unreachable synthetic
address before setup is expected and does not demonstrate interception success.
