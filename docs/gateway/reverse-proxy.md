# Reverse proxy recipes

Start an application on `127.0.0.1:3000`, save
[http-reverse.json](examples/http-reverse.json), and send:

```sh
curl -H 'Host: app.example.com' http://127.0.0.1:8080/
curl -i -H 'Host: app.example.com' http://127.0.0.1:8080/ads/banner.js
```

The first request reaches the application through Direct; the second returns 204.
The example's `/health` endpoint should return 2xx/3xx for active health checks;
otherwise set `healthPath` empty. Request bodies are streamed with a 16 MiB limit
in this example. Increase or remove that limit for authorized large uploads.

For an HTTPS listener, set:

```json
{
  "listen": "127.0.0.1:8443",
  "tlsMode": "termination",
  "certificateFile": "/etc/yuhaiin/site.crt",
  "keyFile": "/etc/yuhaiin/site.key"
}
```

These are fields on the Gateway, not a separate config file. The site certificate
must cover the hostname used by clients. HTTP/2 ALPN is supported. For an HTTPS
backend, use an `https://` backend URL. Its certificate is verified by default;
`serverName` sets SNI and the verification name, and `trustPem` adds an explicit
private trust root without disabling verification.

For a WireGuard outbound reaching a private service:

```json
{
  "id": "private-app",
  "name": "Private app over WireGuard",
  "revision": 0,
  "backends": [{"url": "http://10.0.0.5:8080", "weight": 1}],
  "balance": "round_robin",
  "outbound": {"type": "selector", "id": "wireguard-selector"}
}
```

Create that existing Selector using the normal Outbound UI and select the
WireGuard node. Then reference `private-app` in a `reverse_proxy` action. With
`preserveHost: true`, `app.example.com` remains the HTTP Host while TCP goes to
`10.0.0.5:8080`. An HTTPS private backend may use `serverName: "backend.example"`
for SNI/certificate verification. Any other TCP-compatible node uses the same
`netapi.Proxy` connection path; no protocol-specific Gateway adapter is needed.

Upstreams support round robin, weighted round robin, and least active **HTTP
requests**. The latter is deliberately named `least_requests`: HTTP/2 stream
counts are not equivalent to socket counts. Passive failures quarantine a backend;
active HEAD probes can recover it. Timeouts and connection/concurrency/rate limits
are independently configurable. Explicit retries cover network failures for
replayable idempotent requests only; POST/PATCH bodies are not replayed by default.

WebSocket Upgrade, SSE, and gRPC use the same reverse-proxy action. There is no
body-buffering mode to turn on. Use an HTTPS backend for HTTP/2/gRPC and ensure
the endpoint supports ALPN `h2`. gRPC response trailers are preserved. `requestTimeoutMs` bounds ordinary requests and the time until response headers
for long-lived SSE, WebSocket, and gRPC streams. Once a streaming response is
established, the total request deadline is disabled; `streamIdleTimeoutMs`
optionally limits periods with **no upstream response data** (or no WebSocket
traffic in either direction). Zero disables that idle limit. This is not a
maximum lifetime for a healthy stream. `idleTimeoutMs` still controls pooled
upstream idle connections, not active streams. URL rewrite replaces configured fields; an
explicit empty query removes all parameters. Path matching uses Go's decoded
`URL.Path`, while forwarding preserves the original encoded path unless rewritten.
