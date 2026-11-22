# DNS history

DNS history records one row per client DNS request, from receipt to the
delivery of the response. It covers the local DNS listeners (UDP and TCP)
and DNS hijacking (UDP and TCP) with one model, and stores what really
happened rather than what the configuration suggests.

## Observation

```text
Local listener (UDP/TCP) ─┐            Inbound DNS hijack (UDP/TCP)
  server starts trace     │              inbound starts trace, records
                          │              rejections before the agent
                          ▼                        │
                 netapi.DNSTrace  ◀────────────────┘
                          │ (carried in the request context)
                          ▼
        dnsServer.DoDatagram / handleTCP ── admission: cache_hit, queued,
                          │                  budget_full, queue_full, expired
                          ▼
     custom responses → FakeIP → hosts → route → upstream client
       source:custom     decision    hosts    rule,     cache hit/miss,
                         & result    rewrite  mode,     shared exchange,
                                              resolver  attempts
                          ▼
            pack / truncate → WriteBack → Finish (exactly once)
                          ▼
         bounded queue → batch worker → dns_query_history
```

* The trace is created by whoever receives the request: the DNS server for
  its own listeners, the inbound for hijacked traffic. Once the request is
  handed to the DNS agent (`DoDatagram`/`DoStream`), the agent finishes the
  trace, including on a synchronous error. `Finish` is idempotent.
* Every layer records only results it produced: the FakeIP pool records the
  address it actually returned, the route the rule that matched, the
  upstream client the server and every exchange it performed. A
  configuration flag such as `ForceFakeIP` is stored next to the result, not
  instead of it.
* Lookups made while matching route rules (GeoIP, IP rules), background
  cache refreshes and upstream dials do not write to the client's trace.
* While history is disabled no trace exists. Resolver layers skip even the
  context lookup (`activeDNSTraces == 0`), and the DNS path keeps its
  previous frame sizes.

## Outcomes

The DNS RCODE and the request outcome are separate. `success`, `nxdomain`
and `nodata` are delivered answers. `servfail`, `refused` and
`other_rcode` are delivered error responses. `timeout`, `canceled`,
`rejected`, `dropped`, `malformed`, `write_error` and `internal_error` are
request failures, each with a failure stage and reason, for example
`dns_admission/queue_full`, `dns_admission/expired`, `upstream/timeout`,
`traffic_control/download_quota` or `response_delivery/partial_write`.

Drops before a request is parsed (kernel, TUN or UDP receive queues) cannot be
attributed to a domain and stay in the aggregate
`yuhaiin_udp_receive_dropped_packets_total` metric. A full history queue
drops the history record, never the DNS request; it is counted separately as
`yuhaiin_dns_history_record_dropped_total` and in the recorder status.

## Storage

`dns_query_history` (migration 27) keeps filter and sort fields as columns
and display-only details (records, flags, attempts) as JSON. Records are
generic presentation-format RRs; at most 32 per section and 512 bytes of
RDATA are kept, and the omitted counts are stored. The raw wire packet and
EDNS options (for example ECS) are never stored. Resolver URLs are stored in
redacted form.

Writes never happen on the DNS path: completed traces enter a bounded
channel, a worker writes them in one transaction per batch with a reused
prepared statement, and a write error drops that batch (counted) instead of
retrying without bound. Retention (default 72 hours and 20,000 rows, 5,000 in
Lite mode) runs periodically and when the settings change. Both tables are
runtime data and are excluded from configuration backups.

## API

All operations are RPC endpoints (`POST /api/v2/rpc/<operation>`):

| Operation | Permission |
|---|---|
| `dns.history.list` (cursor pagination, filters) | `dns-history:read` |
| `dns.history.get` | `dns-history:read` |
| `dns.history.stats` | `dns-history:read` |
| `dns.history.settings.get` | `dns-history:read` |
| `dns.history.clear` | `dns-history:write` |
| `dns.history.settings.put` | `dns-history:write` |

The list is ordered by `(created_at DESC, id DESC)`, a total order, so rows with
equal timestamps are neither repeated nor skipped. A list can be read by page
number (the Web UI keeps `to` fixed while paging, so new requests do not shift
pages) or by cursor, the last row's key, which needs no OFFSET scan. `sortBy`
(`time`, `domain`, `type`, `result`, `latency`) and `sortOrder` choose another
order for numbered pages; ties fall back to newest first and then the id, so
every order stays total. Cursors continue only the default newest-first order.
