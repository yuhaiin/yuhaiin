# Custom DNS responses

Custom replies match the question name and record type before FakeIP, static
hosts and routed upstream DNS. Configure them in **DNS → Custom replies**, or
with the `resolver.responses.get` and `resolver.responses.put` RPC operations.

For example, POST this object to `/api/v2/rpc/resolver.responses.put`:

```json
{
  "rules": [
    {
      "domain": "*.example.com",
      "queryType": "HTTPS",
      "rcode": "NXDOMAIN",
      "ttl": 0,
      "answers": []
    },
    {
      "domain": "*.a.example.com",
      "queryType": "AAAA",
      "rcode": "NOERROR",
      "ttl": 300,
      "answers": ["::1"]
    }
  ]
}
```

Rules apply in list order: the first matching name/type pair wins, regardless
of whether another rule is more specific. A name is case insensitive and may
have a trailing dot. `example.com` matches only that name. `*.example.com`
matches subdomains at any depth, including `a.b.example.com`, but excludes
`example.com` itself. `*` matches all names. A `queryType` of `*` matches all
record types; `ANY` matches an actual ANY question, not every query.

`answers` contains record data in DNS presentation format, one record per
entry. The question name becomes every answer's owner; the configured TTL
applies to all answers. The answer record type is the selected query type:

| Query type | Example answer data |
| --- | --- |
| A | `192.0.2.1` |
| AAAA | `::1` |
| TXT | `"custom text"` |
| MX | `10 mail.example.com.` |
| SRV | `0 5 443 service.example.com.` |
| HTTPS | `1 . alpn="h2,h3"` |

Multiple answers are supported. TTL zero disables caching by clients that
respect the record TTL. An empty NOERROR reply returns no records (NODATA).
Other supported codes are NXDOMAIN, REFUSED, SERVFAIL, FORMERR and NOTIMPL.
Non-NOERROR replies, wildcard query types and ANY questions cannot include
answer data. OPT/TSIG metadata and zone transfers are not supported.

NXDOMAIN is selected by question type, as in the first example, but its DNS
meaning remains "the name does not exist." Some clients can cache it across
types. Use NOERROR with no answers when the intended meaning is that only a
particular record type is absent. Negative replies do not synthesize an SOA.

Only Internet-class questions are matched. Unmatched questions follow the
existing resolver pipeline, including forced FakeIP for intercepted traffic.
The resolver's `LookupIP` method also applies A/AAAA rules and preserves
family-specific lookups. These rules govern DNS answers; they do not rewrite
connection destinations or create reverse/FakeIP mappings. Bootstrap and
explicit upstream diagnostic queries continue to query their selected resolver.

Saving validates names, types, codes and record data before persisting an
ordered snapshot in SQLite `settings_kv` under `dns/response_rules`. The existing
configuration backup includes these settings. Successful saves atomically
replace the active snapshot and refresh the system DNS cache. Invalid updates
leave the saved and active configuration intact. Saving `{"rules":[]}` clears
all custom replies. Rules are restored at application startup.

The implementation lives in `pkg/net/dns/response`, with no dependency on
FakeIP or hosts. `pkg/resolver/DNSServer` owns the listeners and intercepted DNS
entry points, while application assembly puts the custom resolver ahead of
FakeIP. Matching uses immutable exact-name and suffix indexes; lookup work
depends on name depth rather than the total number of configured rules.

See [DNS benchmarks](benchmarks/dns-responses.md) for full packet processing,
loopback UDP, CPU and allocation measurements.
