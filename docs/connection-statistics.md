# Connection statistics

`GET /api/v2/connections/statistics` (`connections:read`) reports a
**runtime-only** breakdown of the connections opened through yuhaiin since the
process started, or since the last
`POST /api/v2/connections/statistics/reset` (`connections:write`).

| Field | Meaning |
|---|---|
| `active`, `activeTcp`, `activeUdp` | Connections open right now. |
| `opened`, `failed`, `closed` | Dials that succeeded, dials that failed, connections that closed. |
| `download`, `upload` | Bytes transferred in the period. |
| `connectTime` | Histogram of routing + outbound dial time of successful connections. |
| `lifetime` | Histogram of how long closed connections stayed open. |
| `failures` | Failed dials by cause: `timeout`, `refused`, `reset`, `unreachable`, `dns`, `blocked`, `canceled`, `other`. |
| `history` | One hour of 10-second intervals: opened, failed, closed, peak active, summed connect time, download, upload. |

Histogram buckets use `leMs` as the inclusive upper bound; `0` marks the final
open-ended bucket.

## Cost

Opening, failing or closing a connection costs a few atomic increments and one
short mutex section. Reads and writes are not touched: per-interval traffic is
sampled from the running totals when an event or a snapshot happens, and bytes
between two samples are spread evenly across the quiet intervals in between.

## Lifecycle

- Nothing is written to SQLite; a restart starts from zero.
- Reset clears the breakdown only. The persisted traffic totals, the traffic
  series, telemetry and the Android session summary are left untouched.
- Connections open during a reset stay counted as active and are counted as
  closed when they end.

## Country telemetry

The persisted telemetry (`GET /api/v2/connections/telemetry`) also groups
traffic and failures by `geo` (destination country) and `outboundGeo` (country
of the outbound peer). Both are ISO 3166-1 alpha-2 codes from the configured
GeoIP database and are omitted when no database is configured.
