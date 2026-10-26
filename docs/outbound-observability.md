# Outbound runtime observability

Outbound nodes now expose persistent per-node observations independently of
the lifetime of their cached `netapi.Proxy` instances. The state is keyed by
**stable Node ID**, not the editable Node Name.

## Collection

The existing outbound interface is wrapped once at each selected node
boundary. Ordinary connection operations remain entirely in memory:

- TCP dial attempts, successful connections and active sessions
- UDP session attempts, successful sessions and active sessions
- successful logical UDP datagrams sent and received
- successful application payload bytes read and written
- ping attempts, last attempt/success/error timestamps
- the most recent bounded error text
- explicit TCP, DNS/DoQ, IP, STUN and STUN/TCP probe results

An optional `NodeRuntimeStatusProvider` lets a protocol report its own
tunnel state. The generic wrapper never treats a created proxy object as
proof that a VPN tunnel is connected.

Payload bytes are **not wire bytes**. TCP read calls are not TCP packet
counts. UDP packet counts count successful application datagrams, not
fragments or encrypted underlay traffic.

### Nested node accounting

Set selectors and nested chains can be visited at more than one node
boundary. Their statistics are intentionally **per-node** and must not be
summed together to produce global traffic usage. The existing connection
monitor provides the authoritative global transferred-byte totals. Each
node's counters express traffic handled at that node boundary.

## Health semantics

`unknown`: No recent evidence. Never implies failure or success.

`healthy`: A stream/session/ping or explicit probe recently succeeded.

`degraded`: The latest observed attempt/probe recently failed.

`disabled`: The node is disabled in saved configuration.

These are passive observations, not an active continuous online check.
States automatically become `unknown` after **2 minutes** without new
successes/failures. The last observation/error timestamp stays visible.
No automatic periodic probing of idle nodes is performed, to preserve
battery and prevent involuntary enterprise VPN or authentication traffic.

Note that proxy-session creation may be lazy in some protocol
implementations. A successful generic session creation does not imply a
complete remote handshake; a protocol can implement the optional native
status provider when it can provide a stronger state signal.

## SQLite and lifecycle

Migration v15 adds `node_runtime_stats` with one JSON snapshot per Node ID,
and a foreign key to `nodes_v2` with cascading deletion. Snapshots contain
absolute cumulative values and are updated transactionally every 5 seconds,
or on graceful shutdown. Retrying a failed flush does not double-count data.
A hard crash can lose data since the most recent flush.

Node rename, group updates, policy changes and proxy eviction do not clear
statistics. Real node deletion clears its row; recreating the same ID starts
from zero. The observer and SQLite cleanup account for subscription updates.
Active session counts and current rates are runtime-only and restart at zero.
Configuration backups intentionally omit statistics data.

## HTTP API and frontend

`POST /api/v2/nodes/status` with `{"ids":["node-1","node-2"]}`
returns at most 100 persisted/live node statuses and does not create
outbound instances or run probes. It is suitable for the paginated Nodes
workspace. The existing `node.latency` RPC records test results in the
backend instead of relying on browser localStorage.

All cumulative counters are decimal strings so JavaScript clients do not
round them at 2^53. Upload and download speeds are estimated from 5-second
samples of payload bytes, and may lag one interval.

The native VPN state adapter, per-hop underlay wire counters and optional
background health-check scheduler are separate future enhancements.

## Selector evidence and active download measurements

Opt-in intelligent Selectors extend this same per-node observer with independent
TCP/UDP evidence, bounded comparable latency samples, and active download-test
summaries. Generic passive counters above retain their original meaning; use the
channel evidence and selector decision reasons when inspecting automatic
selection. UDP PacketConn construction no longer records remote-success evidence.
See [intelligent selectors](intelligent-selectors.md) for eligibility, measurement
budgets, persistence, scoring, and current delivery boundaries.

## Native session evidence

The existing optional protocol-status interface now has production adapters for
OpenVPN, L2TP, SoftEther, GlobalProtect and Tailscale. They read existing session
state and expose bounded failure descriptions through the existing status API.
There is no private-key or credential read API and no new statistics subsystem.

- OpenVPN, negotiated L2TP, SoftEther and GlobalProtect report `connected` only
  for a session that completed their existing native authentication/tunnel setup.
- Static L2TPv3 reports `configured`: its local setup does not prove a peer handshake.
- Tailscale control readiness reports `configured`, never a peer WireGuard
  handshake. An unavailable control state is separate from native tunnel loss.
- `authentication_failed` requires administrator attention. Automatic selection
  excludes it as unavailable without incrementing transport failures/loss.
- `idle`, `connecting`, `reconnecting`, `closed`, `failed` and `disconnected` remain
  explicit lifecycle states. A status read never starts login or network probes.

`updatedAt` is the time of the session-state observation in Unix seconds, not the
last packet time or a last-handshake claim. Scheduled native probes ignore stale,
future and configuration-only snapshots. Native tunnel evidence remains distinct
from a successful HTTPS request or remote TCP/UDP target response and never
supplies a comparable target RTT. Other protocols without trustworthy native
status continue to use their existing passive/explicit network observations.

The Nodes panel localizes these states in EN/JA/KO and displays observation time
and this evidence boundary. Candidate details retain raw latency/throughput when
native availability excludes the candidate, alongside an explicit reason.
