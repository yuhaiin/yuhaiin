# Inbound ingress statistics

Inbound runtime status reports three **cumulative ingress** counters, keyed by
stable Inbound ID:

- **Accepted streams**: TCP streams delivered to the Inbound handler.
- **Received packets**: packets delivered to the datagram handler.
- **Received pings**: ICMP/ping events delivered to the Inbound handler.

These counts describe ingress admission, **not successful end-to-end forwarding**.

## Persistence and lifecycle

The counters are updated using Go atomic increments on the request path.
A background task takes absolute snapshots and writes changed totals to SQLite
in one transaction every five seconds. Shutdown performs a final flush before
the SQLite database closes. Abrupt termination may lose the unflushed interval.

The database migration creates `inbound_statistics` (one row per Inbound ID).
Existing installations start from zero because historical counters were not
previously stored. Repeated snapshot writes are idempotent.

- Restarting the application restores the counters before listeners start.
- Editing, disabling or re-enabling an existing Inbound keeps its totals.
- An Inbound that fails to start retains previously saved counts.
- Deleting an Inbound removes its statistics in the same SQLite transaction
  as the configuration record. Reusing that ID begins at zero.
- Counter history is runtime data and does not appear in config-only exports.
  Listener health and lifecycle events remain separate, transient signals.

The existing `inbounds.status` RPC and Inbound runtime panel display these
values as decimal strings to avoid JavaScript numeric precision loss.
No management API or frontend contract migration is required.
