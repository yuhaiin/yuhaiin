# Configuration loading and failure isolation

Saved data and an active listener are different things. Unsupported historical
Inbound protocol/network/transport tags remain readable for management, while
new writes still require a valid contract. Startup records a `failed` state and
the concrete validation error/event for each incompatible Inbound, skips that
listener, and continues starting the others. The frontend uses that runtime
state for its status indicator and existing failure/details panel. Nothing is
automatically migrated or deleted.

Audit of the other bulk-loading paths found the same early-return pattern in
Node lists and paging, DNS Resolver lists, subscriptions and publishes. Those
independent-resource lists now log and omit an undecodable/invalid stored row
while continuing with valid rows. Direct reads and new writes retain validation.
Database query, scan and iteration errors still fail the operation. Node page
totals count stored rows, including omitted invalid rows. Selector lists read
typed SQL columns without decoding or validating every referenced Node; a failed
selected Node is handled when that destination is used.

Gateway configuration is one dependent policy snapshot. Invalid saved policy or
a listener bind failure leaves the Gateway unavailable, retains its draft for
repair, and exposes `startupError` through runtime status and the UI. Other
application listeners can start. Traffic explicitly selected for the failed
Gateway is closed until a repaired snapshot activates. Store/database load errors
still propagate; CA storage/initialization failures are also still startup errors.

Route rules/lists and Gateway save operations retain atomic validation. A failed
hot update preserves the running snapshot rather than silently dropping a Block
rule or a referenced list. This is different from a set of independent listeners;
the audit does not change cold-start recovery of corrupt Route/CA data.

Regression coverage exercises actual Mixed listeners before and after an old
`reverse_http` entry, SOCKS5 greetings, the failed status/event/detail read, and
unchanged stored JSON. Store cases cover the independent-resource list APIs and
database failures. Gateway cases cover invalid policy, occupied listener,
explicitly selected connection rejection, retained draft and successful repair.
