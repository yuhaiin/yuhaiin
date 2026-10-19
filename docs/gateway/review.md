# Implementation review

Review compared backend main `d6c071d669e7078d643cca7b95280f712e0bc93a`
and frontend main `2297510a2af7e021a19575192eefef622a4564db` with the Gateway
branches. Standards and specification were reviewed independently.

## Standards

No additional repository-documented hard violation was found. Two ownership
findings were repaired: header row drafts now follow parent resets/action
changes, and domain deletion helpers remove Gateway/filter/interception and
rule references atomically. Referenced Upstreams cannot be deleted accidentally.
Component regressions cover Discard, action changes and resource deletion.
Resource panels also remain expanded while naming a new resource.

## Spec

Six concrete findings were repaired and covered by regression tests:

- Wildcard listeners now distinguish local destinations from remote hosts on
  the same port, retaining actual socket reentry detection.
- Admission metadata is retained and checked after hot updates. Existing MITM
  HTTP/2 sessions close when domain, port, source, process or mode no longer
  permits them, or their Gateway is disabled.
- Managed listeners track physical connections below TLS, preserving standard
  HTTP/2 handling while closing hijacked WebSockets on disable/delete/shutdown.
- The tester reports the effective Upstream outbound fallback and differentiates
  ordinary listener TLS from inbound MITM admission.
- Replacing a Gateway at the same address closes the previous owner's sockets
  while keeping the already-bound listener, avoiding a fallible post-commit bind.
- Tester source IP/process inputs allow source-constrained admission to be
  evaluated using the same predicate as active sessions.

Follow-up reviews confirmed the reported scenarios fixed. Additional tests cover
unsupported/no ALPN passthrough/rejection with byte-for-byte ClientHello replay,
IP destinations without SNI, rejected upstream client-certificate authentication
without fallback, inbound filtering, and incomplete TLS probe timeout/replay.

Standards: 2 findings resolved, 0 outstanding. Spec: 6 findings resolved,
0 outstanding within the reviewed scenarios. These checks do not replace the
manual platform/client verification boundaries in the other Gateway documents.

## Existing Route handoff and admission optimization

Incremental review compared backend `ad719ae1` and frontend `025878e` with the
follow-up changes. The independent standards pass found no actionable violation
or ownership defect: both Routing editors share the same Gateway picker/action
transition, and HTTP request forks cannot reuse the connection's cached route.

The specification pass found one P2: Yuubinsya Ping destinations carry a TCP
address label, so checking that label alone could select a Gateway target for
Ping. Ping and PacketConn now explicitly skip Gateway actions when such rules
exist. A regression failed before the fix for both Direct and Block fallback,
then passed under the race detector. A deterministic Apply-between-check-and-match
regression also covers installation of the first Gateway rule during dispatch.
The final result is rechecked before outbound selection. The disabled path does not allocate a
skip marker. DNS already skips Gateway actions explicitly.

The review also checked ordinary rule precedence, passthrough, reentry/block
preservation, reference integrity for saved/applied rules, and the actual common
handler/TLS integration. Tests cover cheap admission failures, process lookup
reuse, unused health workers, long HTTP headers with the smaller probe buffer,
and zero-allocation filtering for unrelated hosts.
