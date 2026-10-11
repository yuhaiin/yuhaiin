package mgmt

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/supervisor"
)

// GET /api/metrics — the supervisor's traffic figures in Prometheus text
// exposition format.
//
// The format is emitted by hand rather than through a client library, and that
// is a deliberate constraint rather than an inconvenience. internal/mgmt's
// dependency contract already forbids reaching outside the standard library
// (see README.md there), the module as a whole depends only on golang.org/x,
// and the exposition format is a dozen lines to write: a HELP line, a TYPE
// line, and `name{labels} value` per series. Pulling in a metrics library to
// produce that would cost the "no dependencies outside x/" claim at the top of
// the README for nothing.
//
// # What is exported, and why it stops there
//
// Per peer: bytes and packets each way, as counters. Per listener: whether it
// is up, and how many peers it has. Nothing is exported that the API does not
// already serve on /api/listeners and /api/listeners/{name}/peers -- this is
// the same data in the shape a time-series database ingests, not a second
// source of truth that can disagree with the first.
//
// Peer identity is a label, which is a cardinality decision worth naming: a
// VPN has tens or hundreds of peers, not millions, and per-peer traffic is the
// entire question an operator brings to a metrics endpoint. Aggregating it away
// would leave a total that answers "is this server busy" and not "which of my
// users is".

// handleMetrics writes the exposition. It builds on the same manager calls the
// JSON endpoints use, so a metric and the panel can never disagree about a
// listener's state, and so peer listing keeps going through the manager's locks
// rather than reading a live server handle out from under a rebuild.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder

	metric(&b, "veepin_listener_up", "gauge",
		"Whether a configured listener is running (1) or not (0).")
	statuses := s.mgr.All()
	// Sorted, because the exposition format does not require an order and a
	// diff of two scrapes is a normal debugging move.
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].Name < statuses[j].Name })
	for _, st := range statuses {
		up := 0
		if st.State == "running" {
			up = 1
		}
		fmt.Fprintf(&b, "veepin_listener_up{listener=%s,protocol=%s} %d\n",
			label(st.Name), label(st.Protocol), up)
	}

	// Abandoned listeners: a listener whose Close overran the supervisor's grace
	// period and is still holding its packet-pump goroutine and TUN fd.
	//
	// This is the one series here that is not also on /api/listeners, and it
	// earns the exception because it is the only failure in the supervisor that
	// gets worse over time rather than merely staying broken -- a fleet
	// restarting a genuinely wedged listener on a timer accumulates one of each
	// per attempt. Before this it was visible only as a log line.
	//
	// Both halves are exported deliberately. The gauge answers "is something
	// wedged right now"; the counter answers "has this ever happened", which is
	// what survives a listener that eventually unblocks and would otherwise
	// erase the evidence between two scrapes.
	// Optional on the backend rather than part of ManagerBackend, the same way
	// client.DualStackServer is optional on a server: a fake backend in a test
	// or the e2e harness has nothing to report, and a required method would
	// make every one of them implement a stub that lies. A backend that cannot
	// say is absent from the scrape rather than exported as zero, for the same
	// reason the peer block above skips a listener it cannot ask.
	if r, ok := s.mgr.(interface{ Abandoned() (int, uint64) }); ok {
		current, total := r.Abandoned()
		metric(&b, "veepin_listeners_abandoned", "gauge",
			"Listeners whose Close overran the stop grace period and still hold a goroutine and TUN fd.")
		fmt.Fprintf(&b, "veepin_listeners_abandoned %d\n", current)
		metric(&b, "veepin_listeners_abandoned_total", "counter",
			"Listeners abandoned since this process started.")
		fmt.Fprintf(&b, "veepin_listeners_abandoned_total %d\n", total)
	}

	// Peers are collected once and used for both the count and the per-peer
	// series, so the two can never disagree within one scrape -- which they
	// would if each metric block asked the manager again and a client
	// connected in between.
	type listenerPeers struct {
		status supervisor.Status
		peers  []client.PeerInfo
	}
	collected := make([]listenerPeers, 0, len(statuses))
	for _, st := range statuses {
		peers, avail := s.mgr.Peers(st.Name)
		if avail != supervisor.PeersOK {
			// A listener that is stopped, or a protocol that cannot report
			// peers, is deliberately absent rather than exported as zero. Zero
			// is a claim ("no peers"), and absence is the truth ("we cannot
			// say") -- and a dashboard alerting on "peers dropped to 0" should
			// not fire because a protocol never had the capability.
			continue
		}
		collected = append(collected, listenerPeers{status: st, peers: peers})
	}

	metric(&b, "veepin_listener_peers", "gauge",
		"Peers a listener currently reports.")
	for _, lp := range collected {
		fmt.Fprintf(&b, "veepin_listener_peers{listener=%s,protocol=%s} %d\n",
			label(lp.status.Name), label(lp.status.Protocol), len(lp.peers))
	}

	for _, m := range []struct {
		name, help string
		value      func(client.PeerInfo) uint64
	}{
		{"veepin_peer_rx_bytes_total", "Inner bytes received from a peer.",
			func(p client.PeerInfo) uint64 { return p.RxBytes }},
		{"veepin_peer_tx_bytes_total", "Inner bytes sent to a peer.",
			func(p client.PeerInfo) uint64 { return p.TxBytes }},
		{"veepin_peer_rx_packets_total", "Inner packets received from a peer.",
			func(p client.PeerInfo) uint64 { return p.RxPackets }},
		{"veepin_peer_tx_packets_total", "Inner packets sent to a peer.",
			func(p client.PeerInfo) uint64 { return p.TxPackets }},
	} {
		metric(&b, m.name, "counter", m.help)
		for _, lp := range collected {
			for _, p := range lp.peers {
				fmt.Fprintf(&b, "%s{listener=%s,protocol=%s,peer=%s} %d\n",
					m.name, label(lp.status.Name), label(lp.status.Protocol),
					label(p.ID), m.value(p))
			}
		}
	}

	// text/plain with the version parameter is what Prometheus's own scraper
	// looks for; without it a scrape still works but negotiates down.
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

// metric writes the HELP and TYPE header lines for one metric family.
func metric(b *strings.Builder, name, typ, help string) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

// label renders a label value, quoted and escaped.
//
// Escaping is not optional here and is easy to skip: every label value on this
// endpoint is operator-supplied -- a listener name from a config file, a peer
// ID that is a username or a base64 key -- so a value containing a quote or a
// backslash would produce an exposition that fails to parse, taking every other
// metric on the page down with it. The three characters the format requires
// escaping are backslash, double quote and newline, in that order: escaping the
// backslash after the quote would double-escape the one just inserted.
func label(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return `"` + v + `"`
}
