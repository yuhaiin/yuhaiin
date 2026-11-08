package node

import (
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

// unchangedSince lets flush skip the snapshot; it must agree with equal().
func TestNodeCountersUnchangedSinceMatchesSnapshot(t *testing.T) {
	n := new(nodeCounters)
	now := time.Now()
	n.mu.Lock()
	n.tcpHealth = contract.ChannelHealth{Sequence: 1, State: "healthy", ConsecutiveSuccesses: 1,
		Samples: []contract.HealthSample{{Sequence: 1, At: now.UnixMilli(), OK: true, Kind: "dial"}}}
	n.mu.Unlock()
	n.upload.Store(10)

	saved := n.snapshot()
	check := func(want bool, why string) {
		t.Helper()
		v := n.snapshot()
		if got := n.unchangedSince(&saved, n.upload.Load(), n.download.Load(), time.Now()); got != want || got != saved.equal(&v) {
			t.Fatalf("%s: unchangedSince=%v equal=%v want %v", why, got, saved.equal(&v), want)
		}
	}
	check(true, "idle")

	n.download.Add(1)
	check(false, "traffic")
	saved = n.snapshot()

	n.probe("tcp", contract.LatencyResponse{OK: true}, nil)
	check(false, "probe")
	saved = n.snapshot()
	check(true, "after probe")

	// Health turns "unknown" once its newest sample ages out.
	n.mu.Lock()
	n.tcpHealth.Samples[0].At = now.Add(-2 * recentNodeObservation).UnixMilli()
	n.mu.Unlock()
	saved.TCPHealth.Samples[0].At = n.tcpHealth.Samples[0].At
	check(false, "stale health")
}
