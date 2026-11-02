package lightweight

import (
	"testing"
	"testing/synctest"
)

func TestTCPDiagnosticSnapshot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, c, _, _ := passiveWire(t, 100, 10000, "bbr")
		snapshot := c.DiagnosticSnapshot()
		if snapshot.State != Established || snapshot.CongestionWindow == 0 ||
			snapshot.RTOMilliseconds <= 0 || snapshot.BBR == nil ||
			snapshot.Local == "" || snapshot.Remote == "" {
			t.Fatalf("incomplete TCP diagnostic snapshot: %+v", snapshot)
		}
	})
}

func TestStackDiagnosticSnapshotBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, c, _, _ := passiveWire(t, 100, 10000, "bbr")
		one := s.DiagnosticSnapshot(1)
		if one.MTU == 0 || one.Stats.Connections != 1 || len(one.Flows) != 1 {
			t.Fatalf("unexpected stack snapshot: %+v", one)
		}
		if one.Flows[0].Local == "" || one.Flows[0].CongestionWindow == 0 {
			t.Fatalf("missing flow snapshot: %+v", one.Flows[0])
		}
		if zero := s.DiagnosticSnapshot(0); len(zero.Flows) != 0 || zero.Stats.Connections != 1 {
			t.Fatalf("zero-limit snapshot should retain totals: %+v", zero)
		}
		_ = c.Close()
	})
}
