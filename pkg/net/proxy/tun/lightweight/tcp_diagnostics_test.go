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
