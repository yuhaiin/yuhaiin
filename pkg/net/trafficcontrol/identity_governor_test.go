package trafficcontrol

import (
	"math"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
)

func TestIdentitySessionIsolationUpdatesAndRelease(t *testing.T) {
	limits := resource.Limits{MaxTCPSessions: 1, MaxUDPSessions: 2, MaxSessions: 3, ConnectionsPerSecond: 0.001, ConnectionBurst: 3}
	alice, err := NewIdentityGovernor(limits)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewIdentityGovernor(limits)
	if err != nil {
		t.Fatal(err)
	}
	tcp, ok := alice.AcquireTCP()
	if !ok {
		t.Fatal("first TCP rejected")
	}
	for range 100 {
		if lease, ok := alice.AcquireTCP(); ok {
			lease.Release()
			t.Fatal("TCP cap bypassed")
		}
	}
	if reason := alice.Snapshot().LastRejection; reason != "tcp_limit" {
		t.Fatalf("wrong rejection reason: %s", reason)
	}
	udp, ok := alice.AcquireUDP()
	if !ok {
		t.Fatal("rejected TCP attempts consumed UDP CPS")
	}
	other, ok := bob.AcquireTCP()
	if !ok {
		t.Fatal("Alice consumed Bob's budget")
	}
	other.Release()
	limits.MaxSessions = 1
	if err := alice.UpdateLimits(limits); err != nil {
		t.Fatal(err)
	}
	if s := alice.Snapshot(); s.Total.Sessions != 2 {
		t.Fatalf("update reset live leases: %+v", s)
	}
	if lease, ok := alice.AcquireUDP(); ok {
		lease.Release()
		t.Fatal("lowered total cap ignored")
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() { tcp.Release(); udp.Release() })
	}
	wg.Wait()
	if s := alice.Snapshot(); s.Total.Sessions != 0 || s.TCP.Sessions != 0 || s.UDP.Sessions != 0 {
		t.Fatalf("double release: %+v", s)
	}
	last, ok := alice.AcquireTCP()
	if !ok {
		t.Fatal("remaining earned creation token lost")
	}
	last.Release()
	if err := alice.UpdateLimits(limits); err != nil {
		t.Fatal(err)
	}
	if lease, ok := alice.AcquireTCP(); ok {
		lease.Release()
		t.Fatal("unchanged policy minted fresh CPS burst")
	}
}

func TestGovernorConcurrentUpdateAndAdmission(t *testing.T) {
	g := NewGovernor(Limits{MaxSessions: 10, SessionsPerSec: 10000, SessionBurst: 100, PacketsPerSec: 10000, PacketBurst: 100}, nil)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 500 {
				lease, ok := g.AcquireSession()
				if ok {
					lease.Release()
				}
				g.AdmitPacket(time.Now())
			}
		})
	}
	wg.Go(func() {
		for range 100 {
			if err := g.UpdateLimits(Limits{MaxSessions: 5, SessionsPerSec: 5000, SessionBurst: 50, PacketsPerSec: 5000, PacketBurst: 50}); err != nil {
				t.Error(err)
			}
		}
	})
	wg.Wait()
	if g.Snapshot().Sessions != 0 {
		t.Fatal("live sessions leaked")
	}
	if err := g.UpdateLimits(Limits{SessionsPerSec: math.NaN()}); err == nil {
		t.Fatal("invalid rate published")
	}
	if err := g.UpdateLimits(Limits{PacketBurst: math.Inf(1)}); err == nil {
		t.Fatal("infinite burst published")
	}
}

func TestEnablingAnAdmissionRateStartsOneBudgetWithoutRepeatedRefills(t *testing.T) {
	g := NewGovernor(Limits{}, nil)
	limits := Limits{SessionsPerSec: 0.001}
	if err := g.UpdateLimits(limits); err != nil {
		t.Fatal(err)
	}
	lease, ok := g.AcquireSession()
	if !ok {
		t.Fatal("newly enabled CPS budget had no initial whole-event burst")
	}
	lease.Release()
	if err := g.UpdateLimits(limits); err != nil {
		t.Fatal(err)
	}
	if other, ok := g.AcquireSession(); ok {
		other.Release()
		t.Fatal("unchanged update refilled the CPS burst")
	}
}
