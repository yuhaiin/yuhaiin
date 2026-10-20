package nat

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
)

func TestRetiredSourceReleasesSessionWithoutExternalClose(t *testing.T) {
	budget := trafficcontrol.NewGovernor(trafficcontrol.Limits{MaxSessions: 1}, nil)
	lease, ok := budget.AcquireSession()
	if !ok {
		t.Fatal("acquire session")
	}
	source := newSourceChan(nil, nil, lease, budget, nil)
	t.Cleanup(func() { _ = source.Close() })
	old := time.Now().Add(-time.Hour)
	source.loopStopTime.Store(&old)
	if !source.retireIdle(time.Second) {
		t.Fatal("source did not retire")
	}
	awaitClosed(t, source.done)
	if got := budget.Snapshot().Sessions; got != 0 {
		t.Fatalf("retired worker retained %d sessions", got)
	}
}

func TestRetiredSourceRetryReusesSessionCapacity(t *testing.T) {
	dialer := lifecycleDialer{dial: func(ctx context.Context) (net.PacketConn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	table := NewTable(nil, dialer)
	table.budget = trafficcontrol.NewGovernor(trafficcontrol.Limits{MaxSessions: 1}, nil)
	t.Cleanup(func() { _ = table.Close() })
	lease, ok := table.budget.AcquireSession()
	if !ok {
		t.Fatal("acquire session")
	}
	source := newSourceChan(nil, dialer, lease, table.budget, nil)
	t.Cleanup(func() { _ = source.Close() })
	pkt := resourcePacket(t, 31001)
	defer pkt.DecRef()
	pkt.MigrateID = 123
	table.sourceControl.Store(pkt.MigrateID, source)
	old := time.Now().Add(-time.Hour)
	source.loopStopTime.Store(&old)
	if !source.retireIdle(time.Second) {
		t.Fatal("source did not retire")
	}
	if err := table.Write(t.Context(), pkt); err != nil {
		t.Fatalf("retry retained retired session quota: %v", err)
	}
	if table.sourceControl.CompareAndDelete(pkt.MigrateID, source) {
		t.Fatal("old source replaced new mapping")
	}
	_ = table.Close()
	if got := table.ResourceStats().Sessions; got != 0 {
		t.Fatalf("shutdown retained %d sessions", got)
	}
}
