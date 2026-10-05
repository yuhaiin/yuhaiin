package statistics

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
)

func TestNotifyCloseWithBlockedSend(t *testing.T) {
	n := newNotify()
	entered, release := make(chan struct{}), make(chan struct{})
	initial := make(chan struct{})
	var calls atomic.Int32
	s := contractNotifyStream{ctx: context.Background(), send: func(contractconnection.Event) error {
		call := calls.Add(1)
		if call == 1 {
			close(initial)
		}
		if call == 2 {
			close(entered)
			<-release
		}
		return nil
	}}
	c := &Connections{notify: n, infoStore: &sqliteInfoStore{}}
	notifyDone := make(chan struct{})
	go func() { _ = c.Notify(s); close(notifyDone) }()
	select {
	case <-initial:
	case <-time.After(time.Second):
		t.Fatal("initial snapshot not sent")
	}
	n.pubNewConn(performanceInfo(1))
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("send not reached")
	}
	done := make(chan struct{})
	go func() { n.Close(); close(done) }()
	defer func() { close(release); <-done; <-notifyDone }()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Close waits indefinitely for a blocked stream Send before canceling subscribers")
	}
}

func TestNotifySkipsWorkWithoutSubscribers(t *testing.T) {
	n := newNotify()
	defer n.Close()
	n.pubNewConn(performanceInfo(1))
	n.pubRemoveConn(1)
	if len(n.notifyTrigger) != 0 || len(n.notifyStore.dump()) != 0 {
		t.Fatal("connection without subscribers queued notification work")
	}
}

type snapshotInfoStore struct {
	InfoCache
	onLoad func()
}

func (s snapshotInfoStore) Load(id uint64) (contractconnection.Connection, bool) {
	s.onLoad()
	return performanceInfo(id), true
}

func TestNotifyRemovalDuringInitialSnapshotIsDelivered(t *testing.T) {
	n := newNotify()
	defer n.Close()
	c := &Connections{notify: n, counters: newCounters(), history: newSQLiteHistory(nil)}
	c.infoStore = snapshotInfoStore{InfoCache: &sqliteInfoStore{}, onLoad: func() { n.pubNewConn(performanceInfo(1)) }}
	c.storeConnection(performanceConnection(1), performanceInfo(1))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	removed, done := make(chan struct{}), make(chan struct{})
	s := contractNotifyStream{ctx: ctx, send: func(event contractconnection.Event) error {
		if event.Type == "connections_added" {
			c.Remove(1)
		}
		if event.Type == "connections_removed" {
			close(removed)
			cancel()
		}
		return nil
	}}
	go func() { _ = c.Notify(s); close(done) }()
	select {
	case <-removed:
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("snapshot retained a closed pending connection")
	}
	<-done
}

func TestNotifySlowSubscriberDoesNotBlockOthers(t *testing.T) {
	n := newNotify()
	defer n.Close()
	s := contractNotifyStream{ctx: context.Background(), send: func(contractconnection.Event) error { return nil }}
	slowID, slow := n.register(s)
	defer n.unregister(slowID)
	fastID, fast := n.register(s)
	defer n.unregister(fastID)
	fastEntry, _ := n.notifier.Load(fastID)
	for id := uint64(1); id <= 17; id++ {
		n.notifyStore.push(performanceInfo(id))
		n.send()
		select {
		case <-fastEntry.events:
		default:
			t.Fatal("fast subscriber missed event")
		}
	}
	if slow.Err() == nil {
		t.Fatal("full subscriber queue was not canceled")
	}
	if fast.Err() != nil {
		t.Fatal("fast subscriber canceled")
	}
}

func TestFailureOnlySchedulesMaintenance(t *testing.T) {
	c := NewSQLiteConnStore(t.TempDir()+"/state.db", nil)
	defer c.Close()
	c.telemetry.RecordFailure(performanceInfo(1))
	deadline := time.NewTimer(telemetryFlushInterval + 200*time.Millisecond)
	defer deadline.Stop()
	<-deadline.C
	c.telemetry.maintenanceMu.Lock()
	last := c.telemetry.lastMaintenance
	c.telemetry.maintenanceMu.Unlock()
	if last.IsZero() {
		t.Fatal("failure telemetry persists data but never schedules hourly retention maintenance")
	}
}
