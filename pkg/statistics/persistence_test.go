package statistics

import (
	"errors"
	"testing"
	"time"

	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"

	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestPendingMetadataSurvivesConcurrentCommit(t *testing.T) {
	store, err := storagesqlite.Open(t.Context(), t.TempDir()+"/state.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s, h := newSQLiteInfoStore(store.DB()), newSQLiteHistory(store.DB())
	defer s.Close()
	defer h.Close()
	p := newConnectionPersistence(store.DB(), s, h)
	// Stop the worker so the allInfos read/commit/overlay interleaving is deterministic.
	close(p.stop)
	<-p.done
	p.Store(1, performanceInfo(1))
	ids := []uint64{1}
	infos := p.loadMany(ids, func(ids []uint64) []contractconnection.Connection {
		infos := s.loadMany(ids)
		if err := p.flush(); err != nil {
			t.Fatal(err)
		}
		return infos
	})
	if infos[0].Addr != performanceInfo(1).Addr {
		t.Fatalf("metadata lost between database snapshot and overlay: %+v", infos[0])
	}
}

func TestFailureRetryRetainsNewestError(t *testing.T) {
	key := failedHistoryKey{protocol: "tcp", host: "example.com:443"}
	h := &SQLiteFailedHistory{pending: map[failedHistoryKey]failedHistoryPending{
		key: {count: 1, lastSeen: 123, lastErr: "newer error"},
	}}
	h.requeue(map[failedHistoryKey]failedHistoryPending{
		key: {count: 1, lastSeen: 123, lastErr: "older error"},
	})
	if h.pending[key].lastErr != "newer error" {
		t.Fatalf("same-second retry replaced newest error with %q", h.pending[key].lastErr)
	}
}

func TestConnectionHistoryAggregatesAndRetries(t *testing.T) {
	c := NewSQLiteConnStore(t.TempDir()+"/state.db", nil)
	defer c.Close()
	for id := uint64(1); id <= 3; id++ {
		c.storeConnection(performanceConnection(id), performanceInfo(id))
		c.Remove(id)
	}
	if _, err := c.sqliteDB.Exec(`CREATE TRIGGER fail_history BEFORE INSERT ON connection_history BEGIN SELECT RAISE(ABORT, 'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := c.persistence.flush(); err == nil {
		t.Fatal("failed batch accepted")
	}
	c.storeConnection(performanceConnection(4), performanceInfo(4))
	c.Remove(4)
	c.persistence.mu.Lock()
	entries := len(c.persistence.historyQ)
	c.persistence.mu.Unlock()
	if entries != 1 {
		t.Fatal("duplicate histories were not aggregated")
	}
	if _, err := c.sqliteDB.Exec(`DROP TRIGGER fail_history`); err != nil {
		t.Fatal(err)
	}
	if err := c.persistence.flush(); err != nil {
		t.Fatal(err)
	}
	if err := c.persistence.flush(); err != nil {
		t.Fatal(err)
	}
	history := c.history.Get()
	if len(history.Items) != 1 || history.Items[0].Count != "4" || history.Items[0].Connection.ID != "4" {
		t.Fatalf("lost count or replaced newest metadata: %+v", history)
	}
}

func TestBatchRetryCannotBeBypassedByNewEvents(t *testing.T) {
	stop, trigger, done := make(chan struct{}), make(chan struct{}, 1), make(chan struct{})
	attempts := make(chan struct{}, 10)
	go runPersistenceWorker(stop, trigger, done, time.Millisecond, func() bool { return true }, func() error {
		attempts <- struct{}{}
		return errors.New("database unavailable")
	}, "test")
	defer func() { close(stop); <-done }()
	trigger <- struct{}{}
	select {
	case <-attempts:
	case <-time.After(time.Second):
		t.Fatal("initial batch not attempted")
	}
	for range 100 {
		select {
		case trigger <- struct{}{}:
		default:
		}
	}
	select {
	case <-attempts:
		t.Fatal("new events bypassed retry backoff")
	case <-time.After(100 * time.Millisecond):
	}
	select {
	case <-attempts:
	case <-time.After(2 * time.Second):
		t.Fatal("failed batch not retried")
	}
	select {
	case <-attempts:
		t.Fatal("repeated failure retried without exponential backoff")
	case <-time.After(1100 * time.Millisecond):
	}
}
