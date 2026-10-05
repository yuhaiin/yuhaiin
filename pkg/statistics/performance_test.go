package statistics

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
)

type performanceConnection uint64

func (c performanceConnection) ID() uint64 { return uint64(c) }
func (performanceConnection) Close() error { return nil }

func performanceInfo(id uint64) contractconnection.Connection {
	return contractconnection.Connection{ID: formatUint64(id), Addr: "example.com:443", Process: "browser", Source: "127.0.0.1:12345", NodeName: "proxy", Network: contractconnection.NetworkType{ConnType: "tcp"}}
}

func BenchmarkPersistConnection(b *testing.B) {
	c := NewSQLiteConnStore(filepath.Join(b.TempDir(), "state.db"), nil)
	defer c.Close()
	info := performanceInfo(1)
	b.ReportAllocs()
	for b.Loop() {
		c.storeConnection(performanceConnection(1), info)
	}
}

func BenchmarkAllInfos(b *testing.B) {
	for _, size := range []int{10, 100} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			c := NewSQLiteConnStore(filepath.Join(b.TempDir(), "state.db"), nil)
			defer c.Close()
			for id := uint64(1); id <= uint64(size); id++ {
				c.storeConnection(performanceConnection(id), performanceInfo(id))
			}
			b.ReportAllocs()
			for b.Loop() {
				if len(c.allInfos()) != size {
					b.Fatal("missing connection metadata")
				}
			}
		})
	}
}

func TestAllInfosReadsCurrentPersistedData(t *testing.T) {
	c := NewSQLiteConnStore(filepath.Join(t.TempDir(), "state.db"), nil)
	defer c.Close()
	c.storeConnection(performanceConnection(1), performanceInfo(1))
	// Runtime membership remains authoritative, including metadata write
	// failures. Persisted rows for untracked connections must not be exposed.
	c.connStore.Store(2, performanceConnection(2))
	c.infoStore.Store(3, performanceInfo(3))
	info := performanceInfo(1)
	info.Addr = "updated.example:443"
	data, err := encodeStatisticJSON(info)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.sqliteDB.ExecContext(context.Background(), "UPDATE connection_sessions SET summary_json=? WHERE id=1", data); err != nil {
		t.Fatal(err)
	}
	infos := c.allInfos()
	if len(infos) != 2 {
		t.Fatalf("infos=%+v", infos)
	}
	for _, info := range infos {
		switch info.ID {
		case "1":
			if info.Addr != "updated.example:443" {
				t.Fatal("metadata cached stale SQLite state")
			}
		case "2":
			if info.Addr != "" {
				t.Fatal("missing metadata did not return ID-only fallback")
			}
		default:
			t.Fatalf("unexpected connection ID %s", info.ID)
		}
	}
}

func TestSQLiteConnectionRecordIsAtomic(t *testing.T) {
	c := NewSQLiteConnStore(filepath.Join(t.TempDir(), "state.db"), nil)
	defer c.Close()
	if _, err := c.sqliteDB.Exec(`CREATE TRIGGER fail_history BEFORE INSERT ON connection_history BEGIN SELECT RAISE(ABORT, 'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	s := c.infoStore.(*sqliteInfoStore)
	h := c.history.(*SQLiteHistory)
	info := performanceInfo(1)
	if err := storeSQLiteConnection(s, h, 1, info); err == nil {
		t.Fatal("failed history write accepted")
	}
	var count int
	if err := c.sqliteDB.QueryRow(`SELECT COUNT(*) FROM connection_sessions`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("session persisted despite failed history write")
	}
	if _, err := c.sqliteDB.Exec(`DROP TRIGGER fail_history`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := storeSQLiteConnection(s, h, 1, info); err != nil {
			t.Fatal(err)
		}
	}
	var session, history string
	if err := c.sqliteDB.QueryRow(`SELECT summary_json FROM connection_sessions WHERE id=1`).Scan(&session); err != nil {
		t.Fatal(err)
	}
	if err := c.sqliteDB.QueryRow(`SELECT last_connection_json,hit_count FROM connection_history`).Scan(&history, &count); err != nil {
		t.Fatal(err)
	}
	if session != history || count != 2 {
		t.Fatalf("session/history mismatch or lost hit count: %d", count)
	}
}

// Include counter collection, aggregation and the real SQLite transaction.
func BenchmarkTelemetryFlush(b *testing.B) {
	for _, size := range []int{100, 1000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			c := NewSQLiteConnStore(filepath.Join(b.TempDir(), "telemetry.db"), nil)
			defer c.Close()
			counters := make([]*dimensionCounter, size)
			for i := range counters {
				info := performanceInfo(uint64(i + 1))
				info.Addr = fmt.Sprintf("site-%d.example:443", i%10)
				counters[i] = c.telemetry.Register(info)
			}
			// Warm dimension IDs and statement paths before the measured flushes.
			for _, counter := range counters {
				counter.upload.Add(101)
				counter.download.Add(203)
			}
			c.telemetry.flush()
			b.ReportAllocs()
			for b.Loop() {
				for _, counter := range counters {
					counter.upload.Add(101)
					counter.download.Add(203)
				}
				c.telemetry.flush()
			}
		})
	}
}

func TestTelemetryFlushRetriesRolledBackTraffic(t *testing.T) {
	c := NewSQLiteConnStore(filepath.Join(t.TempDir(), "telemetry.db"), nil)
	defer c.Close()
	if _, err := c.sqliteDB.Exec(`CREATE TRIGGER fail_traffic BEFORE INSERT ON traffic_dimension_hourly BEGIN SELECT RAISE(ABORT, 'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	counter := c.telemetry.Register(performanceInfo(1))
	counter.upload.Add(101)
	counter.download.Add(203)
	c.telemetry.Remove(counter)
	c.telemetry.flush()
	var values int
	if err := c.sqliteDB.QueryRow(`SELECT COUNT(*) FROM telemetry_dimension_values`).Scan(&values); err != nil {
		t.Fatal(err)
	}
	if values != 0 {
		t.Fatal("failed traffic did not roll back values")
	}
	if _, err := c.sqliteDB.Exec(`DROP TRIGGER fail_traffic`); err != nil {
		t.Fatal(err)
	}
	// The removed connection's delta must survive both rollback and collection.
	c.telemetry.flush()
	var upload, download int
	if err := c.sqliteDB.QueryRow(`SELECT COALESCE(SUM(upload_bytes),0),COALESCE(SUM(download_bytes),0) FROM traffic_dimension_hourly t JOIN telemetry_dimension_values v ON v.id=t.value_id WHERE v.dimension='protocol'`).Scan(&upload, &download); err != nil {
		t.Fatal(err)
	}
	if upload != 101 || download != 203 {
		t.Fatalf("retry traffic=%d/%d", upload, download)
	}
	c.telemetry.flush()
	var again int
	if err := c.sqliteDB.QueryRow(`SELECT SUM(upload_bytes) FROM traffic_dimension_hourly t JOIN telemetry_dimension_values v ON v.id=t.value_id WHERE v.dimension='protocol'`).Scan(&again); err != nil {
		t.Fatal(err)
	}
	if again != 101 {
		t.Fatal("retry counted traffic twice")
	}
}

func TestTelemetryFailureDoesNotCacheRolledBackValueIDs(t *testing.T) {
	c := NewSQLiteConnStore(filepath.Join(t.TempDir(), "failure.db"), nil)
	defer c.Close()
	dimension := telemetryDimension{kind: "protocol", value: "new-protocol"}
	counts := map[failureBucket]uint64{{dimension: dimension, hour: time.Now().UTC().Truncate(time.Hour).Unix()}: 1}
	if _, err := c.sqliteDB.Exec(`CREATE TRIGGER fail_dimension BEFORE INSERT ON failure_dimension_hourly BEGIN SELECT RAISE(ABORT, 'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := persistFailureCounts(context.Background(), c.sqliteDB, c.telemetry.valueIDs, counts); err == nil {
		t.Fatal("failure accepted")
	}
	if _, cached := c.telemetry.valueIDs.Load(dimension); cached {
		t.Fatal("cached ID from a rolled-back transaction")
	}
	if _, err := c.sqliteDB.Exec(`DROP TRIGGER fail_dimension`); err != nil {
		t.Fatal(err)
	}
	if _, err := c.sqliteDB.Exec(`INSERT INTO telemetry_dimension_values(dimension,value) VALUES ('protocol','other')`); err != nil {
		t.Fatal(err)
	}
	if err := persistFailureCounts(context.Background(), c.sqliteDB, c.telemetry.valueIDs, counts); err != nil {
		t.Fatal(err)
	}
	var failures int
	if err := c.sqliteDB.QueryRow(`SELECT failed_count FROM failure_dimension_hourly f JOIN telemetry_dimension_values v ON v.id=f.value_id WHERE v.value='new-protocol'`).Scan(&failures); err != nil {
		t.Fatal(err)
	}
	if failures != 1 {
		t.Fatalf("failure count=%d", failures)
	}
}

func TestConcurrentTelemetryFlushDoesNotLoseTraffic(t *testing.T) {
	c := NewSQLiteConnStore(filepath.Join(t.TempDir(), "concurrent.db"), nil)
	defer c.Close()
	counter := c.telemetry.Register(performanceInfo(1))
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 1000 {
				counter.upload.Add(1)
				counter.download.Add(2)
			}
		})
	}
	for range 4 {
		wg.Go(func() {
			for range 4 {
				c.telemetry.flush()
			}
		})
	}
	wg.Wait()
	c.telemetry.Remove(counter)
	c.telemetry.flush()
	var upload, download int
	if err := c.sqliteDB.QueryRow(`SELECT SUM(upload_bytes),SUM(download_bytes) FROM traffic_dimension_hourly t JOIN telemetry_dimension_values v ON v.id=t.value_id WHERE v.dimension='protocol'`).Scan(&upload, &download); err != nil {
		t.Fatal(err)
	}
	if upload != 4000 || download != 8000 {
		t.Fatalf("traffic=%d/%d", upload, download)
	}
}

func TestMemoryTelemetryDoesNotRetainConnections(t *testing.T) {
	recorder := newTelemetryRecorder(nil)
	defer recorder.Close()
	counter := recorder.Register(performanceInfo(1))
	counter.upload.Add(1)
	recorder.Remove(counter)
	recorder.flush()
	recorder.counters.Range(func(_ *dimensionCounter, _ struct{}) bool {
		t.Error("memory store retained a telemetry connection without persistence")
		return false
	})
}
