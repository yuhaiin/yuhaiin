package statistics

import (
	"testing"
	"time"
)

func TestFailureTelemetryBatchesAndRetries(t *testing.T) {
	c := NewSQLiteConnStore(t.TempDir()+"/state.db", nil)
	defer c.Close()
	for range 3 {
		c.telemetry.RecordFailure(performanceInfo(1))
	}
	var count int
	if err := c.sqliteDB.QueryRow(`SELECT COUNT(*) FROM failure_dimension_hourly`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("failure path committed instead of batching")
	}
	if _, err := c.sqliteDB.Exec(`CREATE TRIGGER fail_failure BEFORE INSERT ON failure_dimension_hourly BEGIN SELECT RAISE(ABORT, 'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	c.telemetry.flush()
	if !c.telemetry.hasPendingWork() {
		t.Fatal("failed batch was discarded")
	}
	if _, err := c.sqliteDB.Exec(`DROP TRIGGER fail_failure`); err != nil {
		t.Fatal(err)
	}
	c.telemetry.flush()
	c.telemetry.flush()
	if err := c.sqliteDB.QueryRow(`SELECT SUM(failed_count) FROM failure_dimension_hourly f JOIN telemetry_dimension_values v ON f.value_id=v.id WHERE v.dimension='protocol'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("failure count=%d, want 3", count)
	}
}

func TestFailureTelemetryRetryPreservesEventHour(t *testing.T) {
	c := NewSQLiteConnStore(t.TempDir()+"/state.db", nil)
	defer c.Close()
	hour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour).Unix()
	c.telemetry.flushMu.Lock()
	c.telemetry.pendingFailures = map[failureBucket]uint64{{dimension: telemetryDimension{kind: "protocol", value: "tcp"}, hour: hour}: 2}
	c.telemetry.flushMu.Unlock()
	c.telemetry.flush()
	var got int64
	if err := c.sqliteDB.QueryRow(`SELECT bucket_start_utc FROM failure_dimension_hourly`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != hour {
		t.Fatalf("event hour=%d, want %d", got, hour)
	}
}

func TestFlowTotalsMatchesMonitorTotals(t *testing.T) {
	c := NewSQLiteConnStore(t.TempDir()+"/state.db", nil)
	defer c.Close()
	c.Cache.AddDownload(123)
	c.Cache.AddUpload(456)
	m := NewConnectionMonitor(c)
	download, upload := m.FlowTotals()
	flow, err := m.Total(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if formatUint64(download) != flow.Download || formatUint64(upload) != flow.Upload {
		t.Fatal("notification totals differ from monitor API")
	}
}
