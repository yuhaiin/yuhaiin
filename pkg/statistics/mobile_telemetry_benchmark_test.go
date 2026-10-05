package statistics

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func BenchmarkMobileFailureBurst(b *testing.B) {
	c := NewSQLiteConnStore(b.TempDir()+"/state.db", nil)
	defer c.Close()
	if c.sqliteDB == nil {
		b.Fatal("SQLite store unavailable")
	}
	ctx := netapi.WithContext(context.Background())
	addr, err := netapi.ParseAddressPort("tcp", "example.com", 443)
	if err != nil {
		b.Fatal(err)
	}
	failure := errors.New("dial failed")
	info := performanceInfo(1)
	from, to := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	b.ReportAllocs()
	for b.Loop() {
		for range 32 {
			c.faildHistory.Push(ctx, failure, "tcp", addr)
			c.telemetry.RecordFailure(info)
		}
		c.faildHistory.Get()
		if _, err := c.Telemetry(ctx, from, to, 8); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*32), "ns/failure")
	var count uint64
	if err := c.sqliteDB.QueryRow(`SELECT SUM(failed_count) FROM failure_dimension_hourly f JOIN telemetry_dimension_values v ON f.value_id=v.id WHERE v.dimension='protocol'`).Scan(&count); err != nil {
		b.Fatal(err)
	}
	if count != uint64(b.N*32) {
		b.Fatalf("persisted failures=%d, want %d", count, b.N*32)
	}
}

var benchmarkFlowTotals [2]uint64

func BenchmarkMobileNotificationTotals(b *testing.B) {
	c := NewSQLiteConnStore(b.TempDir()+"/state.db", nil)
	defer c.Close()
	if c.sqliteDB == nil {
		b.Fatal("SQLite store unavailable")
	}
	c.Cache.AddDownload(123)
	c.Cache.AddUpload(456)
	for id := uint64(1); id <= 100; id++ {
		c.counters.Store(id, newCounter(c.Cache, nil))
	}
	m := NewConnectionMonitor(c)
	read := func() (uint64, uint64) {
		flow, err := m.Total(context.Background())
		if err != nil {
			b.Fatal(err)
		}
		download, _ := strconv.ParseUint(flow.Download, 10, 64)
		upload, _ := strconv.ParseUint(flow.Upload, 10, 64)
		return download, upload
	}
	if totals, ok := any(m).(interface{ FlowTotals() (uint64, uint64) }); ok {
		read = totals.FlowTotals
	}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkFlowTotals[0], benchmarkFlowTotals[1] = read()
	}
	if benchmarkFlowTotals != [2]uint64{123, 456} {
		b.Fatal("incorrect notification totals")
	}
}
