package statistics

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
)

type errorProxy struct {
	netapi.Proxy
	err error
}

func (p errorProxy) Conn(context.Context, netapi.Address) (net.Conn, error) { return nil, p.err }

func TestConnectionStatisticsTrackLifecycle(t *testing.T) {
	remote, raw := pipe.Pipe()
	defer remote.Close()
	connections, conn := countedTestConn(t, raw)
	monitor := NewConnectionMonitor(connections)

	stats, err := monitor.Statistics(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Active != 1 || stats.ActiveTCP != 1 || stats.ActiveUDP != 0 || stats.Opened != 1 || stats.Closed != 0 {
		t.Fatalf("opened: %+v", stats)
	}
	if total := sumBuckets(stats.ConnectTime); total != 1 {
		t.Fatalf("connect time buckets = %d, want 1", total)
	}

	data := []byte("downloaded payload")
	go func() { _, _ = remote.Write(data) }()
	if _, err := io.ReadFull(conn, make([]byte, len(data))); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	connections.Proxy = errorProxy{err: &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}}
	if _, err := connections.Conn(netapi.WithContext(t.Context()), netapi.EmptyAddr); err == nil {
		t.Fatal("expected dial failure")
	}

	stats, err = monitor.Statistics(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Active != 0 || stats.Opened != 1 || stats.Closed != 1 || stats.Failed != 1 || stats.Download != uint64(len(data)) {
		t.Fatalf("final: %+v", stats)
	}
	if total := sumBuckets(stats.Lifetime); total != 1 {
		t.Fatalf("lifetime buckets = %d, want 1", total)
	}
	if len(stats.Failures) != 1 || stats.Failures[0] != (contractconnection.FailureKind{Kind: "refused", Count: 1}) {
		t.Fatalf("failures: %+v", stats.Failures)
	}
	h := stats.History
	if len(h.Opened) != statsHistorySlots || sum(h.Opened) != 1 || sum(h.Closed) != 1 || sum(h.Failed) != 1 || sum(h.Download) != uint64(len(data)) {
		t.Fatalf("history: opened=%d closed=%d failed=%d download=%d", sum(h.Opened), sum(h.Closed), sum(h.Failed), sum(h.Download))
	}
	if h.Active[len(h.Active)-1] < 1 {
		t.Fatalf("newest interval should report the peak of one active connection: %v", h.Active[len(h.Active)-5:])
	}

	if err := monitor.ResetStatistics(t.Context()); err != nil {
		t.Fatal(err)
	}
	stats, _ = monitor.Statistics(t.Context())
	if stats.Opened != 0 || stats.Closed != 0 || stats.Failed != 0 || stats.Download != 0 || len(stats.Failures) != 0 || sum(stats.History.Opened) != 0 {
		t.Fatalf("after reset: %+v", stats)
	}
	if summary := monitor.SessionSummary(); summary.Opened != "1" || summary.Failed != "1" {
		t.Fatalf("reset must not touch the session summary: %+v", summary)
	}
}

func TestSessionStatisticsSpreadTrafficAcrossQuietIntervals(t *testing.T) {
	cache := newSQLiteTotalCache(nil, nil)
	defer cache.Close()
	start := time.Unix(1_700_000_000, 0)
	s := newSessionStatistics(cache, start)
	s.connOpened(5*time.Millisecond, start)
	cache.AddDownload(1000)
	cache.AddUpload(100)
	// Ten quiet intervals later, the snapshot spreads the bytes evenly.
	now := start.Add(10 * statsHistoryInterval)
	stats := s.snapshot(1, 0, now)
	tail := stats.History.Download[statsHistorySlots-10:]
	for i, value := range tail {
		if value != 100 {
			t.Fatalf("download[%d] = %d, want 100 (%v)", i, value, tail)
		}
	}
	if got := sum(stats.History.Upload); got != 100 {
		t.Fatalf("upload = %d, want 100", got)
	}
	for i, value := range stats.History.Active[statsHistorySlots-11:] {
		if value != 1 {
			t.Fatalf("active[%d] = %d, want the carried gauge 1", i, value)
		}
	}
	if stats.Download != 1000 || stats.Upload != 100 {
		t.Fatalf("totals: %+v", stats)
	}
}

func TestClassifyFailure(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{&net.OpError{Op: "block", Err: errors.New("rule")}, "blocked"},
		{fmt.Errorf("dial: %w", context.Canceled), "canceled"},
		{fmt.Errorf("dial: %w", context.DeadlineExceeded), "timeout"},
		{os.ErrDeadlineExceeded, "timeout"},
		{&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}, "refused"},
		{syscall.ECONNRESET, "reset"},
		{syscall.EHOSTUNREACH, "unreachable"},
		{fmt.Errorf("lookup: %w", &net.DNSError{Err: "no such host", Name: "example.invalid"}), "dns"},
		{errors.New("boom"), "other"},
	} {
		if got := failureKindNames[classifyFailure(tc.err)]; got != tc.want {
			t.Errorf("classifyFailure(%v) = %s, want %s", tc.err, got, tc.want)
		}
	}
}

func sum(values []uint64) (total uint64) {
	for _, v := range values {
		total += v
	}
	return total
}

func sumBuckets(buckets []contractconnection.StatisticsBucket) (total uint64) {
	for _, b := range buckets {
		total += b.Count
	}
	return total
}
