package statistics

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
)

type failingSummaryProxy struct{ netapi.Proxy }

func (failingSummaryProxy) Conn(context.Context, netapi.Address) (net.Conn, error) {
	return nil, errors.New("test dial failure")
}

func TestSessionSummaryTracksTrafficCloseAndFailures(t *testing.T) {
	remote, raw := pipe.Pipe()
	defer remote.Close()
	connections, conn := countedTestConn(t, raw)
	monitor := NewConnectionMonitor(connections)
	before := monitor.SessionSummary()
	if before.Active != 1 || before.Opened != "1" || before.Failed != "0" {
		t.Fatalf("new session: %+v", before)
	}
	data := []byte("downloaded payload")
	sent := make(chan error, 1)
	go func() { _, err := remote.Write(data); sent <- err }()
	if _, err := io.ReadFull(conn, make([]byte, len(data))); err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	summary := monitor.SessionSummary()
	if summary.Download != "18" || summary.TotalDownload != "18" {
		t.Fatalf("traffic summary: %+v", summary)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	connections.Proxy = failingSummaryProxy{}
	if _, err := connections.Conn(netapi.WithContext(t.Context()), netapi.EmptyAddr); err == nil {
		t.Fatal("expected dial failure")
	}
	summary = monitor.SessionSummary()
	if summary.Active != 0 || summary.Opened != "1" || summary.Failed != "1" || summary.Download != "18" {
		t.Fatalf("final summary: %+v", summary)
	}
}
