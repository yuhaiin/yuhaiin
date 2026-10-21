package node

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/apernet/quic-go"
)

type observedTestProxy struct {
	netapi.EmptyDispatch
	connect func() (net.Conn, error)
	packet  func() (net.PacketConn, error)
}

func (p observedTestProxy) Conn(context.Context, netapi.Address) (net.Conn, error) {
	return p.connect()
}
func (p observedTestProxy) PacketConn(context.Context, netapi.Address) (net.PacketConn, error) {
	if p.packet == nil {
		return nil, errors.New("udp disabled")
	}
	return p.packet()
}
func (observedTestProxy) Ping(context.Context, netapi.Address) (uint64, error) { return 1, nil }
func (observedTestProxy) Close() error                                         { return nil }

func TestObservedNodeTCPTrafficAndActiveSession(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	c := new(nodeCounters)
	proxy := &observedProxy{Proxy: observedTestProxy{connect: func() (net.Conn, error) { return a, nil }}, c: c}
	conn, err := proxy.Conn(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 4)
		_, err := io.ReadFull(conn, buffer)
		if err == nil && string(buffer) != "pong" {
			err = errors.New("unexpected payload")
		}
		readDone <- err
	}()
	if _, err = b.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	if err = <-readDone; err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() { _, err := conn.Write([]byte("ping")); writeDone <- err }()
	buffer := make([]byte, 4)
	if _, err := io.ReadFull(b, buffer); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if got := c.snapshot(); got.UploadBytes != 4 || got.DownloadBytes != 4 || got.TCPConnections != 1 {
		t.Fatalf("counters: %+v", got)
	}
	if c.activeTCP.Load() != 1 {
		t.Fatal("active session missing")
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if c.activeTCP.Load() != 0 {
		t.Fatal("close double-counted")
	}
}

func TestObservedNodeFailedDialAndProbe(t *testing.T) {
	c := new(nodeCounters)
	proxy := &observedProxy{Proxy: observedTestProxy{connect: func() (net.Conn, error) { return nil, errors.New("unreachable") }}, c: c}
	if _, err := proxy.Conn(context.Background(), nil); err == nil {
		t.Fatal("dial success unexpected")
	}
	c.probe("tcp", contract.LatencyResponse{}, errors.New("HTTP probe refused"))
	s := c.status("n1")
	if s.Failures != "1" || s.TCPAttempts != "1" || s.Probes["tcp"].Result.Error == "" || s.LastError == "" {
		t.Fatalf("failed status: %+v", s)
	}
}

func TestNodeObserverRestoreAndDeletion(t *testing.T) {
	r := newTestRuntime(t)
	ctx := t.Context()
	node := testNode(t, "metrics-node", "Metrics Node")
	if _, err := r.Save(ctx, node); err != nil {
		t.Fatal(err)
	}
	_, err := r.openNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c := r.observer.counter(node.ID)
	c.upload.Add(1234)
	c.udpSent.Add(17)
	c.tcpConnected.Add(5)
	c.probe("tcp", contract.LatencyResponse{OK: true, LatencyMS: 23}, nil)
	if err = r.observer.flush(ctx); err != nil {
		t.Fatal(err)
	}
	original := r.observer.status(node.ID)
	if original.UploadBytes != "1234" || original.Probes["tcp"].Result.LatencyMS != 23 {
		t.Fatalf("snapshot: %+v", original)
	}
	path := r.path
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	restarted := NewNodeRuntime(path)
	defer restarted.Close()
	statuses, err := restarted.Statuses(ctx, []string{node.ID})
	if err != nil || len(statuses) != 1 {
		t.Fatalf("restart: %+v %v", statuses, err)
	}
	if statuses[0].UploadBytes != "1234" || statuses[0].UDPSentPackets != "17" || statuses[0].TCPConnections != "5" ||
		statuses[0].Probes["tcp"].Result.LatencyMS != 23 {
		t.Fatalf("restore failed: %+v", statuses[0])
	}
	if err = restarted.Remove(ctx, node.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.Save(ctx, node); err != nil {
		t.Fatal(err)
	}
	statuses, err = restarted.Statuses(ctx, []string{node.ID})
	if err != nil || len(statuses) != 1 || statuses[0].UploadBytes != "0" {
		t.Fatalf("deleted node inherited counters: %+v %v", statuses, err)
	}
}

func BenchmarkObservedNodeWriteCounter(b *testing.B) {
	c := new(nodeCounters)
	for b.Loop() {
		c.upload.Add(1420)
	}
}
func TestNodeUnknownStatusDoesNotProbe(t *testing.T) {
	r := newTestRuntime(t)
	node := testNode(t, "never-used", "Unknown")
	if _, err := r.Save(t.Context(), node); err != nil {
		t.Fatal(err)
	}
	statuses, err := r.Statuses(t.Context(), []string{node.ID, "not-here", node.ID})
	if err != nil || len(statuses) != 1 || statuses[0].State != "unknown" {
		t.Fatalf("statuses: %+v %v", statuses, err)
	}
}

func TestObservedNodeUDPPayloadAndPackets(t *testing.T) {
	a, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(3 * time.Second))
	_ = b.SetDeadline(time.Now().Add(3 * time.Second))
	counters := new(nodeCounters)
	proxy := &observedProxy{
		Proxy: observedTestProxy{
			connect: func() (net.Conn, error) { return nil, errors.New("tcp disabled") },
			packet:  func() (net.PacketConn, error) { return a, nil },
		},
		c: counters,
	}
	conn, err := proxy.PacketConn(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.WriteTo([]byte("hello"), b.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, _, err := b.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("udp send: %q %v", buf[:n], err)
	}
	if _, err := b.WriteTo([]byte("reply"), a.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	n, _, err = conn.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "reply" {
		t.Fatalf("udp receive: %q %v", buf[:n], err)
	}
	snapshot := counters.snapshot()
	if snapshot.UDPSentPackets != 1 || snapshot.UDPRecvPackets != 1 ||
		snapshot.UploadBytes != 5 || snapshot.DownloadBytes != 5 ||
		snapshot.UDPSessions != 1 {
		t.Fatalf("incorrect UDP payload stats: %+v", snapshot)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if counters.activeUDP.Load() != 0 {
		t.Fatalf("closed UDP session remains active: %d", counters.activeUDP.Load())
	}
}

func TestOutboundHealthExpiresAndProbeFailureAppears(t *testing.T) {
	counters := new(nodeCounters)
	counters.lastSuccess.Store(time.Now().Add(-5 * time.Minute).UnixNano())
	if got := counters.status("expired"); got.State != "unknown" {
		t.Fatalf("stale healthy state should expire: %+v", got)
	}
	counters.probe("tcp", contract.LatencyResponse{OK: false}, nil)
	if got := counters.status("expired"); got.State != "degraded" || got.LastError == "" {
		t.Fatalf("failed test did not update health state: %+v", got)
	}
}

func TestNodeQUICStreamShutdownAccounting(t *testing.T) {
	for _, tc := range []struct {
		name   string
		code   quic.StreamErrorCode
		remote bool
		failed bool
	}{
		{name: "local normal cancellation", code: 0},
		{name: "peer normal cancellation", code: 0, remote: true},
		{name: "local protocol error", code: 1, failed: true},
		{name: "peer protocol error", code: 1, remote: true, failed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := new(nodeCounters)
			c.ioError(&quic.StreamError{StreamID: 7836, ErrorCode: tc.code, Remote: tc.remote})
			got := c.snapshot()
			if tc.failed {
				if got.Failures != 1 || got.LastFailureAt == 0 || got.LastError == "" {
					t.Fatalf("real stream error not recorded: %+v", got)
				}
			} else if got.Failures != 0 || got.LastFailureAt != 0 || got.LastError != "" {
				t.Fatalf("normal QUIC shutdown counted as failure: %+v", got)
			}
		})
	}
}

type observedHalfCloseTestConn struct {
	net.Conn
	readClosed, writeClosed bool
}

func (c *observedHalfCloseTestConn) CloseRead() error {
	c.readClosed = true
	return nil
}
func (c *observedHalfCloseTestConn) CloseWrite() error {
	c.writeClosed = true
	return nil
}

func TestObservedNodePreservesStreamHalfClose(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	delegate := &observedHalfCloseTestConn{Conn: local}
	counters := new(nodeCounters)
	proxy := &observedProxy{
		Proxy: observedTestProxy{connect: func() (net.Conn, error) { return delegate, nil }},
		c:     counters,
	}
	conn, err := proxy.Conn(t.Context(), netapi.EmptyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	half, ok := conn.(interface {
		CloseRead() error
		CloseWrite() error
	})
	if !ok {
		t.Fatalf("observation wrapper lost stream half-close: %T", conn)
	}
	if err := half.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := half.CloseRead(); err != nil {
		t.Fatal(err)
	}
	if !delegate.readClosed || !delegate.writeClosed || counters.activeTCP.Load() != 1 {
		t.Fatalf("half-close was swallowed or closed the entire connection: %+v", delegate)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if counters.activeTCP.Load() != 0 {
		t.Fatal("full close must release the active connection")
	}
}

func TestObservedNodeUnsupportedHalfClose(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	conn := &observedConn{Conn: local, c: new(nodeCounters)}
	if err := conn.CloseWrite(); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("unsupported CloseWrite: %v", err)
	}
	if err := conn.CloseRead(); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("unsupported CloseRead: %v", err)
	}
}
