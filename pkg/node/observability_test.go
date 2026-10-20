package node

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
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
		c:     counters,
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
