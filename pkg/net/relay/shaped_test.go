package relay

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
)

func TestRelayShapedPreservesPayloadAndTerminates(t *testing.T) {
	manager := trafficcontrol.NewManager()
	if err := manager.Apply(trafficcontrol.Config{
		Enabled: true, Global: trafficcontrol.Profile{Upload: trafficcontrol.Rate{BytesPerSecond: 200000, BurstBytes: 256}},
	}); err != nil {
		t.Fatal(err)
	}
	client, front := net.Pipe()
	back, remote := net.Pipe()
	defer client.Close()
	defer remote.Close()
	done := make(chan struct{})
	go func() {
		RelayContext(t.Context(), trafficcontrol.WrapConn(t.Context(), front, func() trafficcontrol.Policy { return manager.Resolve("", "") }), back)
		close(done)
	}()
	payload := bytes.Repeat([]byte("shaped"), 128)
	sent := make(chan struct{})
	go func() { _, _ = client.Write(payload); _ = client.Close(); close(sent) }()
	received, err := io.ReadAll(remote)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatalf("payload mismatch: got %d want %d", len(received), len(payload))
	}
	select {
	case <-sent:
	case <-time.After(3 * time.Second):
		t.Fatal("writer did not terminate")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not terminate")
	}
}
func TestRelayShapedCanceledStreamDoesNotHang(t *testing.T) {
	manager := trafficcontrol.NewManager()
	if err := manager.Apply(trafficcontrol.Config{Enabled: true, Global: trafficcontrol.Profile{
		Upload: trafficcontrol.Rate{BytesPerSecond: 1, BurstBytes: 1},
	}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	client, front := net.Pipe()
	back, remote := net.Pipe()
	defer client.Close()
	defer remote.Close()
	done := make(chan struct{})
	go func() {
		RelayContext(ctx, trafficcontrol.WrapConn(ctx, front, func() trafficcontrol.Policy { return manager.Resolve("", "") }), back)
		close(done)
	}()
	go func() { _, _ = client.Write([]byte("large payload")); _ = client.Close() }()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled paced relay stuck")
	}
}
