package ikev2

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/ikev2/ike"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/internal/testutil/leaktest"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/vlog"
)

func TestConnectCancellationClosesIKETransport(t *testing.T) {
	leaktest.VerifyNoGoroutineLeaks(t)
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client := ike.NewClient(ike.ClientConfig{
		ServerHost: "127.0.0.1",
		ServerPort: server.LocalAddr().(*net.UDPAddr).Port,
		NATTPort:   server.LocalAddr().(*net.UDPAddr).Port,
		PSK:        []byte("test-key"),
		Logger:     vlog.Discard(),
	})
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, err := connect(ctx, client)
		result <- err
	}()

	if err := server.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 2048)
	if _, _, err := server.ReadFromUDP(packet); err != nil {
		t.Fatalf("read IKE_SA_INIT from client: %v", err)
	}
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("connect() error = %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("IKE handshake did not stop after cancellation")
	}
}
