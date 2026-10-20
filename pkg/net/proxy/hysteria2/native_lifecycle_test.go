package hysteria2

import (
	"context"
	"io"
	"testing"
	"time"

	inbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestNativeTCPHandlerOwnsStream(t *testing.T) {
	handler := netapi.NewChannelHandler(t.Context())
	host, ca, _ := newTestServerWithHandler(t, "127.0.0.1:0", "", inbound.Hysteria2Protocol{}, handler)
	client := testClient(t, host, ca, "")
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	addr, _ := netapi.ParseAddress("tcp", "example.com:80")
	conn, err := client.Conn(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	meta := <-handler.Stream()
	defer meta.Src.Close()
	// The channel handler returns before its consumer starts using the stream.
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := meta.Src.Write([]byte("reply")); done <- err }()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("handed-off stream was closed: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
