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

func TestNativeTCPHalfClosePreservesResponse(t *testing.T) {
	handler := netapi.NewChannelHandler(t.Context())
	host, ca, _ := newTestServerWithHandler(t, "127.0.0.1:0", "", inbound.Hysteria2Protocol{}, handler)
	client := testClient(t, host, ca, "")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	target, err := netapi.ParseAddress("tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.Conn(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	meta := <-handler.Stream()
	defer meta.Src.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_ = meta.Src.SetDeadline(time.Now().Add(5 * time.Second))
	clientHalf, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("client stream has no CloseWrite: %T", conn)
	}
	serverHalf, ok := meta.Src.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("server stream has no CloseWrite: %T", meta.Src)
	}
	if _, err := conn.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := clientHalf.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	request, err := io.ReadAll(meta.Src)
	if err != nil || string(request) != "request" {
		t.Fatalf("request after client FIN = %q, %v", request, err)
	}
	// The client must still be able to receive the server's full response.
	if _, err := meta.Src.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err := serverHalf.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(conn)
	if err != nil || string(response) != "response" {
		t.Fatalf("response after client FIN = %q, %v", response, err)
	}
}
