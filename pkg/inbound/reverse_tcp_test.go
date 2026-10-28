package inbound

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestReverseTCPHandsRawStreamToInboundHandler(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	handler := netapi.NewChannelHandler(t.Context())
	server, err := contractProtocol(contract.NewTypedProtocol(contract.ReverseTCPProtocol{Target: "target.example:443"}), netapi.NewListener(listener, nil), handler, [2]netip.Prefix{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var stream *netapi.StreamMeta
	select {
	case stream = <-handler.Stream():
	case <-time.After(2 * time.Second):
		t.Fatal("TCP stream was not handed to the existing inbound handler")
	}
	defer stream.Src.Close()
	if stream.Address.String() != "target.example:443" || stream.Destination.String() != stream.Address.String() || stream.Source.String() != client.LocalAddr().String() || stream.Inbound.String() != listener.Addr().String() {
		t.Fatalf("incorrect stream metadata: %+v", stream)
	}
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_ = stream.Src.SetDeadline(time.Now().Add(2 * time.Second))
	want := []byte{0, 1, 2, 0xff, 'G', 'E', 'T'}
	if _, err := client.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(stream.Src, got); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("raw TCP bytes changed: %x, %v", got, err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second); err == nil {
		_ = conn.Close()
		t.Fatal("closed TCP inbound still accepts connections")
	}
}

func TestReverseTCPRejectsInvalidTarget(t *testing.T) {
	if _, err := newReverseTCPServer("127.0.0.1:not-a-port", nil, nil); err == nil {
		t.Fatal("invalid TCP target accepted")
	}
}
