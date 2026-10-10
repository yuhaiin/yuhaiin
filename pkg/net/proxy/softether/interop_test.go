//go:build softether_interop

package softether

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestOfficialSoftEtherEgress(t *testing.T) {
	gateway := os.Getenv("SOFTETHER_GATEWAY")
	target := os.Getenv("SOFTETHER_ECHO_IP")
	if gateway == "" || target == "" {
		t.Skip("set SOFTETHER_GATEWAY and SOFTETHER_ECHO_IP")
	}
	if net.ParseIP(target) == nil {
		t.Fatalf("bad test target %q", target)
	}
	client, err := NewClient(Config{
		Gateway: gateway, Hub: "DEFAULT", Username: "alice", Password: "s3cret",
		Address: "192.168.30.5/24", Router: "192.168.30.1", MTU: 1400,
		InsecureSkipVerify: true, // Only for the ephemeral self-signed test server.
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tcpAddr, err := netapi.ParseAddress("tcp", net.JoinHostPort(target, "19991"))
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := client.Conn(ctx, tcpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	if err := tcp.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		t.Fatal(err)
	}
	want := []byte("native-softether-tcp")
	if _, err := tcp.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(tcp, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("TCP echo mismatch: %q", got)
	}
	udpAddr, err := netapi.ParseAddress("udp", net.JoinHostPort(target, "19992"))
	if err != nil {
		t.Fatal(err)
	}
	packet, err := client.PacketConn(ctx, udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	if err := packet.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		t.Fatal(err)
	}
	data := []byte("native-softether-udp")
	if _, err := packet.WriteTo(data, &net.UDPAddr{IP: net.ParseIP(target), Port: 19992}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, _, err := packet.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], data) {
		t.Fatalf("UDP echo mismatch: %q", buf[:n])
	}
}
