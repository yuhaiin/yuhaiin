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
		MTU: 1400, UDPAcceleration: true,
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

func TestOfficialSoftEtherDHCPLeaseRenewal(t *testing.T) {
	if os.Getenv("SOFTETHER_TEST_DHCP_RENEWAL") != "1" {
		t.Skip("set SOFTETHER_TEST_DHCP_RENEWAL=1 and configure a 20-second DHCP lease")
	}
	gateway := os.Getenv("SOFTETHER_GATEWAY")
	target := os.Getenv("SOFTETHER_ECHO_IP")
	if gateway == "" || target == "" {
		t.Skip("set SOFTETHER_GATEWAY and SOFTETHER_ECHO_IP")
	}
	client, err := NewClient(Config{
		Gateway: gateway, Hub: "DEFAULT", Username: "alice", Password: "s3cret",
		MTU: 1400, InsecureSkipVerify: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// The test server must issue a 20-second lease. Waiting past the original
	// expiry proves that the client renewed instead of merely retaining its
	// initial address until it became invalid.
	timer := time.NewTimer(25 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer timer.Stop()
	defer ticker.Stop()
waitForRenewal:
	for {
		select {
		case <-timer.C:
			if !client.running.Load() {
				t.Fatal("client closed when the original DHCP lease expired")
			}
			break waitForRenewal
		case <-ticker.C:
			if !client.running.Load() {
				t.Fatal("client closed before the DHCP lease was renewed")
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addr, err := netapi.ParseAddress("tcp", net.JoinHostPort(target, "19991"))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.Conn(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	want := []byte("native-softether-after-dhcp-renewal")
	if _, err := conn.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("TCP echo after DHCP renewal mismatch: %q", got)
	}
}

// BenchmarkOfficialSoftEtherTCPSustained measures one-way application bytes
// over a full-duplex TCP echo stream. It deliberately transfers much more than
// a single RTT window so the result reflects sustained tunnel throughput.
func BenchmarkOfficialSoftEtherTCPSustained(b *testing.B) {
	gateway := os.Getenv("SOFTETHER_GATEWAY")
	target := os.Getenv("SOFTETHER_ECHO_IP")
	if gateway == "" || target == "" {
		b.Skip("set SOFTETHER_GATEWAY and SOFTETHER_ECHO_IP")
	}
	client, err := NewClient(Config{
		Gateway: gateway, Hub: "DEFAULT", Username: "alice", Password: "s3cret",
		MTU: 1400, InsecureSkipVerify: true,
	}, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	addr, err := netapi.ParseAddress("tcp", net.JoinHostPort(target, "19991"))
	if err != nil {
		b.Fatal(err)
	}
	conn, err := client.Conn(ctx, addr)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(10 * time.Minute)); err != nil {
		b.Fatal(err)
	}

	const transferSize = 16 << 20
	chunk := make([]byte, 64<<10)
	for i := range chunk {
		chunk[i] = byte(i)
	}
	b.SetBytes(transferSize)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		readDone := make(chan error, 1)
		go func() {
			_, err := io.CopyN(io.Discard, conn, transferSize)
			readDone <- err
		}()

		for written := 0; written < transferSize; {
			want := min(len(chunk), transferSize-written)
			n, err := conn.Write(chunk[:want])
			if err != nil {
				b.Fatal(err)
			}
			written += n
		}
		if err := <-readDone; err != nil {
			b.Fatal(err)
		}
	}
}
