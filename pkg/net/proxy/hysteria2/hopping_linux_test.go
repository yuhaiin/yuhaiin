//go:build linux

package hysteria2

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	inbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	node "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	"github.com/google/nftables"
)

// All firewall and link changes happen inside a disposable network namespace.
func TestPortHoppingKeepsTCPAndUDPSessions(t *testing.T) {
	if os.Getenv("YUHAIIN_HOP_TEST_NAMESPACE") != "1" {
		if err := exec.Command("unshare", "-Urn", "true").Run(); err != nil {
			t.Skipf("isolated network namespaces unavailable: %v", err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "unshare", "-Urn", "--", os.Args[0], "-test.run=^TestPortHoppingKeepsTCPAndUDPSessions$", "-test.v")
		cmd.Env = append(os.Environ(), "YUHAIIN_HOP_TEST_NAMESPACE=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated hopping test: %v\n%s", err, out)
		} else {
			t.Log(string(out))
		}
		return
	}
	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("enable isolated loopback: %v: %s", err, out)
	}
	t.Run("destination scope and rollback", testHopRedirectScope)
	for _, tc := range []struct{ name, bind, ip, password, ports string }{
		{"IPv4", "127.0.0.1:0", "127.0.0.1", "", "21000-21020"},
		{"IPv6 Salamander", "[::1]:0", "::1", "salamander", "22000-22020"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, ca, server, handler := newTestServerWithConfig(t, tc.bind, tc.password, inbound.Hysteria2Protocol{HopPorts: tc.ports})
			parent := &hoppingTestDialer{}
			client, err := NewClient(node.Hysteria2{Host: net.JoinHostPort(tc.ip, tc.ports), Auth: "secret", TLS: node.TLS{CACert: [][]byte{ca}, ServerNames: []string{"test.example"}}, SalamanderPassword: tc.password, HopIntervalSeconds: 5}, parent)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			target, _ := netapi.ParseAddress("tcp", "example.com:443")
			stream, err := client.Conn(t.Context(), target)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			<-handler.streams
			packet, err := client.PacketConn(t.Context(), target)
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			destination := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}
			var sessionID uint64
			until := time.Now().Add(11 * time.Second)
			for sequence := 0; time.Now().Before(until); sequence++ {
				payload := []byte(fmt.Sprintf("packet %d", sequence))
				_ = stream.SetDeadline(time.Now().Add(2 * time.Second))
				if _, err := stream.Write(payload); err != nil {
					t.Fatal(err)
				}
				reply := make([]byte, len(payload))
				if _, err := io.ReadFull(stream, reply); err != nil || !bytes.Equal(reply, payload) {
					t.Fatalf("TCP reply %q: %v", reply, err)
				}
				_ = packet.SetDeadline(time.Now().Add(2 * time.Second))
				if _, err := packet.WriteTo(payload, destination); err != nil {
					t.Fatal(err)
				}
				n, _, err := packet.ReadFrom(reply)
				if err != nil || !bytes.Equal(reply[:n], payload) {
					t.Fatalf("UDP reply %q: %v", reply[:n], err)
				}
				metadata := <-handler.packets
				if sequence == 0 {
					sessionID = metadata.id
				}
				if metadata.id != sessionID {
					t.Fatal("UDP session changed across a hop")
				}
				time.Sleep(50 * time.Millisecond)
			}
			if parent.opened.Load() < 3 {
				t.Fatalf("only %d sockets opened; expected two hops", parent.opened.Load())
			}
			select {
			case <-handler.streams:
				t.Fatal("TCP reconnected while hopping")
			default:
			}
			redirect := server.redirect.(*hopRedirect)
			if err := server.Close(); err != nil {
				t.Fatal(err)
			}
			tables, err := redirect.conn.ListTablesOfFamily(nftables.TableFamilyINet)
			if err != nil {
				t.Fatal(err)
			}
			for _, table := range tables {
				if table.Name == redirect.table.Name {
					t.Fatal("hopping rules survived server close")
				}
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if parent.opened.Load() != parent.closed.Load() {
				t.Fatalf("socket leak: opened %d, closed %d", parent.opened.Load(), parent.closed.Load())
			}
		})
	}
}

func testHopRedirectScope(t *testing.T) {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	other, err := net.ListenPacket("udp4", "127.0.0.2:23000")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	redirect, err := newHopRedirect(listener.LocalAddr(), "23000-23010")
	if err != nil {
		t.Fatal(err)
	}
	defer redirect.Close()
	for _, tc := range []struct {
		host string
		dest net.PacketConn
	}{
		{"127.0.0.1", listener},
		{"127.0.0.2", other},
	} {
		sender, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer sender.Close()
		addr := &net.UDPAddr{IP: net.ParseIP(tc.host), Port: 23000}
		if _, err := sender.WriteTo([]byte("test"), addr); err != nil {
			t.Fatal(err)
		}
		_ = tc.dest.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 16)
		n, from, err := tc.dest.ReadFrom(buf)
		if err != nil || string(buf[:n]) != "test" {
			t.Fatalf("destination %s: %q, %v", tc.host, buf[:n], err)
		}
		if _, err := tc.dest.WriteTo(buf[:n], from); err != nil {
			t.Fatal(err)
		}
		_ = sender.SetReadDeadline(time.Now().Add(time.Second))
		_, from, err = sender.ReadFrom(buf)
		if err != nil || from.String() != addr.String() {
			t.Fatalf("reply source must preserve hop port: %v, %v", from, err)
		}
	}

	// Invalid TLS must roll back already-created forwarding rules.
	lis, err := fixed.NewServer(fixed.ServerConfig{Host: "127.0.0.1:0", Control: fixed.ControlDisableTCP})
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	_, err = NewServer(inbound.Hysteria2Protocol{Auth: "secret", HopPorts: "24000-24010"}, &tls.Config{}, lis, &echoHandler{})
	if err == nil {
		t.Fatal("invalid TLS accepted")
	}
	r := redirect.(*hopRedirect)
	tables, err := r.conn.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range tables {
		if table.Name != r.table.Name && len(table.Name) >= len("yuhaiin_hy2_") && table.Name[:len("yuhaiin_hy2_")] == "yuhaiin_hy2_" {
			t.Fatalf("failed server leaked rules: %s", table.Name)
		}
	}
}

type hoppingTestDialer struct {
	netapi.Proxy
	opened, closed atomic.Int32
}

func (p *hoppingTestDialer) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ip := addr.(netapi.IPAddress).AddrPort().Addr()
	network := "udp6"
	if ip.Is4() {
		network = "udp4"
	}
	conn, err := net.ListenPacket(network, "")
	if err != nil {
		return nil, err
	}
	p.opened.Add(1)
	return &hoppingTestPacketConn{PacketConn: conn, closed: &p.closed}, nil
}

func (*hoppingTestDialer) Close() error { return nil }

type hoppingTestPacketConn struct {
	net.PacketConn
	closed *atomic.Int32
	once   atomic.Bool
}

func (p *hoppingTestPacketConn) Close() error {
	if !p.once.Swap(true) {
		p.closed.Add(1)
	}
	return p.PacketConn.Close()
}
