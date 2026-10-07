package hysteria2

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/cert"
	inbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	node "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	ytls "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tls"
)

type echoHandler struct {
	streams chan *netapi.StreamMeta
	packets chan packetMeta
}
type packetMeta struct {
	source net.Addr
	id     uint64
	target string
}

func (h *echoHandler) HandleStream(meta *netapi.StreamMeta) {
	if h.streams != nil {
		h.streams <- meta
	}
	_, _ = io.Copy(meta.Src, meta.Src)
}
func (h *echoHandler) HandlePacket(p *netapi.Packet) {
	defer p.DecRef()
	if h.packets != nil {
		h.packets <- packetMeta{p.Src(), p.MigrateID, p.Dst().String()}
	}
	_, _ = p.WriteBack(p.GetPayload(), p.Dst())
}
func (*echoHandler) HandlePing(*netapi.PingMeta) {}

func newTestServer(t *testing.T, password string) (string, []byte, *Server, *echoHandler) {
	t.Helper()
	ca, err := cert.GenerateCa()
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := ca.CertBytes()
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := ytls.TlsAutoConfig(ca, nil, []string{"test.example"}, x509.ECDSA)
	lis, err := fixed.NewServer(fixed.ServerConfig{Host: "127.0.0.1:0", Control: fixed.ControlDisableTCP})
	if err != nil {
		t.Fatal(err)
	}
	packet, err := lis.Packet(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	handler := &echoHandler{streams: make(chan *netapi.StreamMeta, 16), packets: make(chan packetMeta, 32)}
	server, err := NewServer(inbound.Hysteria2Protocol{Auth: "secret", SalamanderPassword: password}, tlsConfig, lis, handler)
	if err != nil {
		_ = lis.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return packet.LocalAddr().String(), caPEM, server, handler
}

func testClient(t *testing.T, host string, ca []byte, password string) netapi.Proxy {
	t.Helper()
	client, err := NewClient(node.Hysteria2{Host: host, Auth: "secret", TLS: node.TLS{CACert: [][]byte{ca}, ServerNames: []string{"test.example"}}, SalamanderPassword: password}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestTCPAndUDPSessionIsolation(t *testing.T) {
	for _, password := range []string{"", "salamander"} {
		t.Run(password, func(t *testing.T) {
			host, ca, _, handler := newTestServer(t, password)
			client := testClient(t, host, ca, password)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			target, _ := netapi.ParseAddress("tcp", "example.com:80")
			stream, err := client.Conn(ctx, target)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
			payload := []byte("hysteria tcp echo")
			if _, err := stream.Write(payload); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, len(payload))
			if _, err := io.ReadFull(stream, reply); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(reply, payload) {
				t.Fatalf("TCP reply %q", reply)
			}
			meta := <-handler.streams
			local, _ := netapi.ParseSysAddr(stream.LocalAddr())
			tcpSource, _ := netapi.ParseSysAddr(meta.Source)
			if tcpSource.Port() != local.Port() || meta.Inbound.String() != host || meta.Address.String() != target.String() {
				t.Fatalf("lost TCP metadata: %+v", meta)
			}
			sessions := make([]net.PacketConn, 2)
			ids := make([]uint64, 2)
			for i := range sessions {
				packet, err := client.PacketConn(ctx, target)
				if err != nil {
					t.Fatal(err)
				}
				defer packet.Close()
				sessions[i] = packet
				_ = packet.SetReadDeadline(time.Now().Add(5 * time.Second))
				// Fragmentation and destination changes must both work in a single session.
				for j, dst := range []string{"example.com:53", "example.net:5353"} {
					addr, _ := netapi.ParseAddress("udp", dst)
					body := bytes.Repeat([]byte{byte(i + 1)}, 8192+j)
					if _, err := packet.WriteTo(body, addr); err != nil {
						t.Fatal(err)
					}
					buf := make([]byte, 16384)
					n, source, err := packet.ReadFrom(buf)
					if err != nil {
						t.Fatal(err)
					}
					if source.String() != dst || !bytes.Equal(buf[:n], body) {
						t.Fatalf("UDP reply source=%v bytes=%d", source, n)
					}
					meta := <-handler.packets
					if j == 0 {
						ids[i] = meta.id
					}
					if meta.id == 0 || meta.id != ids[i] || meta.source.String() != tcpSource.String() || meta.target != dst {
						t.Fatalf("lost UDP metadata: %+v", meta)
					}
				}
			}
			if ids[0] == ids[1] {
				t.Fatal("distinct UDP sessions share NAT key")
			}
			packet := sessions[0]
			_ = packet.SetReadDeadline(time.Now().Add(-time.Second))
			if _, _, err := packet.ReadFrom(make([]byte, 16)); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("deadline error = %v", err)
			}
			_ = packet.SetReadDeadline(time.Time{})
			_ = packet.Close()
			if _, _, err := packet.ReadFrom(make([]byte, 16)); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("closed error = %v", err)
			}
		})
	}
}

func TestTLSAndAuthenticationFailures(t *testing.T) {
	host, ca, _, _ := newTestServer(t, "")
	for _, test := range []struct {
		name, auth, sni string
		ca              []byte
	}{{"wrong password", "wrong", "test.example", ca}, {"untrusted CA", "secret", "test.example", nil}, {"wrong SNI", "secret", "other.example", ca}} {
		t.Run(test.name, func(t *testing.T) {
			c, err := NewClient(node.Hysteria2{Host: host, Auth: test.auth, TLS: node.TLS{ServerNames: []string{test.sni}, CACert: [][]byte{test.ca}}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			addr, _ := netapi.ParseAddress("tcp", "example.com:80")
			if conn, err := c.Conn(ctx, addr); err == nil {
				_ = conn.Close()
				t.Fatal("unexpected successful connection")
			}
		})
	}
}

func TestCloseIsFinalAndConcurrent(t *testing.T) {
	host, ca, server, _ := newTestServer(t, "")
	c := testClient(t, host, ca, "")
	addr, _ := netapi.ParseAddress("tcp", "example.com:80")
	conn, err := c.Conn(t.Context(), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { _ = c.Close() })
	}
	wg.Wait()
	if _, err := c.Conn(t.Context(), addr); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Conn after Close: %v", err)
	}
	if _, err := c.PacketConn(t.Context(), addr); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("PacketConn after Close: %v", err)
	}
	_ = server.Close()
	// Shutdown must release the listening UDP port.
	p, err := net.ListenPacket("udp", host)
	if err != nil {
		t.Fatal(err)
	}
	_ = p.Close()
}

func TestCanceledSetup(t *testing.T) {
	blackhole, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	c, err := NewClient(node.Hysteria2{Host: blackhole.LocalAddr().String(), Auth: "secret"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	addr, _ := netapi.ParseAddress("tcp", "example.com:80")
	start := time.Now()
	if _, err := c.Conn(ctx, addr); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("setup deadline error: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("setup ignored caller deadline")
	}
}

func TestInvalidConfiguration(t *testing.T) {
	for _, config := range []node.Hysteria2{{Host: "localhost:443"}, {Host: "localhost:443", Auth: "secret", SalamanderPassword: "abc"}, {Host: "localhost:443", Auth: "secret", UploadBPS: 1}, {Auth: "secret"}} {
		if c, err := NewClient(config, nil); err == nil {
			_ = c.Close()
			t.Fatalf("accepted invalid config %+v", config)
		}
	}
}

func TestCloseCancelsSetupAndWaitingRequests(t *testing.T) {
	blackhole, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	proxy, err := NewClient(node.Hysteria2{Host: blackhole.LocalAddr().String(), Auth: "secret"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	addr, _ := netapi.ParseAddress("tcp", "example.com:80")
	done := make(chan error, 1)
	go func() { _, err := proxy.Conn(t.Context(), addr); done <- err }()
	// Seeing an Initial on the listening socket proves setup is in progress.
	_ = blackhole.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := blackhole.ReadFrom(make([]byte, 2048)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if _, err := proxy.Conn(ctx, addr); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting request ignored context: %v", err)
	}
	start := time.Now()
	_ = proxy.Close()
	if time.Since(start) > time.Second {
		t.Fatal("Close did not cancel setup")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("setup succeeded after close")
		}
	case <-time.After(time.Second):
		t.Fatal("setup did not stop")
	}
}

func TestNewRequestsReconnect(t *testing.T) {
	host, ca, _, _ := newTestServer(t, "")
	proxy := testClient(t, host, ca, "")
	client := proxy.(*Client)
	old, err := client.getSession(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_ = old.Close()
	<-old.Context().Done()
	fresh, err := client.getSession(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if fresh == old {
		t.Fatal("reused closed QUIC session")
	}
	addr, _ := netapi.ParseAddress("tcp", "example.com:80")
	conn, err := proxy.Conn(t.Context(), addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte("reconnected")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, len("reconnected"))); err != nil {
		t.Fatal(err)
	}
}
