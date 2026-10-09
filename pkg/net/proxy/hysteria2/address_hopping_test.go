package hysteria2

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	node "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// Each relay keeps a UDP mapping per client socket, with a distinct upstream
// source IP. This exercises both the client's destination-IP change and the
// Hysteria server's peer-IP change without privileged firewall configuration.
type addressTestRelay struct {
	front    *net.UDPConn
	backend  *net.UDPAddr
	mu       sync.Mutex
	upstream map[string]*net.UDPConn
	closed   bool
	wg       sync.WaitGroup
	packets  atomic.Int64
}

func newAddressTestRelay(t *testing.T, ip, backend string) *addressTestRelay {
	t.Helper()
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Fatal(err)
	}
	remote, err := net.ResolveUDPAddr("udp", backend)
	if err != nil {
		_ = front.Close()
		t.Fatal(err)
	}
	r := &addressTestRelay{front: front, backend: remote, upstream: make(map[string]*net.UDPConn)}
	r.wg.Add(1)
	go r.forward()
	t.Cleanup(func() {
		r.mu.Lock()
		r.closed = true
		_ = r.front.Close()
		for _, conn := range r.upstream {
			_ = conn.Close()
		}
		r.mu.Unlock()
		r.wg.Wait()
	})
	return r
}

func (r *addressTestRelay) forward() {
	defer r.wg.Done()
	var buf [2048]byte
	for {
		n, client, err := r.front.ReadFromUDP(buf[:])
		if err != nil {
			return
		}
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			return
		}
		conn := r.upstream[client.String()]
		if conn == nil {
			// For IPv4 relays, make the final server observe the relay's IP.
			// A mixed-family relay forwards to the IPv4 backend over IPv4.
			local := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 4)}
			if ip := r.front.LocalAddr().(*net.UDPAddr).IP; ip.To4() != nil {
				local.IP = ip
			}
			conn, err = net.DialUDP("udp4", local, r.backend)
			if err != nil {
				r.mu.Unlock()
				return
			}
			r.upstream[client.String()] = conn
			r.wg.Add(1)
			go r.reply(conn, client)
		}
		r.mu.Unlock()
		r.packets.Add(1)
		if _, err := conn.Write(buf[:n]); err != nil {
			return
		}
	}
}

func (r *addressTestRelay) reply(conn *net.UDPConn, client *net.UDPAddr) {
	defer r.wg.Done()
	var buf [2048]byte
	for {
		n, err := conn.Read(buf[:])
		if err != nil {
			return
		}
		if _, err := r.front.WriteToUDP(buf[:n], client); err != nil {
			return
		}
	}
}

func TestAddressHoppingKeepsTCPAndUDPSessions(t *testing.T) {
	for _, tc := range []struct {
		name, secondIP, password string
		parent                   bool
	}{
		{name: "IPv4 direct", secondIP: "127.0.0.3"},
		{name: "IPv4 proxy Salamander", secondIP: "127.0.0.3", password: "salamander", parent: true},
		{name: "mixed families proxy", secondIP: "::1", parent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			backend, ca, _, handler := newTestServer(t, tc.password)
			relays := []*addressTestRelay{newAddressTestRelay(t, "127.0.0.2", backend), newAddressTestRelay(t, tc.secondIP, backend)}
			var parent netapi.Proxy
			tracker := &addressTestDialer{}
			if tc.parent {
				parent = tracker
			}
			clientProxy, err := NewClient(node.Hysteria2{
				Host: relays[0].front.LocalAddr().String(), HopAddresses: []string{relays[1].front.LocalAddr().String()},
				Auth: "secret", TLS: node.TLS{CACert: [][]byte{ca}, ServerNames: []string{"test.example"}},
				SalamanderPassword: tc.password, HopIntervalSeconds: 5,
			}, parent)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = clientProxy.Close() })
			client := clientProxy.(*Client)
			target, _ := netapi.ParseAddress("tcp", "example.com:443")
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			stream, err := client.Conn(ctx, target)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			<-handler.streams
			initialSession := client.session
			packet, err := client.PacketConn(ctx, target)
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			destination, _ := netapi.ParseAddress("udp", "example.com:53")
			var sessionID uint64
			until := time.Now().Add(11 * time.Second)
			for sequence := 0; time.Now().Before(until); sequence++ {
				payload := []byte(fmt.Sprintf("address hop %d", sequence))
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
				n, source, err := packet.ReadFrom(reply)
				if err != nil || source.String() != destination.String() || !bytes.Equal(reply[:n], payload) {
					t.Fatalf("UDP reply %q from %v: %v", reply[:n], source, err)
				}
				metadata := <-handler.packets
				if sequence == 0 {
					sessionID = metadata.id
				}
				if metadata.id == 0 || metadata.id != sessionID {
					t.Fatal("UDP session changed across an address hop")
				}
				time.Sleep(50 * time.Millisecond)
			}
			for _, relay := range relays {
				if relay.packets.Load() == 0 {
					t.Fatalf("relay %s was never used", relay.front.LocalAddr())
				}
			}
			if client.session != initialSession || initialSession.Context().Err() != nil {
				t.Fatal("QUIC connection changed across address hops")
			}
			select {
			case <-handler.streams:
				t.Fatal("TCP reconnected while hopping")
			default:
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if tc.parent && (tracker.opened.Load() < 3 || tracker.opened.Load() != tracker.closed.Load()) {
				t.Fatalf("socket lifecycle: opened %d, closed %d", tracker.opened.Load(), tracker.closed.Load())
			}
		})
	}
}

type addressTestDialer struct {
	netapi.Proxy
	opened, closed atomic.Int32
}

func (p *addressTestDialer) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	network := "udp6"
	if addr.(netapi.IPAddress).AddrPort().Addr().Is4() {
		network = "udp4"
	}
	conn, err := net.ListenPacket(network, "")
	if err != nil {
		return nil, err
	}
	p.opened.Add(1)
	return &addressTestPacketConn{PacketConn: conn, owner: p}, nil
}

func (*addressTestDialer) Close() error { return nil }

type addressTestPacketConn struct {
	net.PacketConn
	owner *addressTestDialer
	once  sync.Once
}

func (p *addressTestPacketConn) Close() error {
	p.once.Do(func() { p.owner.closed.Add(1) })
	return p.PacketConn.Close()
}
