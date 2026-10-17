package l2tp

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Preserve the old implementation only as an independent Ethernet peer. Both
// the transport and neighbor exchanges cross the new adapter's frame boundary.
func TestEthernetIndependentPeer(t *testing.T) {
	for _, tc := range []struct {
		name              string
		mtu               int
		routed, linkLocal bool
	}{
		{name: "minimum-ipv4", mtu: 576}, {name: "dual-stack", mtu: 1400}, {name: "routed", mtu: 1400, routed: true}, {name: "link-local-router", mtu: 1400, routed: true, linkLocal: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientCfg := Config{Version: 3, MTU: tc.mtu, Address: "192.0.2.1/24", Router: "192.0.2.2"}
			peerCfg := Config{Version: 3, MTU: tc.mtu, Address: "192.0.2.2/24", Router: "192.0.2.1"}
			if tc.mtu >= 1280 {
				clientCfg.IPv6Address = "fd00::1/64"
				clientCfg.IPv6Router = "fd00::2"
				peerCfg.IPv6Address = "fd00::2/64"
				peerCfg.IPv6Router = "fd00::1"
			}
			peer, err := newReferenceEthernetNetwork(peerCfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = peer.Close() })
			if tc.linkLocal {
				a := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, peer.mac[0] ^ 2, peer.mac[1], peer.mac[2], 0xff, 0xfe, peer.mac[3], peer.mac[4], peer.mac[5]}
				clientCfg.IPv6Router = netip.AddrFrom16(a).String()
			}
			client, err := newEthernetNetwork(clientCfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			var wg sync.WaitGroup
			pump := func(src, dst interface {
				Read([]byte, []tun.ReadPacket) (int, error)
				Write([][]byte, int) (int, error)
			}) {
				b := make([]byte, tc.mtu+14+2*tun.ReadPacketSpacing)
				packets := make([]tun.ReadPacket, 1)
				for {
					count, err := src.Read(b, packets)
					if err != nil {
						return
					}
					for _, p := range packets[:count] {
						frame := b[p.Offset : p.Offset+p.Size]
						if _, err := dst.Write([][]byte{frame}, 0); err != nil {
							return
						}
					}
				}
			}
			wg.Go(func() { pump(client, peer) })
			wg.Go(func() { pump(peer, client) })
			t.Cleanup(func() { _ = client.Close(); _ = peer.Close(); wg.Wait() })
			targets := []string{"192.0.2.2"}
			if tc.mtu >= 1280 {
				targets = append(targets, "fd00::2")
			}
			if tc.routed {
				targets = []string{"198.51.100.2", "2001:db8::2"}
				for _, target := range targets {
					ip := netip.MustParseAddr(target)
					proto := ipv4.ProtocolNumber
					if ip.Is6() {
						proto = ipv6.ProtocolNumber
					}
					addr := tcpip.ProtocolAddress{Protocol: proto, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice(ip.AsSlice()), PrefixLen: ip.BitLen()}}
					if err := peer.stack.AddProtocolAddress(1, addr, stack.AddressProperties{}); err != nil {
						t.Fatal(err)
					}
				}
			}
			for _, target := range targets {
				t.Run(target, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					defer cancel()
					ip := net.ParseIP(target)
					listener, err := peerListenTCP(peer, &net.TCPAddr{IP: ip, Port: 18080})
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					echoed := make(chan error, 1)
					go func() {
						conn, err := listener.Accept()
						if err != nil {
							echoed <- err
							return
						}
						defer conn.Close()
						_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
						_, err = io.Copy(conn, conn)
						echoed <- err
					}()
					conn, err := client.DialContextTCP(ctx, &net.TCPAddr{IP: ip, Port: 18080})
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
					payload := bytes.Repeat([]byte("independent Ethernet BBR"), 4096)
					sent := make(chan error, 1)
					go func() {
						_, err := conn.Write(payload)
						if err == nil {
							err = conn.(interface{ CloseWrite() error }).CloseWrite()
						}
						sent <- err
					}()
					got, err := io.ReadAll(conn)
					if err != nil {
						t.Fatal(err)
					}
					if err := <-sent; err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got, payload) {
						t.Fatal("TCP payload/half-close mismatch")
					}
					if err := <-echoed; err != nil {
						t.Fatal(err)
					}
					udpPeer, err := peer.DialUDP(&net.UDPAddr{IP: ip, Port: 18081}, nil)
					if err != nil {
						t.Fatal(err)
					}
					defer udpPeer.Close()
					_ = udpPeer.SetDeadline(time.Now().Add(5 * time.Second))
					udp, err := client.DialUDP(nil, &net.UDPAddr{IP: ip, Port: 18081})
					if err != nil {
						t.Fatal(err)
					}
					defer udp.Close()
					_ = udp.SetDeadline(time.Now().Add(5 * time.Second))
					payload = bytes.Repeat([]byte{0xa5}, 2000)
					if _, err := udp.Write(payload); err != nil {
						t.Fatal(err)
					}
					buf := make([]byte, 4096)
					count, from, err := udpPeer.ReadFrom(buf)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(buf[:count], payload) {
						t.Fatal("UDP fragment mismatch")
					}
					if _, err := udpPeer.WriteTo(buf[:count], from); err != nil {
						t.Fatal(err)
					}
					count, err = udp.Read(buf)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(buf[:count], payload) {
						t.Fatal("UDP reply fragment mismatch")
					}
				})
			}
		})
	}
}

// The independent peer retains its original concrete sockets; expose a
// standard listener only at the test boundary.
func peerListenTCP(n *referenceEthernetNetwork, a *net.TCPAddr) (net.Listener, error) {
	full, proto := fullAddress(a.IP, a.Port)
	return gonet.ListenTCP(n.stack, full, proto)
}

func TestEthernetCloseWithUnresolvedNeighbor(t *testing.T) {
	n, err := newEthernetNetwork(Config{Version: 3, MTU: 1400, Address: "192.0.2.1/24"})
	if err != nil {
		t.Fatal(err)
	}
	udp, err := n.DialUDP(nil, &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 9})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := udp.Write([]byte("unresolved")); err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() { _ = n.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close blocked on unresolved neighbor")
	}
}

func TestEthernetNeighborBoundsAndClose(t *testing.T) {
	n, err := newEthernetNetwork(Config{Version: 3, MTU: 1400, Address: "192.0.2.1/24", IPv6Address: "fd00::1/64"})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	// Fill unresolved neighbors beyond the link budget. No packet reader runs;
	// the bounded frame queue and pending queue must not block stack workers.
	udp, err := n.DialUDP(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 300 {
		a := netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)})
		if _, err := udp.WriteTo([]byte("pending"), net.UDPAddrFromAddrPort(netip.AddrPortFrom(a, 9))); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for {
		n.mu.Lock()
		entries, pending := len(n.neighbors), n.pending
		n.mu.Unlock()
		if entries > neighborLimit || pending > neighborLimit {
			t.Fatal("unbounded neighbor retention")
		}
		if pending == neighborLimit {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("failed to fill neighbor queue")
		}
		time.Sleep(time.Millisecond)
	}
	// Close must cancel a full output queue and release retained resolutions.
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	entries, pending := len(n.neighbors), n.pending
	n.mu.Unlock()
	if entries != 0 || pending != 0 || len(n.frames) != 0 {
		t.Fatalf("closed Ethernet queues retained: neighbors=%d pending=%d frames=%d", entries, pending, len(n.frames))
	}
}

func TestEthernetRejectsInvalidNeighborSolicitations(t *testing.T) {
	n, err := newEthernetNetwork(Config{Version: 3, MTU: 1400, IPv6Address: "fd00::1/64"})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	peer := &ethernetNetwork{ctx: t.Context(), mac: [6]byte{2, 3, 4, 5, 6, 7}, routes: []ethernetRoute{{prefix: netip.MustParsePrefix("fd00::2/64")}}, frames: make(chan []byte, 1)}
	peer.solicit(netip.MustParseAddr("fd00::1"))
	valid := <-peer.frames
	for _, tc := range []struct {
		name string
		edit func([]byte)
	}{
		{"bad-hop-limit", func(b []byte) { b[21] = 64 }},
		{"bad-checksum", func(b []byte) { b[56] ^= 1 }},
		{"zero-length-option", func(b []byte) {
			b[79] = 0
			b[56], b[57] = 0, 0
			binary.BigEndian.PutUint16(b[56:58], ndpChecksum(netip.MustParseAddr("fd00::2"), netip.MustParseAddr("ff02::1:ff00:1"), b[54:]))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame := bytes.Clone(valid)
			tc.edit(frame)
			if _, err := n.Write([][]byte{frame}, 0); err != nil {
				t.Fatal(err)
			}
			if len(n.frames) != 0 {
				t.Fatal("invalid NDP triggered a response")
			}
		})
	}
	if _, err := n.Write([][]byte{valid}, 0); err != nil {
		t.Fatal(err)
	}
	select {
	case reply := <-n.frames:
		if len(reply) < 55 || reply[54] != 136 {
			t.Fatal("missing neighbor advertisement")
		}
	case <-time.After(time.Second):
		t.Fatal("valid NDP ignored")
	}
}
