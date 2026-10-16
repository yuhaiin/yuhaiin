package lightweight

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// gVisor is a test-only independent peer. The implementation package never
// imports it. Packet data crossing either endpoint is copied to its new owner.
type referenceIO struct {
	ep                                      *channel.Endpoint
	stack                                   *stack.Stack
	ctx                                     context.Context
	cancel                                  context.CancelFunc
	once                                    sync.Once
	mu                                      sync.Mutex
	outbound, inbound                       int
	dropEvery, duplicateEvery, reorderEvery int
	held                                    []byte
	reorderTimer                            *time.Timer
}

func newReferenceIO(mtu int) (*referenceIO, error) {
	r := &referenceIO{ep: channel.New(2048, uint32(mtu), ""), stack: stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6}, HandleLocal: true})}
	r.ctx, r.cancel = context.WithCancel(context.Background())
	if e := r.stack.CreateNIC(1, r.ep); e != nil {
		return nil, ErrMalformed
	}
	for _, addr := range []string{"192.0.2.2", "2001:db8::2"} {
		a := netip.MustParseAddr(addr)
		proto := ipv4.ProtocolNumber
		if a.Is6() {
			proto = ipv6.ProtocolNumber
		}
		if e := r.stack.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: proto, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice(a.AsSlice()), PrefixLen: a.BitLen()}}, stack.AddressProperties{}); e != nil {
			return nil, ErrMalformed
		}
	}
	r.stack.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	sack := tcpip.TCPSACKEnabled(true)
	r.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	return r, nil
}
func (r *referenceIO) ReadPacket(b []byte) (int, error) {
	for {
		p := r.ep.ReadContext(r.ctx)
		if p == nil {
			return 0, net.ErrClosed
		}
		v := p.ToView()
		p.DecRef()
		data := v.AsSlice()
		r.mu.Lock()
		r.inbound++
		drop := r.dropEvery > 0 && r.inbound%r.dropEvery == 0
		r.mu.Unlock()
		if drop {
			v.Release()
			continue
		}
		if len(data) > len(b) {
			v.Release()
			return 0, io.ErrShortBuffer
		}
		n := copy(b, data)
		v.Release()
		return n, nil
	}
}
func (r *referenceIO) inject(b []byte) {
	proto := ipv4.ProtocolNumber
	if b[0]>>4 == 6 {
		proto = ipv6.ProtocolNumber
	}
	p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(bytes.Clone(b))})
	r.ep.InjectInbound(proto, p)
	p.DecRef()
}
func (r *referenceIO) WritePacket(b []byte) error {
	select {
	case <-r.ctx.Done():
		return net.ErrClosed
	default:
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.outbound++
	if r.dropEvery > 0 && r.outbound%r.dropEvery == 0 {
		return nil
	}
	// Reorder only data; never strand a lone SYN/FIN in a two-packet swap.
	p, err := ParsePacket(b)
	dataPacket := err == nil && p.Protocol == 6 && len(p.Payload) > int(p.Payload[12]>>4)*4
	if dataPacket && r.reorderEvery > 0 && r.outbound%r.reorderEvery == 0 && r.held == nil {
		r.held = bytes.Clone(b)
		if r.reorderTimer == nil {
			r.reorderTimer = time.AfterFunc(time.Millisecond, func() {
				r.mu.Lock()
				defer r.mu.Unlock()
				if r.held != nil {
					r.inject(r.held)
					r.held = nil
				}
			})
		} else {
			r.reorderTimer.Reset(time.Millisecond)
		}
		return nil
	}
	r.inject(b)
	if r.held != nil {
		r.inject(r.held)
		r.held = nil
	}
	if r.duplicateEvery > 0 && r.outbound%r.duplicateEvery == 0 {
		r.inject(b)
	}
	return nil
}
func (r *referenceIO) Close() error {
	r.once.Do(func() {
		r.mu.Lock()
		if r.reorderTimer != nil {
			r.reorderTimer.Stop()
		}
		r.held = nil
		r.mu.Unlock()
		r.cancel()
		r.ep.Close()
		r.stack.RemoveNIC(1)
		r.stack.Destroy()
	})
	return nil
}
func refAddress(a netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	proto := ipv4.ProtocolNumber
	if a.Addr().Is6() {
		proto = ipv6.ProtocolNumber
	}
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(a.Addr().AsSlice()), Port: a.Port()}, proto
}

func TestGVisorTCPInteroperability(t *testing.T) {
	for _, algorithm := range []string{"reno", "cubic", "bbr"} {
		for _, v6 := range []bool{false, true} {
			for _, direction := range []string{"outbound", "inbound"} {
				t.Run(algorithm+"/"+map[bool]string{false: "v4", true: "v6"}[v6]+"/"+direction, func(t *testing.T) {
					r, err := newReferenceIO(1500)
					if err != nil {
						t.Fatal(err)
					}
					r.dropEvery = 17
					r.duplicateEvery = 11
					r.reorderEvery = 13
					s, err := New(Config{Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}, CongestionControl: algorithm}, r)
					if err != nil {
						t.Fatal(err)
					}
					defer s.Close()
					local, remote := netip.MustParseAddrPort("192.0.2.1:8080"), netip.MustParseAddrPort("192.0.2.2:8080")
					if v6 {
						local = netip.MustParseAddrPort("[2001:db8::1]:8080")
						remote = netip.MustParseAddrPort("[2001:db8::2]:8080")
					}
					ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
					defer cancel()
					var client net.Conn
					var listener net.Listener
					if direction == "outbound" {
						a, proto := refAddress(remote)
						listener, err = gonet.ListenTCP(r.stack, a, proto)
						if err == nil {
							client, err = s.DialContextTCP(ctx, remote)
						}
					} else {
						listener, err = s.ListenTCP(local)
						if err == nil {
							a, proto := refAddress(local)
							client, err = gonet.DialContextTCP(ctx, r.stack, a, proto)
						}
					}
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					defer client.Close()
					server, err := listener.Accept()
					if err != nil {
						t.Fatal(err)
					}
					defer server.Close()
					_ = server.SetDeadline(time.Now().Add(12 * time.Second))
					_ = client.SetDeadline(time.Now().Add(12 * time.Second))
					payload := bytes.Repeat([]byte("independent-reference-peer\x00\xff"), 4096)
					done := make(chan error, 1)
					go func() {
						got := make([]byte, len(payload))
						_, e := io.ReadFull(server, got)
						if e == nil && !bytes.Equal(got, payload) {
							e = ErrMalformed
						}
						if e == nil {
							_, e = server.Write(got)
						}
						if e == nil {
							e = server.(interface{ CloseWrite() error }).CloseWrite()
						}
						done <- e
					}()
					if _, err = client.Write(payload); err != nil {
						t.Fatal(err)
					}
					if err = client.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
						t.Fatal(err)
					}
					got, err := io.ReadAll(client)
					if err != nil || !bytes.Equal(got, payload) {
						t.Fatalf("echo %d/%d: %v stats=%+v", len(got), len(payload), err, s.Stats())
					}
					if err = <-done; err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}
