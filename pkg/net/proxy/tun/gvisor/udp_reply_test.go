package gvisor

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type blockedReplyEndpoint struct {
	*channel.Endpoint
	entered   chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
}

func (e *blockedReplyEndpoint) WritePackets(stack.PacketBufferList) (int, tcpip.Error) {
	close(e.entered)
	<-e.closed
	return 0, &tcpip.ErrClosedForSend{}
}

func (e *blockedReplyEndpoint) Close() {
	e.closeOnce.Do(func() { close(e.closed); e.Endpoint.Close() })
}

func TestUDPReplyCloseInterruptsBlockedWrite(t *testing.T) {
	ep := &blockedReplyEndpoint{Endpoint: channel.New(1, 1500, ""), entered: make(chan struct{}), closed: make(chan struct{})}
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}})
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatal(err)
	}
	writer := newUDPReply(s, 1, 1500)
	server := &tunServer{ep: ep, stack: s, udpReply: writer}
	t.Cleanup(func() { ep.Close(); _ = server.Close() })
	written := make(chan error, 1)
	go func() {
		_, err := writer.write([]byte("blocked reply"), tcpip.AddrFrom4([4]byte{192, 0, 2, 2}), 12345, &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 443})
		written <- err
	}()
	select {
	case <-ep.entered:
	case <-time.After(time.Second):
		t.Fatal("reply did not reach the device")
	}
	closed := make(chan struct{})
	go func() { _ = server.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close waited on a write it must interrupt")
	}
	if err := <-written; !errors.Is(err, net.ErrClosed) {
		t.Errorf("blocked reply after shutdown = %v", err)
	}
}

func TestUDPReplyBeforeAndDuringClose(t *testing.T) {
	for _, host := range []string{"192.0.2.2", "2001:db8::2"} {
		t.Run(host, func(t *testing.T) {
			ep := channel.New(128, 1500, "")
			s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}})
			t.Cleanup(s.Destroy)
			if err := s.CreateNIC(1, ep); err != nil {
				t.Fatal(err)
			}
			writer := newUDPReply(s, 1, 1500)
			address := netip.MustParseAddr(host)
			source := tcpip.AddrFromSlice(address.AsSlice())
			remoteAddress := netip.MustParseAddr("2001:db8:1::1")
			if address.Is4() {
				remoteAddress = netip.MustParseAddr("198.51.100.1")
			}
			remote := net.UDPAddrFromAddrPort(netip.AddrPortFrom(remoteAddress, 443))
			payload := []byte("UDP reply still works")
			if n, err := writer.write(payload, source, 12345, remote); err != nil || n != len(payload) {
				t.Fatalf("write = %d, %v", n, err)
			}
			packet := ep.Read()
			if packet == nil {
				t.Fatal("missing UDP reply")
			}
			view := packet.ToView()
			wire := view.AsSlice()
			var ip header.Network
			if source.Len() == 4 {
				ip = header.IPv4(wire)
			} else {
				ip = header.IPv6(wire)
			}
			udp := header.UDP(ip.Payload())
			valid := ip.SourceAddress() == tcpip.AddrFromSlice(remoteAddress.AsSlice())
			valid = valid && ip.DestinationAddress() == source && udp.SourcePort() == 443 && udp.DestinationPort() == 12345 && bytes.Equal(udp.Payload(), payload)
			view.Release()
			packet.DecRef()
			if !valid {
				t.Fatal("reply addresses, ports or payload changed")
			}
			var writes sync.WaitGroup
			for range 8 {
				writes.Go(func() {
					for range 8 {
						if _, err := writer.write(payload, source, 12345, remote); err != nil && !errors.Is(err, net.ErrClosed) {
							t.Errorf("concurrent write: %v", err)
						}
					}
				})
			}
			writer.close()
			writes.Wait()
			if _, err := writer.write(payload, source, 12345, remote); !errors.Is(err, net.ErrClosed) {
				t.Errorf("write after close = %v", err)
			}
		})
	}
}
