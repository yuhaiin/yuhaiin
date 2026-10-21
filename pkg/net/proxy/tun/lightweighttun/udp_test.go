package lightweighttun

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight"
)

type udpTestLink struct {
	in, out chan []byte
	done    chan struct{}
	once    *sync.Once
}

func (l *udpTestLink) ReadPacket(b []byte) (int, error) {
	select {
	case p := <-l.in:
		return copy(b, p), nil
	case <-l.done:
		return 0, net.ErrClosed
	}
}

func (l *udpTestLink) WritePacket(b []byte) error {
	select {
	case l.out <- bytes.Clone(b):
		return nil
	case <-l.done:
		return net.ErrClosed
	}
}

func (l *udpTestLink) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func TestUDPWriteBack(t *testing.T) {
	for _, family := range []struct{ name, client, dns string }{
		{"IPv4", "192.0.2.2:40000", "192.0.2.1:53"},
		{"IPv6", "[2001:db8::2]:40000", "[2001:db8::1]:53"},
	} {
		for _, addressType := range []string{"netapi", "net.UDPAddr", "mapped-netapi", "mapped-net.UDPAddr"} {
			if family.name == "IPv6" && (addressType == "mapped-netapi" || addressType == "mapped-net.UDPAddr") {
				continue
			}
			t.Run(family.name+"/"+addressType, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				clientAddr := netip.MustParseAddrPort(family.client)
				dnsAddr := netip.MustParseAddrPort(family.dns)
				a, b := make(chan []byte, 8), make(chan []byte, 8)
				done, once := make(chan struct{}), new(sync.Once)
				client, err := lightweight.New(lightweight.Config{Addresses: []netip.Addr{clientAddr.Addr()}}, &udpTestLink{a, b, done, once})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = client.Close() })
				stack, err := lightweight.New(lightweight.Config{Addresses: []netip.Addr{dnsAddr.Addr()}, ForwardUDP: true}, &udpTestLink{b, a, done, once})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = stack.Close() })
				handler := netapi.NewChannelHandler(ctx)
				s := &server{stack: stack, options: &device.Opt{Handler: handler, Options: &netlink.Options{Inet4Address: []netip.Prefix{netip.PrefixFrom(dnsAddr.Addr(), dnsAddr.Addr().BitLen())}}}}
				s.wg.Go(s.udpLoop)
				t.Cleanup(func() { _ = stack.Close(); s.wg.Wait() })
				socket, err := client.ListenUDP(clientAddr)
				if err != nil {
					t.Fatal(err)
				}
				_ = socket.SetReadDeadline(time.Now().Add(5 * time.Second))
				query, reply := []byte("DNS query"), []byte("DNS reply")
				if _, err := client.WriteUDP(clientAddr, dnsAddr, query); err != nil {
					t.Fatal(err)
				}
				var packet *netapi.Packet
				select {
				case packet = <-handler.Packet():
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				defer packet.DecRef()
				if !packet.IsDNSRequest() || !bytes.Equal(packet.GetPayload(), query) {
					t.Fatal("DNS request was not forwarded intact")
				}
				for _, invalid := range []net.Addr{nil, (*net.UDPAddr)(nil), netapi.DomainAddr{HostnameX: "example.com", PortX: 53}, netapi.IPAddr{}} {
					if n, err := packet.WriteBack(reply, invalid); err == nil || n != 0 {
						t.Fatalf("accepted invalid reply address %T: %d, %v", invalid, n, err)
					}
				}
				// A valid IP on the wrong address family must fail as a
				// packet-local error, without implying that the socket is dead.
				if family.name == "IPv4" {
					wrongFamily := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("[2001:db8::15]:53"))
					if _, err := packet.WriteBack(reply, wrongFamily); !errors.Is(err, netapi.ErrUndeliverableDatagram) || !errors.Is(err, lightweight.ErrMalformed) {
						t.Fatalf("cross-family reply: %v", err)
					}
				}
				// DNS hijacking replies through packet.Dst(), a netapi.IPAddr.
				var source net.Addr = packet.Dst()
				switch addressType {
				case "net.UDPAddr":
					// Forwarded proxy replies may originate from another endpoint.
					dnsAddr = netip.AddrPortFrom(dnsAddr.Addr().Next().Next(), 5353)
					source = net.UDPAddrFromAddrPort(dnsAddr)
				case "mapped-netapi":
					source = netapi.ParseNetipAddrPort("udp", netip.MustParseAddrPort("[::ffff:192.0.2.1]:53"))
				case "mapped-net.UDPAddr":
					source = &net.UDPAddr{IP: net.ParseIP("::ffff:192.0.2.1"), Port: 53}
				}
				if n, err := packet.WriteBack(reply, source); err != nil || n != len(reply) {
					t.Fatalf("writeback: %d, %v", n, err)
				}
				buf := make([]byte, 512)
				n, from, err := socket.ReadFrom(buf)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(buf[:n], reply) || from.(*net.UDPAddr).AddrPort() != dnsAddr {
					t.Fatalf("reply: %q from %v", buf[:n], from)
				}
			})
		}
	}
}
