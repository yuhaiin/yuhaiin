package tun

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils/resolver"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type Tun struct {
	dialer proxy.Proxy
}

func (t *Tun) New(name string) (*stack.Stack, error) {
	if len(name) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("interface name too long: %s", name)
	}

	ep, err := open(name)
	if err != nil {
		return nil, fmt.Errorf("open tun failed: %w", err)
	}

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
	})

	// Generate unique NIC id.
	nicID := tcpip.NICID(s.UniqueID())

	s.SetTransportProtocolHandler(
		tcp.ProtocolNumber,
		tcp.NewForwarder(
			s,
			0,
			0,
			func(r *tcp.ForwarderRequest) {
				var wq waiter.Queue

				ep, err := r.CreateEndpoint(&wq)
				if err != nil {
					r.Complete(true)
					return
				}
				defer r.Complete(false)

				local := gonet.NewTCPConn(&wq, ep)

				conn, er := t.dialer.Conn(net.JoinHostPort(r.ID().LocalAddress.String(), strconv.Itoa(int(r.ID().LocalPort))))
				if er != nil {
					local.Close()
					return
				}

				utils.Relay(local, conn)
			},
		).HandlePacket)

	s.SetTransportProtocolHandler(udp.ProtocolNumber, udp.NewForwarder(s, func(fr *udp.ForwarderRequest) {
		var wq waiter.Queue

		ep, err := fr.CreateEndpoint(&wq)
		if err != nil {
			return
		}

		addr, er := resolver.ResolveUDPAddr(net.JoinHostPort(fr.ID().LocalAddress.String(), strconv.Itoa(int(fr.ID().LocalPort))))
		if er != nil {
			return
		}

		local := gonet.NewUDPConn(s, &wq, ep)

		conn, er := t.dialer.PacketConn(net.JoinHostPort(fr.ID().LocalAddress.String(), strconv.Itoa(int(fr.ID().LocalPort))))
		if er != nil {
			local.Close()
			return
		}

		wg := &sync.WaitGroup{}
		wg.Add(2)

		go func() {
			defer wg.Done()
			copyPacketBuffer(conn, local, addr, time.Second)
		}()

		go func() {
			defer wg.Done()
			copyPacketBuffer(local, conn, nil, time.Second)
		}()

		wg.Wait()
	}).HandlePacket)

	s.CreateNICWithOptions(nicID, ep, stack.NICOptions{Disabled: false, QDisc: nil})

	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         nicID,
		},
	})

	s.SetSpoofing(nicID, true)

	s.SetPromiscuousMode(nicID, true)

	return s, nil
}

func open(name string) (_ stack.LinkEndpoint, err error) {
	var fd int
	if strings.HasPrefix(name, "tun://") {
		fd, err = tun.Open(name[6:])
	} else if strings.HasPrefix(name, "fd://") {
		fd, err = strconv.Atoi(name[5:])
	} else {
		err = fmt.Errorf("invalid tun name: %s", name)
	}
	if err != nil {
		return nil, fmt.Errorf("open tun failed: %w", err)
	}

	mtu, err := rawfile.GetMTU(name)
	if err != nil {
		return nil, fmt.Errorf("get mtu failed: %w", err)
	}

	return fdbased.New(&fdbased.Options{
		FDs:                   []int{fd},
		MTU:                   mtu,
		EthernetHeader:        false,
		PacketDispatchMode:    fdbased.Readv,
		MaxSyscallHeaderBytes: 0x00,
	})
}

var MaxSegmentSize = (1 << 16) - 1

func copyPacketBuffer(dst net.PacketConn, src net.PacketConn, to net.Addr, timeout time.Duration) error {
	buf := utils.GetBytes(MaxSegmentSize)
	defer utils.PutBytes(buf)

	for {
		src.SetReadDeadline(time.Now().Add(timeout))
		n, _, err := src.ReadFrom(buf)
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return nil /* ignore I/O timeout */
		} else if err == io.EOF {
			return nil /* ignore EOF */
		} else if err != nil {
			return err
		}

		if _, err = dst.WriteTo(buf[:n], to); err != nil {
			return err
		}
		dst.SetReadDeadline(time.Now().Add(timeout))
	}
}
