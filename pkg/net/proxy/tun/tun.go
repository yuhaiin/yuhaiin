package tun

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils/resolver"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type TunOpt struct {
	Name         string
	Gateway      string
	MTU          int
	DNSHijacking bool
	DNS          *dns.DNSServer
	Dialer       proxy.Proxy
}

func NewTun(opt *TunOpt) (*stack.Stack, error) {
	if opt.MTU <= 0 {
		opt.MTU = 1500
	}

	if len(opt.Name) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("interface name too long: %s", opt.Name)
	}

	if opt.Gateway == "" {
		return nil, fmt.Errorf("gateway is empty")
	}

	if opt.Dialer == nil {
		return nil, fmt.Errorf("dialer is nil")
	}

	if opt.DNS == nil {
		return nil, fmt.Errorf("dns is nil")
	}

	ep, err := open(opt.Name, opt.MTU)
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

	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder(s, opt).HandlePacket)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder(s, opt).HandlePacket)

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

	// ttlopt := tcpip.DefaultTTLOption(defaultTimeToLive)
	// s.SetNetworkProtocolOption(ipv4.ProtocolNumber, &ttlopt)
	// s.SetNetworkProtocolOption(ipv6.ProtocolNumber, &ttlopt)

	// s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, ipForwardingEnabled)
	// s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, ipForwardingEnabled)

	// s.SetICMPBurst(icmpBurst)
	// s.SetICMPLimit(icmpLimit)

	rcvOpt := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     1,
		Default: utils.DefaultSize,
		Max:     utils.DefaultSize,
	}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcvOpt)

	sndOpt := tcpip.TCPSendBufferSizeRangeOption{
		Min:     1,
		Default: utils.DefaultSize,
		Max:     utils.DefaultSize,
	}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sndOpt)

	opt2 := tcpip.CongestionControlOption(tcpCongestionControlAlgorithm)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt2)

	// opt3 := tcpip.TCPDelayEnabled(tcpDelayEnabled)
	// s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt3)

	sOpt := tcpip.TCPSACKEnabled(tcpSACKEnabled)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sOpt)

	mOpt := tcpip.TCPModerateReceiveBufferOption(tcpModerateReceiveBufferEnabled)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &mOpt)

	// tr := tcpRecovery
	// s.SetTransportProtocolOption(tcp.ProtocolNumber, &tr)
	return s, nil
}

func tcpForwarder(s *stack.Stack, opt *TunOpt) *tcp.Forwarder {
	return tcp.NewForwarder(s, 0, 1024, func(r *tcp.ForwarderRequest) {
		var wq waiter.Queue

		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true)
			return
		}
		defer r.Complete(false)

		// if err = setSocketOptions(s, ep); err != nil {
		// log.Printf("set socket options failed: %v\n", err)
		// }

		local := gTcpConn{gonet.NewTCPConn(&wq, ep)}

		if isDNSReq(opt, r.ID()) {
			go func() {
				defer local.Close()
				opt.DNS.HandleTCP(local)
			}()
			return
		}

		go func(local net.Conn, id stack.TransportEndpointID) {
			defer local.Close()
			addr := proxy.ParseAddressSplit("tcp", id.LocalAddress.String(), id.LocalPort)
			conn, er := opt.Dialer.Conn(addr)
			if er != nil {
				return
			}
			defer conn.Close()
			utils.Relay(local, conn)
		}(local, r.ID())
	})
}

type gTcpConn struct{ *gonet.TCPConn }

func (g gTcpConn) Close() error {
	g.TCPConn.SetDeadline(time.Now().Add(-1))
	return g.TCPConn.Close()
}

type gUdpConn struct{ *gonet.UDPConn }

func (g gUdpConn) Close() error {
	g.UDPConn.SetDeadline(time.Now().Add(-1))
	return g.UDPConn.Close()
}

func udpForwarder(s *stack.Stack, opt *TunOpt) *udp.Forwarder {
	return udp.NewForwarder(s, func(fr *udp.ForwarderRequest) {
		var wq waiter.Queue
		ep, err := fr.CreateEndpoint(&wq)
		if err != nil {
			return
		}

		local := gUdpConn{gonet.NewUDPConn(s, &wq, ep)}

		if isDNSReq(opt, fr.ID()) {
			go func() {
				defer local.Close()
				opt.DNS.HandleUDP(local)
			}()
			return
		}

		go func(local net.PacketConn) {
			defer local.Close()
			addr, er := resolver.ResolveUDPAddr(net.JoinHostPort(fr.ID().LocalAddress.String(), strconv.Itoa(int(fr.ID().LocalPort))))
			if er != nil {
				return
			}
			conn, er := opt.Dialer.PacketConn(proxy.ParseAddressSplit("udp", fr.ID().LocalAddress.String(), fr.ID().LocalPort))
			if er != nil {
				return
			}
			defer conn.Close()

			go copyPacketBuffer(conn, local, addr, time.Second)
			copyPacketBuffer(local, conn, nil, time.Second)
		}(local)
	})
}

func isDNSReq(opt *TunOpt, id stack.TransportEndpointID) bool {
	if id.LocalPort == 53 && (opt.DNSHijacking || id.LocalAddress.String() == opt.Gateway) {
		return true
	}
	return false
}

func open(name string, mtu int) (_ stack.LinkEndpoint, err error) {
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

	return fdbased.New(&fdbased.Options{
		FDs:            []int{fd},
		MTU:            uint32(mtu),
		EthernetHeader: false,
		// PacketDispatchMode:    fdbased.Readv,
		// MaxSyscallHeaderBytes: 0x00,
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

const (
	// tcpCongestionControl is the congestion control algorithm used by
	// stack. ccReno is the default option in gVisor stack.
	tcpCongestionControlAlgorithm = "reno" // "reno" or "cubic"

	// tcpModerateReceiveBufferEnabled is the value used by stack to
	// enable or disable tcp receive buffer auto-tuning option.
	tcpModerateReceiveBufferEnabled = false

	// tcpSACKEnabled is the value used by stack to enable or disable
	// tcp selective ACK.
	tcpSACKEnabled = true
)

// const (
// 	// defaultWndSize if set to zero, the default
// 	// receive window buffer size is used instead.
// 	defaultWndSize = 0

// 	// maxConnAttempts specifies the maximum number
// 	// of in-flight tcp connection attempts.
// 	maxConnAttempts = 2 << 10

// 	// tcpKeepaliveCount is the maximum number of
// 	// TCP keep-alive probes to send before giving up
// 	// and killing the connection if no response is
// 	// obtained from the other end.
// 	tcpKeepaliveCount = 9

// 	// tcpKeepaliveIdle specifies the time a connection
// 	// must remain idle before the first TCP keepalive
// 	// packet is sent. Once this time is reached,
// 	// tcpKeepaliveInterval option is used instead.
// 	tcpKeepaliveIdle = 60 * time.Second

// 	// tcpKeepaliveInterval specifies the interval
// 	// time between sending TCP keepalive packets.
// 	tcpKeepaliveInterval = 30 * time.Second
// )

// func setSocketOptions(s *stack.Stack, ep tcpip.Endpoint) tcpip.Error {
// 	{ /* TCP keepalive options */
// 		ep.SocketOptions().SetKeepAlive(true)

// 		idle := tcpip.KeepaliveIdleOption(tcpKeepaliveIdle)
// 		if err := ep.SetSockOpt(&idle); err != nil {
// 			return err
// 		}

// 		interval := tcpip.KeepaliveIntervalOption(tcpKeepaliveInterval)
// 		if err := ep.SetSockOpt(&interval); err != nil {
// 			return err
// 		}

// 		if err := ep.SetSockOptInt(tcpip.KeepaliveCountOption, tcpKeepaliveCount); err != nil {
// 			return err
// 		}
// 	}
// 	{ /* TCP recv/send buffer size */
// 		var ss tcpip.TCPSendBufferSizeRangeOption
// 		if err := s.TransportProtocolOption(header.TCPProtocolNumber, &ss); err == nil {
// 			ep.SocketOptions().SetReceiveBufferSize(int64(ss.Default), false)
// 		}

// 		var rs tcpip.TCPReceiveBufferSizeRangeOption
// 		if err := s.TransportProtocolOption(header.TCPProtocolNumber, &rs); err == nil {
// 			ep.SocketOptions().SetReceiveBufferSize(int64(rs.Default), false)
// 		}
// 	}
// 	return nil
// }
