package tun

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
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
	DNS          server.DNSServer
	Dialer       proxy.Proxy
}

func NewTun(opt *TunOpt) (*stack.Stack, error) {
	if opt.MTU <= 0 {
		opt.MTU = 1500
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

	log.Println("new tun stack:", opt.Name, "mtu:", opt.MTU, "gateway:", opt.Gateway)

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})

	// Generate unique NIC id.
	nicID := tcpip.NICID(s.UniqueID())

	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder(s, opt).HandlePacket)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder(s, opt).HandlePacket)

	s.CreateNIC(nicID, ep)

	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
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

	// opt2 := tcpip.CongestionControlOption(tcpCongestionControlAlgorithm)
	// s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt2)

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

		go func(local net.Conn, id stack.TransportEndpointID) {
			defer local.Close()

			if isDNSReq(opt, id) {
				if err := opt.DNS.HandleTCP(local); err != nil {
					log.Printf("dns handle tcp failed: %v\n", err)
				}
				return
			}

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

		go func(local net.PacketConn, id stack.TransportEndpointID) {
			defer local.Close()
			if isDNSReq(opt, fr.ID()) {
				if err := opt.DNS.HandleUDP(local); err != nil {
					log.Printf("dns handle udp failed: %v\n", err)
				}
				return
			}

			addr := proxy.ParseAddressSplit("udp", id.LocalAddress.String(), id.LocalPort)
			conn, er := opt.Dialer.PacketConn(addr)
			if er != nil {
				return
			}
			defer conn.Close()

			uaddr, err := addr.UDPAddr()
			if err != nil {
				return
			}
			go handleUDPToRemote(local, conn, uaddr)
			handleUDPToLocal(local, conn, uaddr)
		}(local, fr.ID())
	})
}

func isDNSReq(opt *TunOpt, id stack.TransportEndpointID) bool {
	if id.LocalPort == 53 && (opt.DNSHijacking || id.LocalAddress.String() == opt.Gateway) {
		return true
	}
	return false
}

var MaxSegmentSize = (1 << 16) - 1

func handleUDPToRemote(uc, pc net.PacketConn, remote net.Addr) {
	buf := utils.GetBytes(MaxSegmentSize)
	defer utils.PutBytes(buf)

	for {
		n, _, err := uc.ReadFrom(buf)
		if err != nil {
			return
		}

		if _, err := pc.WriteTo(buf[:n], remote); err != nil {
			log.Printf("[UDP] write to %s error: %v\n", remote, err)
		}
		pc.SetReadDeadline(time.Now().Add(20 * time.Second)) /* reset timeout */
	}
}

func handleUDPToLocal(uc, pc net.PacketConn, remote net.Addr) {
	buf := utils.GetBytes(MaxSegmentSize)
	defer utils.PutBytes(buf)

	for {
		pc.SetReadDeadline(time.Now().Add(20 * time.Second)) /* reset timeout */
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) /* ignore I/O timeout */ {
				log.Printf("[UDP] read error: %v\n", err)
			}
			return
		}

		if from.Network() != remote.Network() || from.String() != remote.String() {
			log.Printf("[UDP] drop unknown packet from %s\n", from)
			return
		}

		if _, err := uc.WriteTo(buf[:n], nil); err != nil {
			log.Printf("[UDP] write back from %s error: %v\n", from, err)
			return
		}
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
