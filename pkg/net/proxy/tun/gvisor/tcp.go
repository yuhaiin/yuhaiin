package tun

import (
	"context"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func tcpForwarder(s *stack.Stack, opt *listener.Opts[*listener.Protocol_Tun]) *tcp.Forwarder {
	return tcp.NewForwarder(s, defaultWndSize, maxConnAttempts, func(r *tcp.ForwarderRequest) {
		wq := new(waiter.Queue)
		id := r.ID()

		ep, err := r.CreateEndpoint(wq)
		if err != nil {
			log.Errorln("create endpoint failed:", err)
			r.Complete(true)
			return
		}
		r.Complete(false)

		if err = setSocketOptions(s, ep); err != nil {
			log.Errorf("set socket options failed: %v\n", err)
		}

		go func(local net.Conn, id stack.TransportEndpointID) {
			defer local.Close()

			if IsHandleDNS(opt, id.LocalAddress.String(), id.LocalPort) {
				if err := opt.DNSServer.HandleTCP(local); err != nil {
					log.Errorf("dns handle tcp failed: %v\n", err)
				}
				return
			}

			ctx, cancel := context.WithTimeout(context.TODO(), time.Second*15)
			defer cancel()

			addr := proxy.ParseAddressPort(statistic.Type_tcp, id.LocalAddress.String(), proxy.ParsePort(id.LocalPort))
			addr.WithContext(ctx)
			addr.WithValue(proxy.SourceKey{}, local.RemoteAddr())
			addr.WithValue(proxy.DestinationKey{}, addr)

			conn, er := opt.Dialer.Conn(addr)
			if er != nil {
				log.Errorln("dial failed:", er)
				return
			}
			defer conn.Close()
			relay.Relay(local, conn)
		}(gonet.NewTCPConn(wq, ep), id)
	})
}

const (
	// defaultWndSize if set to zero, the default
	// receive window buffer size is used instead.
	defaultWndSize = 0

	// maxConnAttempts specifies the maximum number
	// of in-flight tcp connection attempts.
	maxConnAttempts = 2 << 10

	// tcpKeepaliveCount is the maximum number of
	// TCP keep-alive probes to send before giving up
	// and killing the connection if no response is
	// obtained from the other end.
	tcpKeepaliveCount = 9

	// tcpKeepaliveIdle specifies the time a connection
	// must remain idle before the first TCP keepalive
	// packet is sent. Once this time is reached,
	// tcpKeepaliveInterval option is used instead.
	tcpKeepaliveIdle = 60 * time.Second

	// tcpKeepaliveInterval specifies the interval
	// time between sending TCP keepalive packets.
	tcpKeepaliveInterval = 30 * time.Second
)

func setSocketOptions(s *stack.Stack, ep tcpip.Endpoint) tcpip.Error {
	{ /* TCP keepalive options */
		ep.SocketOptions().SetKeepAlive(true)

		idle := tcpip.KeepaliveIdleOption(tcpKeepaliveIdle)
		if err := ep.SetSockOpt(&idle); err != nil {
			return err
		}

		interval := tcpip.KeepaliveIntervalOption(tcpKeepaliveInterval)
		if err := ep.SetSockOpt(&interval); err != nil {
			return err
		}

		if err := ep.SetSockOptInt(tcpip.KeepaliveCountOption, tcpKeepaliveCount); err != nil {
			return err
		}
	}
	{ /* TCP recv/send buffer size */
		var ss tcpip.TCPSendBufferSizeRangeOption
		if err := s.TransportProtocolOption(header.TCPProtocolNumber, &ss); err == nil {
			ep.SocketOptions().SetReceiveBufferSize(int64(ss.Default), false)
		}

		var rs tcpip.TCPReceiveBufferSizeRangeOption
		if err := s.TransportProtocolOption(header.TCPProtocolNumber, &rs); err == nil {
			ep.SocketOptions().SetReceiveBufferSize(int64(rs.Default), false)
		}
	}
	return nil
}
