package tun

import (
	"fmt"
	"io"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"golang.org/x/time/rate"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type tunServer struct {
	mtu   int32
	nicID tcpip.NICID
	stack *stack.Stack
	ep    stack.LinkEndpoint

	*netapi.ChannelServer
}

func (t *tunServer) Close() error {

	var err error
	if ep, ok := t.ep.(io.Closer); ok {
		err = ep.Close()
	}

	if t.stack != nil {
		t.stack.RemoveRoutes(func(r tcpip.Route) bool {
			return true
		})
		t.stack.Destroy()
	}
	t.ChannelServer.Close()
	return err
}

type Opt struct {
	*listener.Inbound_Tun
	*netlink.Options
}

func New(o *Opt) (netapi.Accepter, error) {
	opt := o.Tun
	if opt.Mtu <= 0 {
		opt.Mtu = 1500
	}

	ep, err := Open(o.Interface, opt.GetDriver(), int(opt.Mtu))
	if err != nil {
		return nil, fmt.Errorf("open tun failed: %w", err)
	}

	o.Endpoint = ep

	log.Debug("preload tun device", "name", o.Interface, "mtu", opt.Mtu, "portal", opt.Portal)
	if err = netlink.Route(o.Options); err != nil {
		log.Warn("preload failed", "err", err)
	}

	log.Debug("new tun stack", "name", opt.Name, "mtu", opt.Mtu, "portal", opt.Portal)

	stackOption := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
	}
	// if o.IPv6 {
	stackOption.NetworkProtocols = append(stackOption.NetworkProtocols, ipv6.NewProtocol)
	stackOption.TransportProtocols = append(stackOption.TransportProtocols, icmp.NewProtocol6)
	// }

	s := stack.New(stackOption)

	// Generate unique NIC id.
	nicID := tcpip.NICID(s.UniqueID())
	if er := s.CreateNIC(nicID, ep); er != nil {
		ep.Attach(nil)
		return nil, fmt.Errorf("create nic failed: %v", er)
	}

	t := &tunServer{
		mtu:           opt.Mtu,
		nicID:         nicID,
		stack:         s,
		ep:            ep,
		ChannelServer: netapi.NewChannelServer(),
	}

	s.SetSpoofing(nicID, true)
	s.SetPromiscuousMode(nicID, true)
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})
	ttlopt := tcpip.DefaultTTLOption(defaultTimeToLive)
	s.SetNetworkProtocolOption(ipv4.ProtocolNumber, &ttlopt)
	s.SetNetworkProtocolOption(ipv6.ProtocolNumber, &ttlopt)

	s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, ipForwardingEnabled)
	s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, ipForwardingEnabled)

	s.SetICMPBurst(icmpBurst)
	s.SetICMPLimit(icmpLimit)

	rcvOpt := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     tcp.MinBufferSize,
		Default: pool.DefaultSize,
		Max:     tcp.MaxBufferSize,
	}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcvOpt)

	sndOpt := tcpip.TCPSendBufferSizeRangeOption{
		Min:     tcp.MinBufferSize,
		Default: pool.DefaultSize,
		Max:     tcp.MaxBufferSize,
	}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sndOpt)

	opt2 := tcpip.CongestionControlOption(tcpCongestionControlAlgorithm)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt2)

	opt3 := tcpip.TCPDelayEnabled(tcpDelayEnabled)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt3)

	sOpt := tcpip.TCPSACKEnabled(tcpSACKEnabled)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sOpt)

	mOpt := tcpip.TCPModerateReceiveBufferOption(tcpModerateReceiveBufferEnabled)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &mOpt)

	tr := tcpRecovery
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &tr)

	s.SetTransportProtocolHandler(tcp.ProtocolNumber, t.tcpForwarder().HandlePacket)

	s.SetTransportProtocolHandler(udp.ProtocolNumber, t.udpForwarder().HandlePacket)

	return t, nil
}

const (
	// defaultTimeToLive specifies the default TTL used by stack.
	defaultTimeToLive uint8 = 64

	// ipForwardingEnabled is the value used by stack to enable packet
	// forwarding between NICs.
	ipForwardingEnabled = true

	// icmpBurst is the default number of ICMP messages that can be sent in
	// a single burst.
	icmpBurst = 50

	// icmpLimit is the default maximum number of ICMP messages permitted
	// by this rate limiter.
	icmpLimit rate.Limit = 1000

	// tcpCongestionControl is the congestion control algorithm used by
	// stack. ccReno is the default option in gVisor stack.
	tcpCongestionControlAlgorithm = "cubic" // "reno" or "cubic"

	// tcpDelayEnabled is the value used by stack to enable or disable
	// tcp delay option. Disable Nagle's algorithm here by default.
	tcpDelayEnabled = false

	// tcpModerateReceiveBufferEnabled is the value used by stack to
	// enable or disable tcp receive buffer auto-tuning option.
	tcpModerateReceiveBufferEnabled = false

	// tcpSACKEnabled is the value used by stack to enable or disable
	// tcp selective ACK.
	tcpSACKEnabled = true

	// tcpRecovery is the loss detection algorithm used by TCP.
	tcpRecovery = tcpip.TCPRACKLossDetection
)
