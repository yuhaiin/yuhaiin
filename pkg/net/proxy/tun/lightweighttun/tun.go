package lightweighttun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
)

type server struct {
	stack     *lightweight.Stack
	options   *device.Opt
	handler   netapi.Handler
	addresses []netip.Prefix
	name      string
	listener  net.Listener
	once      sync.Once
	err       error
	wg        sync.WaitGroup
	streams   chan struct{}
}

var _ netapi.Accepter = (*server)(nil)

func Validate(o device.TunConfig) error {
	if o.Driver != "" && o.Driver != device.DriverChannel {
		return fmt.Errorf("lightweight: driver %q is unsupported; use channel", o.Driver)
	}
	return lightweight.ValidateConfig(lightweight.Config{OutputScheduler: trafficcontrol.SchedulerMode(o.OutputScheduler), MTU: int(o.MTU), CongestionControl: o.CongestionControl})
}
func stackConfig(o *device.Opt) lightweight.Config {
	var addresses []netip.Addr
	for _, a := range append(append([]netip.Prefix(nil), o.Inet4Address...), o.Inet6Address...) {
		addresses = append(addresses, a.Addr())
	}
	return lightweight.Config{OutputScheduler: trafficcontrol.SchedulerMode(o.Tun.OutputScheduler), Addresses: addresses, MTU: o.MTU, CongestionControl: o.Tun.CongestionControl, Promiscuous: true, ForwardUDP: true, ForwardPing: forwardPing}
}
func New(o *device.Opt) (netapi.Accepter, error) {
	if err := Validate(o.Tun); err != nil {
		return nil, err
	}
	if o.Handler == nil {
		return nil, errors.New("lightweight: nil inbound handler")
	}
	if o.Tun.MTU == 0 {
		o.Tun.MTU = 1500
	}
	o.MTU = int(o.Tun.MTU)
	d, err := device.OpenPacketWriter(o.Interface, o.MTU)
	if err != nil {
		return nil, err
	}
	d = device.ConfigureDarwinTUN(d, o.Interface, o.Tun.Platform.Darwin)
	o.Device = d
	p, err := NewPacketIO(d)
	if err != nil {
		_ = d.Close()
		return nil, err
	}
	stack, err := lightweight.New(stackConfig(o), p)
	if err != nil {
		_ = p.Close()
		return nil, err
	}
	l, err := stack.ListenTCP(netip.AddrPort{})
	if err != nil {
		_ = stack.Close()
		return nil, err
	}
	o.UnsetRoute, err = netlink.Route(o.Options)
	if err != nil {
		_ = l.Close()
		_ = stack.Close()
		if o.UnsetRoute != nil {
			o.UnsetRoute()
		}
		return nil, fmt.Errorf("install lightweight TUN routes: %w", err)
	}
	o.PostUp()
	s := &server{stack: stack, options: o, handler: o.Handler, addresses: append(append([]netip.Prefix(nil), o.Inet4Address...), o.Inet6Address...), listener: l, streams: make(chan struct{}, 8192)}
	s.wg.Go(s.tcpLoop)
	s.wg.Go(s.udpLoop)
	if forwardPing {
		for range pingWorkers {
			s.wg.Go(s.pingLoop)
		}
	}
	return s, nil
}

// NewFromStack shares the normal TCP/UDP proxy handler with non-TUN packet
// sources such as a WireGuard listener. The caller retains ownership of the
// packet device; closing the accepter closes the lightweight stack.
func NewFromStack(stack *lightweight.Stack, handler netapi.Handler, addresses []netip.Prefix, name string) (netapi.Accepter, error) {
	if stack == nil || handler == nil {
		return nil, errors.New("lightweight: missing stack or inbound handler")
	}
	l, err := stack.ListenTCP(netip.AddrPort{})
	if err != nil {
		return nil, err
	}
	s := &server{stack: stack, handler: handler, addresses: append([]netip.Prefix(nil), addresses...), name: name, listener: l, streams: make(chan struct{}, 8192)}
	s.wg.Go(s.tcpLoop)
	s.wg.Go(s.udpLoop)
	return s, nil
}

func (s *server) TrafficControlQueue() (trafficcontrol.FairStats, bool) {
	return s.stack.TrafficControlQueue()
}

func (s *server) Interface() string {
	if s.options != nil {
		return s.options.Interface.Name
	}
	return s.name
}
func (s *server) Close() error {
	s.once.Do(func() {
		s.err = s.stack.Close()
		s.wg.Wait()
		if s.options != nil {
			s.options.PostDown()
		}
	})
	return s.err
}
func (s *server) flowHandler() netapi.Handler {
	if s.handler != nil {
		return s.handler
	}
	// Legacy constructors and package tests pass the Handler through Opt.
	if s.options != nil {
		return s.options.Handler
	}
	return nil
}

func (s *server) isDNS(a netip.AddrPort) bool {
	if a.Port() != 53 {
		return false
	}
	addresses := s.addresses
	if len(addresses) == 0 && s.options != nil {
		addresses = append(append([]netip.Prefix(nil), s.options.Inet4Address...), s.options.Inet6Address...)
	}
	for _, p := range addresses {
		if a.Addr() == p.Addr() || a.Addr() == p.Addr().Next() {
			return true
		}
	}
	return false
}
func (s *server) tcpLoop() {
	for {
		c, err := s.listener.Accept()
		if err != nil {
			return
		}
		dst := c.LocalAddr().(*net.TCPAddr).AddrPort()
		select {
		case s.streams <- struct{}{}:
			s.wg.Go(func() {
				defer func() { <-s.streams }()
				defer c.Close()
				s.flowHandler().HandleStream(&netapi.StreamMeta{Source: c.RemoteAddr(), Destination: c.LocalAddr(), Src: c, Address: netapi.ParseNetipAddrPort("tcp", dst), DnsRequest: s.isDNS(dst)})
			})
		case <-s.stack.Done():
			_ = c.Close()
			return
		default:
			_ = c.Close()
		}
	}
}
func (s *server) udpLoop() {
	for {
		d, err := s.stack.ReceiveUDP(context.Background())
		if err != nil {
			return
		}
		// ReceiveUDP transfers its allocation; netapi.Packet owns its final release.
		s.flowHandler().HandlePacket(netapi.NewPacket(net.UDPAddrFromAddrPort(d.Source), netapi.ParseNetipAddrPort("udp", d.Destination), d.Payload, netapi.WriteBackFunc(func(b []byte, addr net.Addr) (int, error) {
			var source netip.AddrPort
			switch addr := addr.(type) {
			case netapi.IPAddress:
				source = addr.AddrPort()
			case *net.UDPAddr:
				if addr != nil {
					source = addr.AddrPort()
				}
			}
			if !source.IsValid() {
				return 0, fmt.Errorf("%w: lightweight UDP invalid reply address %T (client %s, request destination %s)", netapi.ErrUndeliverableDatagram, addr, d.Source, d.Destination)
			}
			n, err := s.stack.WriteUDP(source, d.Source, b)
			if err != nil {
				err = fmt.Errorf("lightweight UDP reply source=%s client=%s request-destination=%s: %w", source, d.Source, d.Destination, err)
				if errors.Is(err, lightweight.ErrMalformed) || errors.Is(err, lightweight.ErrMTU) || errors.Is(err, lightweight.ErrLimit) {
					// One unusable datagram must not poison the outbound NAT socket.
					return n, fmt.Errorf("%w: %w", netapi.ErrUndeliverableDatagram, err)
				}
			}
			return n, err
		}), netapi.WithDNSRequest(s.isDNS(d.Destination))))
	}
}
