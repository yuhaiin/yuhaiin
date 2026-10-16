package lightweighttun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

type server struct {
	stack    *lightweight.Stack
	options  *device.Opt
	listener net.Listener
	once     sync.Once
	err      error
	wg       sync.WaitGroup
	streams  chan struct{}
}

var _ netapi.Accepter = (*server)(nil)

func Validate(o device.TunConfig) error {
	if o.Driver != "" && o.Driver != device.DriverChannel {
		return fmt.Errorf("lightweight: driver %q is unsupported; use channel", o.Driver)
	}
	return lightweight.ValidateConfig(lightweight.Config{MTU: int(o.MTU), CongestionControl: o.CongestionControl})
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
	o.Device = d
	p, err := newPacketIO(d)
	if err != nil {
		_ = d.Close()
		return nil, err
	}
	var addresses []netip.Addr
	for _, a := range append(append([]netip.Prefix(nil), o.Inet4Address...), o.Inet6Address...) {
		addresses = append(addresses, a.Addr())
	}
	stack, err := lightweight.New(lightweight.Config{Addresses: addresses, MTU: o.MTU, CongestionControl: o.Tun.CongestionControl, Promiscuous: true, ForwardUDP: true}, p)
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
	s := &server{stack: stack, options: o, listener: l, streams: make(chan struct{}, 8192)}
	s.wg.Go(s.tcpLoop)
	s.wg.Go(s.udpLoop)
	return s, nil
}
func (s *server) Interface() string { return s.options.Interface.Name }
func (s *server) Close() error {
	s.once.Do(func() { s.err = s.stack.Close(); s.wg.Wait(); s.options.PostDown() })
	return s.err
}
func (s *server) isDNS(a netip.AddrPort) bool {
	if a.Port() != 53 {
		return false
	}
	for _, p := range append(append([]netip.Prefix(nil), s.options.Inet4Address...), s.options.Inet6Address...) {
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
				s.options.HandleStream(&netapi.StreamMeta{Source: c.RemoteAddr(), Destination: c.LocalAddr(), Src: c, Address: netapi.ParseNetipAddrPort("tcp", dst), DnsRequest: s.isDNS(dst)})
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
		payload := pool.Clone(d.Payload)
		s.options.HandlePacket(netapi.NewPacket(net.UDPAddrFromAddrPort(d.Source), netapi.ParseNetipAddrPort("udp", d.Destination), payload, netapi.WriteBackFunc(func(b []byte, addr net.Addr) (int, error) {
			source, ok := addr.(*net.UDPAddr)
			if !ok || source == nil {
				return 0, fmt.Errorf("lightweight: invalid UDP reply address %T", addr)
			}
			n, err := s.stack.WriteUDP(source.AddrPort(), d.Source, b)
			if err != nil {
				log.Debug("lightweight UDP writeback failed", "err", err)
			}
			return n, err
		}), netapi.WithDNSRequest(s.isDNS(d.Destination))))
	}
}
