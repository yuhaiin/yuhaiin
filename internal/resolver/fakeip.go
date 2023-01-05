package resolver

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	idns "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	pdns "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
)

type Fakedns struct {
	fake   *dns.NFakeDNS
	config *pdns.Config

	dialer         proxy.Proxy
	resolverDialer proxy.ResolverProxy
}

func NewFakeDNS(dialer proxy.Proxy, resolverProxy proxy.ResolverProxy) proxy.DialerResolverProxy {
	ipRange, _ := netip.ParsePrefix("10.2.0.1/24")
	return &Fakedns{fake: dns.NewNFakeDNS(ipRange), dialer: dialer, resolverDialer: resolverProxy}
}

func (f *Fakedns) Resolver(addr proxy.Address) idns.DNS {
	if f.config != nil && f.config.Fakedns {
		return dns.WrapFakeDNS(
			func(b []byte) ([]byte, error) { return f.resolverDialer.Resolver(addr).Do(b) },
			f.fake,
		)
	}

	return f.resolverDialer.Resolver(addr)
}

func (f *Fakedns) Update(c *protoconfig.Setting) {
	f.config = c.Dns

	ipRange, err := netip.ParsePrefix(c.Dns.FakednsIpRange)
	if err != nil {
		log.Errorln("parse fakedns ip range failed:", err)
		return
	}

	f.fake = dns.NewNFakeDNS(ipRange)
}

func (f *Fakedns) Conn(addr proxy.Address) (net.Conn, error) {
	c, err := f.dialer.Conn(f.getAddr(addr))
	if err != nil {
		return nil, fmt.Errorf("connect tcp to %s failed: %w", addr, err)
	}

	return c, nil
}

func (f *Fakedns) PacketConn(addr proxy.Address) (net.PacketConn, error) {
	c, err := f.dialer.PacketConn(f.getAddr(addr))
	if err != nil {
		return nil, fmt.Errorf("connect udp to %s failed: %w", addr, err)
	}

	if f.config != nil && f.config.Fakedns {
		c = &WrapAddressPacketConn{c, f.getAddr}
	}

	return c, nil
}

func (f *Fakedns) getAddr(addr proxy.Address) proxy.Address {
	if f.config != nil && f.config.Fakedns && addr.Type() == proxy.IP {
		t, ok := f.fake.GetDomainFromIP(addr.Hostname())
		if ok {
			return addr.OverrideHostname(t)
		}
	}
	return addr
}

type WrapAddressPacketConn struct {
	net.PacketConn
	ProcessAddress func(proxy.Address) proxy.Address
}

func (f *WrapAddressPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	z, err := proxy.ParseSysAddr(addr)
	if err != nil {
		return 0, fmt.Errorf("parse addr failed: %w", err)
	}

	z = f.ProcessAddress(z)

	return f.PacketConn.WriteTo(b, z)
}
