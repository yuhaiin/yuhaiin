package resolver

import (
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	idns "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	pdns "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
)

type Fakedns struct {
	fake   *dns.Fake
	config *pdns.Config

	dialer         proxy.Proxy
	resolverDialer proxy.ResolverProxy
}

func NewFakeDNS(dialer proxy.Proxy, resolverProxy proxy.ResolverProxy) proxy.DialerResolverProxy {
	_, ipRange, _ := net.ParseCIDR("10.2.0.1/24")
	return &Fakedns{fake: dns.NewFake(ipRange), dialer: dialer, resolverDialer: resolverProxy}
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

	_, ipRange, err := net.ParseCIDR(c.Dns.FakednsIpRange)
	if err != nil {
		log.Errorln("parse fakedns ip range failed:", err)
		return
	}

	f.fake = dns.NewFake(ipRange)
}

func (f *Fakedns) Conn(addr proxy.Address) (net.Conn, error) {
	c, err := f.dialer.Conn(f.getAddr(addr))
	if err != nil {
		return nil, fmt.Errorf("connect tcp to %s(%s) failed: %s",
			addr, proxy.GetMark(addr, tun.PACKAGE_MARK_KEY{}, ""), err)
	}

	return c, nil
}

func (f *Fakedns) PacketConn(addr proxy.Address) (net.PacketConn, error) {
	c, err := f.dialer.PacketConn(f.getAddr(addr))
	if err != nil {
		return nil, fmt.Errorf("connect udp to %s(%s) failed: %s",
			addr, proxy.GetMark(addr, tun.PACKAGE_MARK_KEY{}, ""), err)
	}

	return &WrapAddressPacketConn{c, f.getAddr}, nil
}

type FAKE_IP_MARK_KEY struct{}

func (FAKE_IP_MARK_KEY) String() string { return "Fake IP" }

func (f *Fakedns) getAddr(addr proxy.Address) proxy.Address {
	if f.config != nil && f.config.Fakedns && addr.Type() == proxy.IP {
		t, ok := f.fake.GetDomainFromIP(addr.Hostname())
		if ok {
			addr.WithValue(FAKE_IP_MARK_KEY{}, addr.String())
			addr = addr.OverrideHostname(t)
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
