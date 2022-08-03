package router

import (
	"fmt"
	"log"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	idns "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

type fakedns struct {
	fake   *dns.Fake
	config *protoconfig.DnsSetting
	shunt  Shunt
}

func newFakedns(dialer Shunt) *fakedns {
	_, ipRange, _ := net.ParseCIDR("10.2.0.1/24")
	return &fakedns{fake: dns.NewFake(ipRange), shunt: dialer}
}

func (f *fakedns) Resolver(addr proxy.Address) idns.DNS {
	z := f.shunt.Resolver(addr)
	if f.config != nil && f.config.Fakedns {
		return dns.WrapFakeDNS(z, f.fake)
	}
	return z
}

func (f *fakedns) Update(c *protoconfig.Setting) {
	f.config = c.Dns

	_, ipRange, err := net.ParseCIDR(c.Dns.FakednsIpRange)
	if err != nil {
		log.Println("parse fakedns ip range failed:", err)
		return
	}

	f.fake = dns.NewFake(ipRange)
}

func getStringValue(key any, addr proxy.Address) string {
	m, _ := addr.GetMark(key)
	r, ok := m.(string)
	if !ok {
		return ""
	}

	return r
}

func (f *fakedns) Conn(addr proxy.Address) (net.Conn, error) {
	c, err := f.shunt.Conn(f.getAddr(addr))
	if err != nil {
		return nil, fmt.Errorf("connect tcp to %s(%s) failed: %s", addr, getStringValue("packageName", addr), err)
	}

	return c, nil
}

func (f *fakedns) PacketConn(addr proxy.Address) (net.PacketConn, error) {
	c, err := f.shunt.PacketConn(f.getAddr(addr))
	if err != nil {
		return nil, fmt.Errorf("connect udp to %s(%s) failed: %s", addr, getStringValue("packageName", addr), err)
	}
	return c, nil
}

const FAKEDNS_MARK = "FAKEDNS"

func (f *fakedns) getAddr(addr proxy.Address) proxy.Address {
	if f.config != nil && f.config.Fakedns && addr.Type() == proxy.IP {
		t, ok := f.fake.GetDomainFromIP(addr.Hostname())
		if ok {
			fakeip := addr.String()
			addr = proxy.ConvertFakeDNS(addr, t)
			addr.AddMark(FAKEDNS_MARK, fakeip)
		}
	}
	return addr
}
