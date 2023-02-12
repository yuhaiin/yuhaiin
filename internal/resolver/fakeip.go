package resolver

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	id "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
)

type Fakedns struct {
	enabled  bool
	fake     *dns.FakeDNS
	dialer   proxy.Proxy
	upstream id.DNS
	cacheDir string

	// current dns client(fake/upstream)
	id.DNS
}

func NewFakeDNS(cacheDir string, dialer proxy.Proxy, upstream id.DNS) *Fakedns {
	return &Fakedns{
		fake:     dns.NewFakeDNS(upstream, yerror.Ignore(netip.ParsePrefix("10.2.0.1/24"))),
		dialer:   dialer,
		upstream: upstream,
		DNS:      upstream,
		cacheDir: cacheDir,
	}
}

func (f *Fakedns) Close() error {
	if !f.enabled {
		return nil
	}

	cache := make(map[string]string)

	f.fake.LRU().Range(func(s1, s2 string) {
		cache[s1] = s2
	})

	data, err := json.Marshal(cache)
	if err != nil {
		return err
	}

	return os.WriteFile(f.cacheDir, data, os.ModePerm)
}

func (f *Fakedns) RecoveryCache() {
	if !f.enabled {
		return
	}
	data, err := os.ReadFile(f.cacheDir)
	if err != nil {
		return
	}

	cache := make(map[string]string)
	json.Unmarshal(data, &cache)

	lru := f.fake.LRU()

	for k, v := range cache {
		lru.Add(k, v)
	}
}

func (f *Fakedns) Update(c *pc.Setting) {
	f.Close()

	f.enabled = c.Dns.Fakedns

	ipRange, err := netip.ParsePrefix(c.Dns.FakednsIpRange)
	if err != nil {
		log.Errorln("parse fakedns ip range failed:", err)
		return
	}
	f.fake = dns.NewFakeDNS(f.upstream, ipRange)

	if f.enabled {
		f.DNS = f.fake
	} else {
		f.DNS = f.upstream
	}

	f.RecoveryCache()
}

func (f *Fakedns) Dispatch(addr proxy.Address) (proxy.Address, error) {
	return f.dialer.Dispatch(f.getAddr(addr))
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

	if f.enabled {
		c = &dispatchPacketConn{c, f.getAddr}
	}

	return c, nil
}

func (f *Fakedns) getAddr(addr proxy.Address) proxy.Address {
	if f.enabled && addr.Type() == proxy.IP {
		t, ok := f.fake.GetDomainFromIP(addr.Hostname())
		if ok {
			r := addr.OverrideHostname(t)
			r.WithValue(proxy.FakeIPKey{}, addr)
			r.WithValue(proxy.CurrentKey{}, r)
			return r
		}
	}
	return addr
}

type dispatchPacketConn struct {
	net.PacketConn
	dispatch func(proxy.Address) proxy.Address
}

func (f *dispatchPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	z, err := proxy.ParseSysAddr(addr)
	if err != nil {
		return 0, fmt.Errorf("parse addr failed: %w", err)
	}

	return f.PacketConn.WriteTo(b, f.dispatch(z))
}
