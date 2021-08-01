package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

type DNS interface {
	LookupIP(domain string) ([]net.IP, error)
	Resolver() *net.Resolver
}

func reqAndHandle(domain string, subnet *net.IPNet, f func([]byte) ([]byte, error)) ([]net.IP, error) {
	var req []byte
	if subnet == nil {
		req = creatRequest(domain, A, false)
	} else {
		req = createEDNSReq(domain, A, createEdnsClientSubnet(subnet))
	}
	b, err := f(req)
	if err != nil {
		return nil, err
	}
	return Resolve(req, b)
}

var _ DNS = (*dns)(nil)

type dns struct {
	DNS
	Server string
	Subnet *net.IPNet
	cache  *utils.LRU
	proxy  proxy.Proxy
}

func NewDNS(host string, subnet *net.IPNet, p proxy.Proxy) DNS {
	if p == nil {
		p = &proxy.DefaultProxy{}
	}

	_, _, err := net.SplitHostPort(host)
	if e, ok := err.(*net.AddrError); ok {
		if strings.Contains(e.Err, "missing port in address") {
			host = net.JoinHostPort(host, "53")
		}
	}

	return &dns{
		Server: host,
		Subnet: subnet,
		cache:  utils.NewLru(200, 20*time.Minute),
		proxy:  p,
	}
}

// LookupIP resolve domain return net.IP array
func (n *dns) LookupIP(domain string) (DNS []net.IP, err error) {
	if x, _ := n.cache.Load(domain); x != nil {
		return x.([]net.IP), nil
	}
	DNS, err = reqAndHandle(domain, n.Subnet, n.udp)
	if err != nil || len(DNS) == 0 {
		return nil, fmt.Errorf("normal resolve domain %s failed: %v", domain, err)
	}
	n.cache.Add(domain, DNS)
	return
}

func (n *dns) Resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.DialTimeout("udp", n.Server, time.Second*6)
		},
	}
}

func (n *dns) udp(req []byte) (data []byte, err error) {
	var b = *utils.BuffPool.Get().(*[]byte)
	defer utils.BuffPool.Put(&(b))

	addr, err := net.ResolveUDPAddr("udp", n.Server)
	if err != nil {
		return nil, fmt.Errorf("resolve addr failed: %v", err)
	}

	conn, err := n.proxy.PacketConn(n.Server)
	if err != nil {
		return nil, fmt.Errorf("get packetConn failed: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err = conn.WriteTo(req, addr)
	if err != nil {
		return nil, err
	}

	nn, _, err := conn.ReadFrom(b)
	return b[:nn], err
}
