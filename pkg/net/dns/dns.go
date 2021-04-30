package dns

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

type DNSType int

const (
	Normal DNSType = 1 << iota
	DNSOverHTTPS
	DNSOverTLS
)

type DNS interface {
	LookupIP(domain string) ([]net.IP, error)
	Resolver() *net.Resolver
}

func dnsHandle(domain string, subnet *net.IPNet,
	reqF func(reqData []byte) (body []byte, err error)) (DNS []net.IP, err error) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Recovering from panic in resolve DNS(%s) error is: %v \n", domain, r)
			err = fmt.Errorf("recovering from panic in resolve DNS(%s) error is: %v", domain, r)
		}
	}()
	req := createEDNSReq(domain, A, createEdnsClientSubnet(subnet))
	b, err := reqF(req)
	if err != nil {
		return nil, err
	}
	return Resolve(req, b)
}

func NewDNS(host string, dnsType DNSType, subnet *net.IPNet, p proxy.Proxy) DNS {
	switch dnsType {
	case DNSOverHTTPS:
		return NewDoH(host, subnet, p)
	case DNSOverTLS:
		return NewDoT(host, subnet, p)
	}
	return NewNormalDNS(host, subnet, p)
}

var _ DNS = (*NormalDNS)(nil)

type NormalDNS struct {
	DNS
	Server string
	Subnet *net.IPNet
	cache  *utils.LRU
	proxy  func(string) (net.PacketConn, error)
}

func NewNormalDNS(host string, subnet *net.IPNet, p proxy.Proxy) DNS {
	if subnet == nil {
		_, subnet, _ = net.ParseCIDR("0.0.0.0/0")
	}
	if p == nil {
		p = &proxy.DefaultProxy{}
	}

	return &NormalDNS{
		Server: host,
		Subnet: subnet,
		cache:  utils.NewLru(200, 20*time.Minute),
		proxy:  p.PacketConn,
	}
}

// LookupIP resolve domain return net.IP array
func (n *NormalDNS) LookupIP(domain string) (DNS []net.IP, err error) {
	if x, _ := n.cache.Load(domain); x != nil {
		return x.([]net.IP), nil
	}
	DNS, err = dnsHandle(domain, n.Subnet, func(data []byte) ([]byte, error) {
		return udpDial(data, n.Server, n.proxy)
	})
	if err != nil || len(DNS) == 0 {
		return nil, fmt.Errorf("normal resolve domain %s failed: %v", domain, err)
	}
	n.cache.Add(domain, DNS)
	return
}

func (n *NormalDNS) Resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.DialTimeout("udp", n.Server, time.Second*6)
		},
	}
}
func udpDial(req []byte, DNSServer string, proxy func(string) (net.PacketConn, error)) (data []byte, err error) {
	var b = *utils.BuffPool.Get().(*[]byte)
	defer utils.BuffPool.Put(&(b))

	addr, err := net.ResolveUDPAddr("udp", DNSServer)
	if err != nil {
		return nil, fmt.Errorf("resolve addr failed: %v", err)
	}

	var conn net.PacketConn
	if proxy != nil {
		conn, err = proxy(DNSServer)
	} else {
		conn, err = net.ListenPacket("udp", "")
	}
	if err != nil {
		return nil, fmt.Errorf("get packetConn failed: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err = conn.WriteTo(req, addr)
	if err != nil {
		return nil, err
	}

	n, _, err := conn.ReadFrom(b[:])
	return b[:n], err
}
