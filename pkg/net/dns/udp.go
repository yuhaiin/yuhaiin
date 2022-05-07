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

var _ DNS = (*dns)(nil)

type dns struct {
	Server string
	proxy  proxy.PacketProxy

	*client
}

func NewDNS(host string, subnet *net.IPNet, p proxy.PacketProxy) DNS {
	if p == nil {
		p = &proxy.Default{}
	}

	_, _, err := net.SplitHostPort(host)
	if e, ok := err.(*net.AddrError); ok {
		if strings.Contains(e.Err, "missing port in address") {
			host = net.JoinHostPort(host, "53")
		}
	}
	if i := net.ParseIP(host); i != nil {
		host = net.JoinHostPort(host, "53")
	}

	d := &dns{
		Server: host,
		proxy:  p,
	}

	d.client = NewClient(subnet, d.udp)

	return d
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
	var b = utils.GetBytes(utils.DefaultSize)
	defer utils.PutBytes(b)

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
