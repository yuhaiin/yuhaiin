package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	nr "github.com/Asutorufa/yuhaiin/pkg/net/utils/resolver"
)

var _ dns.DNS = (*udp)(nil)

type udp struct {
	Server string
	proxy  proxy.PacketProxy

	*client
}

func NewDoU(host string, subnet *net.IPNet, p proxy.PacketProxy) dns.DNS {
	if p == nil {
		p = direct.Default
	}

	_, _, err := net.SplitHostPort(host)
	if e, ok := err.(*net.AddrError); ok {
		if strings.Contains(e.Err, "missing port in address") {
			host = net.JoinHostPort(host, "53")
		}
	}

	d := &udp{
		Server: host,
		proxy:  p,
	}

	d.client = NewClient(subnet, d.udp)

	return d
}

func (n *udp) Resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.DialTimeout("udp", n.Server, time.Second*6)
		},
	}
}

func (n *udp) Close() error { return nil }

func (n *udp) udp(req []byte) (data []byte, err error) {
	var b = utils.GetBytes(utils.DefaultSize)
	defer utils.PutBytes(b)

	addr, err := nr.ResolveUDPAddr(n.Server)
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
