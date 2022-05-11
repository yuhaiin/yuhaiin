package dns

import (
	"context"
	"fmt"
	"log"
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
	*client
	server string
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

	add, err := proxy.ParseAddress("udp", host)
	if err != nil {
		log.Println(err)
		add = proxy.EmptyAddr
	}

	return &udp{
		NewClient(subnet, func(req []byte) ([]byte, error) {
			var b = utils.GetBytes(utils.DefaultSize)
			defer utils.PutBytes(b)

			addr, err := proxy.ResolveIPAddress(add, nr.LookupIP)
			if err != nil {
				return nil, fmt.Errorf("resolve addr failed: %v", err)
			}

			conn, err := p.PacketConn(add)
			if err != nil {
				return nil, fmt.Errorf("get packetConn failed: %v", err)
			}
			defer conn.Close()

			err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if err != nil {
				return nil, fmt.Errorf("set read deadline failed: %v", err)
			}

			_, err = conn.WriteTo(req, addr.UDPAddr())
			if err != nil {
				return nil, err
			}

			err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if err != nil {
				return nil, fmt.Errorf("set read deadline failed: %v", err)
			}

			nn, _, err := conn.ReadFrom(b)
			return b[:nn], err
		}), host}
}

func (n *udp) Resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.DialTimeout("udp", n.server, time.Second*6)
		},
	}
}

func (n *udp) Close() error { return nil }
