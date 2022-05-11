package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
)

var _ dns.DNS = (*tcp)(nil)

var sessionCache = tls.NewLRUClientSessionCache(128)

type tcp struct {
	host  string
	proxy proxy.StreamProxy

	*client

	tls *tls.Config
}

func NewTCP(host string, subnet *net.IPNet, p proxy.StreamProxy) dns.DNS {
	return newTCP(host, "53", subnet, p)
}

func newTCP(host, defaultPort string, subnet *net.IPNet, p proxy.StreamProxy) *tcp {
	if p == nil {
		p = direct.Default
	}

	if i := strings.Index(host, "://"); i != -1 {
		host = host[i+3:]
	}

	_, _, err := net.SplitHostPort(host)
	if e, ok := err.(*net.AddrError); ok {
		if strings.Contains(e.Err, "missing port in address") {
			host = net.JoinHostPort(host, defaultPort)
		}
	}

	d := &tcp{
		host:  host,
		proxy: p,
	}

	d.client = NewClient(subnet, func(b []byte) ([]byte, error) {
		length := len(b) // dns over tcp, prefix two bytes is request data's length
		b = append([]byte{byte(length >> 8), byte(length - ((length >> 8) << 8))}, b...)

		conn, err := d.proxy.Conn(d.host)
		if err != nil {
			return nil, fmt.Errorf("tcp dial failed: %v", err)
		}
		defer conn.Close()

		if d.tls != nil {
			conn = tls.Client(conn, d.tls)
		}

		_, err = conn.Write(b)
		if err != nil {
			return nil, fmt.Errorf("write data failed: %v", err)
		}

		leg := make([]byte, 2)
		_, err = conn.Read(leg)
		if err != nil {
			return nil, fmt.Errorf("read data length from server failed %v", err)
		}
		all := make([]byte, int(leg[0])<<8+int(leg[1]))
		n, err := conn.Read(all)
		if err != nil {
			return nil, fmt.Errorf("read data from server failed: %v", err)
		}
		return all[:n], err
	})

	return d
}

func (d *tcp) Close() error { return nil }

func (d *tcp) Resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := d.proxy.Conn(d.host)
			if err != nil {
				return nil, fmt.Errorf("tcp dial failed: %v", err)
			}

			if d.tls != nil {
				conn = tls.Client(conn, d.tls)
			}

			return conn, nil
		},
	}
}
