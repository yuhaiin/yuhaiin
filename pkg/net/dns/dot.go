package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
)

var _ DNS = (*dot)(nil)

type dot struct {
	host         string
	servername   string
	subnet       *net.IPNet
	proxy        func(string) (net.Conn, error)
	sessionCache tls.ClientSessionCache
}

func NewDoT(host string, subnet *net.IPNet, p proxy.Proxy) DNS {
	if p == nil {
		p = &proxy.DefaultProxy{}
	}
	servername, _, err := net.SplitHostPort(host)
	if e, ok := err.(*net.AddrError); ok {
		if strings.Contains(e.Err, "missing port in address") {
			servername = host
			host = net.JoinHostPort(host, "853")
		}
	}

	hostname, port, _ := net.SplitHostPort(host)
	if net.ParseIP(hostname) == nil {
		i, err := net.LookupIP(hostname)
		if err != nil {
			i = []net.IP{net.ParseIP("1.1.1.1")}
		}
		host = net.JoinHostPort(i[0].String(), port)
	}

	return &dot{
		host:         host,
		subnet:       subnet,
		servername:   servername,
		sessionCache: tls.NewLRUClientSessionCache(0),
		proxy:        p.Conn,
	}
}

func (d *dot) LookupIP(domain string) ([]net.IP, error) {
	conn, err := d.proxy(d.host)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %v", err)
	}
	conn = tls.Client(conn, &tls.Config{
		ServerName:         d.servername,
		ClientSessionCache: d.sessionCache,
	})
	defer conn.Close()
	return reqAndHandle(domain, d.subnet, func(reqData []byte) (body []byte, err error) {
		length := len(reqData) // dns over tcp, prefix two bytes is request data's length
		reqData = append([]byte{byte(length >> 8), byte(length - ((length >> 8) << 8))}, reqData...)
		_, err = conn.Write(reqData)
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
}

func (d *dot) Resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := d.proxy(d.host)
			if err != nil {
				return nil, fmt.Errorf("tcp dial failed: %v", err)
			}
			conn = tls.Client(conn, &tls.Config{ServerName: d.servername, ClientSessionCache: d.sessionCache})
			return conn, nil
		},
	}
}
