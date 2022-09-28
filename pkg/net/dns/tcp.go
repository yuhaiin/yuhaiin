package dns

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

func init() {
	Register(config.Dns_tcp, NewTCP)
}

var _ dns.DNS = (*tcp)(nil)

type tcp struct {
	host  proxy.Address
	proxy proxy.StreamProxy

	*client

	tls *tls.Config
}

func NewTCP(config Config) dns.DNS {
	return newTCP(config, "53")
}

func newTCP(config Config, defaultPort string) *tcp {
	host := config.Host
	if i := strings.Index(host, "://"); i != -1 {
		host = host[i+3:]
	}

	_, _, err := net.SplitHostPort(host)
	if e, ok := err.(*net.AddrError); ok {
		if strings.Contains(e.Err, "missing port in address") {
			host = net.JoinHostPort(host, defaultPort)
		}
	}

	addr, err := proxy.ParseAddress("tcp", host)
	if err != nil {
		log.Errorln(err)
		addr = proxy.EmptyAddr
	}
	d := &tcp{host: addr, proxy: config.Dialer}

	d.client = NewClient(config, func(b []byte) ([]byte, error) {
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
