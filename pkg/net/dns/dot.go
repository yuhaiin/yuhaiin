package dns

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
)

var _ DNS = (*dot)(nil)

type dot struct {
	host         string
	servername   string
	proxy        proxy.StreamProxy
	sessionCache tls.ClientSessionCache

	*client

	conn net.Conn
	lock sync.Mutex
}

func NewDoT(host string, subnet *net.IPNet, p proxy.StreamProxy) DNS {
	if p == nil {
		p = &proxy.Default{}
	}

	if i := strings.Index(host, "://"); i != -1 {
		host = host[i+3:]
	}

	servername, _, err := net.SplitHostPort(host)
	if e, ok := err.(*net.AddrError); ok {
		if strings.Contains(e.Err, "missing port in address") {
			servername = host
			host = net.JoinHostPort(host, "853")
		}
	}

	d := &dot{
		host:         host,
		servername:   servername,
		sessionCache: tls.NewLRUClientSessionCache(0),
		proxy:        p,
	}

	d.client = NewClient(subnet, func(b []byte) ([]byte, error) {
		// conn, err := d.proxy.Conn(d.host)
		// if err != nil {
		// 	return nil, fmt.Errorf("tcp dial failed: %v", err)
		// }
		// conn = tls.Client(conn, &tls.Config{ServerName: d.servername, ClientSessionCache: d.sessionCache})
		// defer conn.Close()

		d.lock.Lock()
		defer d.lock.Unlock()

		length := len(b) // dns over tcp, prefix two bytes is request data's length
		b = append([]byte{byte(length >> 8), byte(length - ((length >> 8) << 8))}, b...)

	_retry:
		err := d.initConn()
		if err != nil {
			return nil, err
		}

		_, err = d.conn.Write(b)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				d.conn.Close()
				d.conn = nil
				goto _retry
			}
			return nil, fmt.Errorf("write data failed: %v", err)
		}

		leg := make([]byte, 2)
		_, err = d.conn.Read(leg)
		if err != nil {
			return nil, fmt.Errorf("read data length from server failed %v", err)
		}
		all := make([]byte, int(leg[0])<<8+int(leg[1]))
		n, err := d.conn.Read(all)
		if err != nil {
			return nil, fmt.Errorf("read data from server failed: %v", err)
		}
		return all[:n], err
	})

	return d
}

func (d *dot) Close() error {
	if d.conn != nil {
		return d.conn.Close()
	}

	return nil
}

func (d *dot) initConn() error {
	if d.conn != nil {
		return nil
	}
	conn, err := d.proxy.Conn(d.host)
	if err != nil {
		return fmt.Errorf("tcp dial failed: %v", err)
	}

	d.conn = tls.Client(conn, &tls.Config{ServerName: d.servername, ClientSessionCache: d.sessionCache})
	return nil
}

func (d *dot) Resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := d.proxy.Conn(d.host)
			if err != nil {
				return nil, fmt.Errorf("tcp dial failed: %v", err)
			}
			conn = tls.Client(conn, &tls.Config{ServerName: d.servername, ClientSessionCache: d.sessionCache})
			return conn, nil
		},
	}
}
