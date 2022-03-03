package direct

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
)

type direct struct {
	dialer   *net.Dialer
	listener *net.ListenConfig

	lookup func(host string) ([]net.IP, error)
}

type Option func(*direct)

func WithLookup(f func(host string) ([]net.IP, error)) Option {
	return func(d *direct) {
		d.lookup = f
	}
}

func NewDirect(o ...Option) proxy.Proxy {
	d := &direct{
		dialer: &net.Dialer{
			Timeout: time.Second * 10,
		},
		listener: &net.ListenConfig{},
	}

	for _, opt := range o {
		opt(d)
	}

	if d.lookup == nil {
		d.lookup = net.LookupIP
	}

	return d
}

var _ error = (errors)(nil)

type errors []error

func (e errors) Error() string {
	var es = []error(e)
	return fmt.Sprintln(es)
}

func (d *direct) Conn(s string) (net.Conn, error) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}

	var ips []net.IP

	if i := net.ParseIP(s); i != nil {
		ips = append(ips, i)
	} else if ips, err = d.lookup(h); err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}

	var errs errors
	for _, ip := range ips {
		conn, err := d.dialer.Dial("tcp", net.JoinHostPort(ip.String(), p))
		if err != nil {
			errs = append(errs, err)
			continue
		}

		// logasfmt.Println("use ip:", ip.String())

		return conn, nil
	}

	return nil, errs
}

func (d *direct) PacketConn(string) (net.PacketConn, error) {
	return d.listener.ListenPacket(context.TODO(), "udp", "")
}
