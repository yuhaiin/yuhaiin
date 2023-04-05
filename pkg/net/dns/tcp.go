package dns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	pdns "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
)

func init() {
	Register(pdns.Type_tcp, NewTCP)
}

func NewTCP(config Config) (dns.DNS, error) {
	return newTCP(config, "53", nil)
}

// ParseAddr
// host eg: cloudflare-dns.com, https://cloudflare-dns.com, 1.1.1.1:853
func ParseAddr(netType statistic.Type, host, defaultPort string) (proxy.Address, error) {
	if i := strings.Index(host, "://"); i != -1 {
		host = host[i+3:]
	}

	if i := strings.IndexByte(host, '/'); i != -1 {
		host = host[:i]
	}

	_, _, err := net.SplitHostPort(host)
	if err != nil {
		e, ok := err.(*net.AddrError)
		if !ok || !strings.Contains(e.Err, "missing port in address") {
			if ok && strings.Contains(e.Err, "too many colons in address") {
				if _, er := netip.ParseAddr(host); er != nil {
					return nil, fmt.Errorf("split host port failed: %w", err)
				}
			}
		}

		host = net.JoinHostPort(host, defaultPort)
	}

	addr, err := proxy.ParseAddress(netType, host)
	if err != nil {
		return nil, fmt.Errorf("parse address failed: %w", err)
	}

	return addr, nil
}

func newTCP(config Config, defaultPort string, tlsConfig *tls.Config) (*client, error) {
	addr, err := ParseAddr(statistic.Type_tcp, config.Host, defaultPort)
	if err != nil {
		return nil, fmt.Errorf("parse addr failed: %w", err)
	}

	return NewClient(config, func(ctx context.Context, b []byte) ([]byte, error) {
		conn, err := config.Dialer.Conn(ctx, addr)
		if err != nil {
			return nil, fmt.Errorf("tcp dial failed: %w", err)
		}
		defer conn.Close()

		if tlsConfig != nil {
			conn = tls.Client(conn, tlsConfig)
		}

		// dns over tcp, prefix two bytes is request data's length
		err = binary.Write(conn, binary.BigEndian, uint16(len(b)))
		if err != nil {
			return nil, fmt.Errorf("write data length failed: %w", err)
		}

		_, err = conn.Write(b)
		if err != nil {
			return nil, fmt.Errorf("write data failed: %w", err)
		}

		var length uint16
		err = binary.Read(conn, binary.BigEndian, &length)
		if err != nil {
			return nil, fmt.Errorf("read data length from server failed: %w", err)
		}

		all := make([]byte, length)
		n, err := conn.Read(all)
		if err != nil {
			return nil, fmt.Errorf("read data from server failed: %w", err)
		}
		return all[:n], err
	}), nil
}
