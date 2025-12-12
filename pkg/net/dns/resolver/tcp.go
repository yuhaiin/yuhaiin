package resolver

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

func init() {
	Register(config.Type_tcp, NewTCP)
}

func NewTCP(config Config) (Transport, error) {
	return newTCP(config, "53", nil)
}

// ParseAddr
// host eg: cloudflare-dns.com, https://cloudflare-dns.com, 1.1.1.1:853
func ParseAddr(netType string, host, defaultPort string) (netapi.Address, error) {
	if i := strings.Index(host, "://"); i != -1 {
		host = host[i+3:]
	}

	if i := strings.IndexByte(host, '/'); i != -1 {
		host = host[:i]
	}

	_, _, err := net.SplitHostPort(host)
	if err != nil {
		var e *net.AddrError
		ok := errors.As(err, &e)
		if !ok || !strings.Contains(e.Err, "missing port in address") {
			if ok && strings.Contains(e.Err, "too many colons in address") {
				if _, er := netip.ParseAddr(host); er != nil {
					return nil, fmt.Errorf("split host port failed: %w", err)
				}
			}
		}

		host = net.JoinHostPort(host, defaultPort)
	}

	addr, err := netapi.ParseAddress(netType, host)
	if err != nil {
		return nil, fmt.Errorf("parse address failed: %w", err)
	}

	return addr, nil
}

func tcpDo(ctx context.Context, addr netapi.Address, config Config, tlsConfig *tls.Config, b *Request) (Response, error) {
	conn, err := config.Dialer.Conn(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}
	defer conn.Close()

	if tlsConfig != nil {
		conn = tls.Client(conn, tlsConfig)
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(5 * time.Second)
	}

	err = conn.SetDeadline(deadline)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("set deadline failed: %w", err)
	}

	// dns over tcp, prefix two bytes is request data's length
	err = pool.BinaryWriteUint16(conn, binary.BigEndian, uint16(len(b.Bytes())))
	if err != nil {
		return nil, fmt.Errorf("write data length failed: %w", err)
	}

	_, err = conn.Write(b.Bytes())
	if err != nil {
		return nil, fmt.Errorf("write data failed: %w", err)
	}

	var length uint16
	err = binary.Read(conn, binary.BigEndian, &length)
	if err != nil {
		return nil, fmt.Errorf("read data length from server failed: %w", err)
	}

	all := pool.GetBytes(int(length))
	_, err = io.ReadFull(conn, all)
	if err != nil {
		return nil, fmt.Errorf("read data from server failed: %w", err)
	}
	return BytesResponse(all), nil
}

func newTCP(config Config, defaultPort string, tlsConfig *tls.Config) (Transport, error) {
	addr, err := ParseAddr("tcp", config.Host, defaultPort)
	if err != nil {
		return nil, fmt.Errorf("parse addr failed: %w", err)
	}

	return TransportFunc(func(ctx context.Context, b *Request) (Response, error) {
		return tcpDo(ctx, addr, config, tlsConfig, b)
	}), nil
}
