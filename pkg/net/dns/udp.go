package dns

import (
	"context"
	"fmt"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	pdns "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

func init() {
	Register(pdns.Type_udp, NewDoU)
	Register(pdns.Type_reserve, NewDoU)
}

func NewDoU(config Config) (dns.DNS, error) {
	addr, err := ParseAddr(config.Host, "53")
	if err != nil {
		return nil, fmt.Errorf("parse addr failed: %w", err)
	}

	return NewClient(config, func(req []byte) ([]byte, error) {
		var b = pool.GetBytes(8192)
		defer pool.PutBytes(b)

		addr := proxy.ParseAddressPort(addr.NetworkType(), addr.Hostname(), addr.Port())
		ctx, cancel := context.WithTimeout(context.TODO(), time.Second*15)
		defer cancel()
		addr.WithContext(ctx)

		conn, err := config.Dialer.PacketConn(addr)
		if err != nil {
			return nil, fmt.Errorf("get packetConn failed: %w", err)
		}
		defer conn.Close()

		err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if err != nil {
			return nil, fmt.Errorf("set read deadline failed: %w", err)
		}

		_, err = conn.WriteTo(req, addr)
		if err != nil {
			return nil, err
		}

		err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if err != nil {
			return nil, fmt.Errorf("set read deadline failed: %w", err)
		}

		nn, _, err := conn.ReadFrom(b)

		return b[:nn], err
	}), nil
}
