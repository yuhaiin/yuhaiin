package tls

import (
	"context"
	"crypto/tls"
	"math/rand/v2"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

type Tls struct {
	netapi.EmptyDispatch

	dialer       netapi.Proxy
	tlsConfig    []*tls.Config
	configLength int
}

func init() {
	register.RegisterPoint(NewClient)
}

func NewClient(c *protocol.TlsConfig, p netapi.Proxy) (netapi.Proxy, error) {
	var tlsConfigs []*tls.Config
	tls := register.ParseTLSConfig(c)
	if tls != nil {
		// if !tls.InsecureSkipVerify && tls.ServerName == "" {
		// 	tls.ServerName = c.Simple.GetHost()
		// }

		tlsConfigs = append(tlsConfigs, tls)

		if len(c.GetServerNames()) > 1 {
			for _, v := range c.GetServerNames()[1:] {
				tc := tls.Clone()
				tc.ServerName = v

				tlsConfigs = append(tlsConfigs, tc)
			}
		}
	}

	if len(tlsConfigs) == 0 {
		return p, nil
	}

	return &Tls{
		tlsConfig:    tlsConfigs,
		dialer:       p,
		configLength: len(tlsConfigs),
	}, nil
}

func (t *Tls) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	c, err := t.dialer.Conn(ctx, addr)
	if err != nil {
		return nil, err
	}

	return tls.Client(c, t.tlsConfig[rand.IntN(t.configLength)]), nil
}

func (t *Tls) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	return t.dialer.PacketConn(ctx, addr)
}

func init() {
	register.RegisterTransport(NewServer)
}

func NewServer(c *listener.Tls, ii netapi.Listener) (netapi.Listener, error) {
	config, err := register.ParseTLS(c.GetTls())
	if err != nil {
		return nil, err
	}

	lis, err := ii.Stream(context.TODO())
	if err != nil {
		return nil, err
	}
	return netapi.NewListener(tls.NewListener(lis, config), ii), nil
}
