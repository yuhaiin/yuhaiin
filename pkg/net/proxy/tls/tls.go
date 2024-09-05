package tls

import (
	"context"
	"crypto/tls"
	"math/rand/v2"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
)

type Tls struct {
	netapi.EmptyDispatch

	dialer       netapi.Proxy
	tlsConfig    []*tls.Config
	configLength int
}

func init() {
	point.RegisterProtocol(NewClient)
}

func NewClient(c *protocol.Protocol_Tls) point.WrapProxy {
	return func(p netapi.Proxy) (netapi.Proxy, error) {
		var tlsConfigs []*tls.Config
		tls := point.ParseTLSConfig(c.Tls)
		if tls != nil {
			// if !tls.InsecureSkipVerify && tls.ServerName == "" {
			// 	tls.ServerName = c.Simple.GetHost()
			// }

			tlsConfigs = append(tlsConfigs, tls)

			if len(c.Tls.ServerNames) > 1 {
				for _, v := range c.Tls.ServerNames[1:] {
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
	listener.RegisterTransport(NewServer)
}

func NewServer(c *listener.Transport_Tls) func(netapi.Listener) (netapi.Listener, error) {
	config, err := listener.ParseTLS(c.Tls.Tls)
	if err != nil {
		return listener.ErrorTransportFunc(err)
	}

	return func(ii netapi.Listener) (netapi.Listener, error) {
		lis, err := ii.Stream(context.TODO())
		if err != nil {
			return nil, err
		}
		return netapi.NewListener(tls.NewListener(lis, config), ii), nil
	}
}
