package tls

import (
	"context"
	"crypto/tls"
	"math/rand"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
)

type Tls struct {
	netapi.EmptyDispatch

	tlsConfig   *tls.Config
	serverNames []string
	dialer      netapi.Proxy
}

func New(c *protocol.Protocol_Tls) protocol.WrapProxy {
	return func(p netapi.Proxy) (netapi.Proxy, error) {
		var serverNames []string
		tls := protocol.ParseTLSConfig(c.Tls)
		if tls != nil {
			// if !tls.InsecureSkipVerify && tls.ServerName == "" {
			// 	tls.ServerName = c.Simple.GetHost()
			// }
			serverNames = c.Tls.ServerNames
		}

		return &Tls{
			tlsConfig:   tls,
			serverNames: serverNames,
			dialer:      p,
		}, nil
	}
}

func (t *Tls) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	c, err := t.dialer.Conn(ctx, addr)
	if err != nil {
		return nil, err
	}

	if t.tlsConfig == nil {
		return c, nil
	}

	tlsConfig := t.tlsConfig
	if sl := len(t.serverNames); sl > 1 {
		tlsConfig = tlsConfig.Clone()
		tlsConfig.ServerName = t.serverNames[rand.Intn(sl)]
	}
	return tls.Client(c, tlsConfig), nil
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
		return listener.NewWrapListener(tls.NewListener(lis, config), ii), nil
	}
}
