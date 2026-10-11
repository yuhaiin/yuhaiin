package ikev2

import (
	"context"
	"errors"
	"github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit"
	client "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/session"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

func init() {
	register.RegisterContractPoint("ikev2", func(c node.IKEv2, up netapi.Proxy) (netapi.Proxy, error) { return NewOutbound(c, up) })
}
func NewOutbound(c node.IKEv2, up netapi.Proxy) (netapi.Proxy, error) {
	if vpnkit.IsChained(up) && !c.TCP {
		return nil, errors.New("ikev2: UDP NAT-T through upstream is unsupported; select RFC 8229 TCP encapsulation")
	}
	port := 500
	if c.TCP {
		port = 4500
	}
	host, p, err := vpnkit.ParseGateway(c.Gateway, port)
	if err != nil {
		return nil, err
	}
	if c.LocalID == "" || c.PSK == "" {
		return nil, errors.New("ikev2: local ID and PSK are required")
	}
	return vpnkit.NewOutbound("ikev2", int(c.MTU), func(ctx context.Context, tun string) (client.Session, client.Result, error) {
		return Dial(ctx, Config{Server: host, Port: p, LocalID: c.LocalID, ServerID: c.ServerID,
			PSK: c.PSK, EAPUser: c.Username, EAPPassword: c.Password, TCP: c.TCP,
			TUNName: tun, DialContext: vpnkit.EndpointDialer(up)})
	})
}
