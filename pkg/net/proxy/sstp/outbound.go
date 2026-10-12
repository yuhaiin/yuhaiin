package sstp

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
	register.RegisterContractPoint("sstp", func(c node.SSTP, up netapi.Proxy) (netapi.Proxy, error) { return NewOutbound(c, up) })
}
func NewOutbound(c node.SSTP, up netapi.Proxy) (netapi.Proxy, error) {
	host, port, err := vpnkit.ParseGateway(c.Gateway, 443)
	if err != nil {
		return nil, err
	}
	if c.Username == "" || c.Password == "" {
		return nil, errors.New("sstp: username/password required")
	}
	return vpnkit.NewOutbound("sstp", int(c.MTU), func(ctx context.Context, tun string) (client.Session, client.Result, error) {
		return Dial(ctx, Config{Server: host, Port: port, Username: c.Username, Password: c.Password,
			TUNName: tun, SkipVerify: c.InsecureSkipVerify, DialContext: vpnkit.EndpointDialer(up)})
	})
}
