package fortinet

import (
	"context"
	"crypto/x509"
	"errors"
	"github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit"
	client "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/session"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

func init() {
	register.RegisterContractPoint("fortinet", func(c node.Fortinet, up netapi.Proxy) (netapi.Proxy, error) { return NewOutbound(c, up) })
}
func NewOutbound(c node.Fortinet, up netapi.Proxy) (netapi.Proxy, error) {
	host, port, err := vpnkit.ParseGateway(c.Gateway, 443)
	if err != nil {
		return nil, err
	}
	if c.Username == "" {
		return nil, errors.New("fortinet: username required")
	}
	var roots *x509.CertPool
	if c.CACertPEM != "" {
		roots, err = x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM([]byte(c.CACertPEM)) {
			return nil, errors.New("fortinet: invalid CA PEM")
		}
	}
	return vpnkit.NewOutbound("fortinet", func(ctx context.Context, tun string) (client.Session, client.Result, error) {
		s, res, e := Dial(ctx, Config{Server: host, Port: port, Username: c.Username, Password: c.Password,
			Realm: c.Realm, Token: c.Token, TOTPSecret: c.TOTPSecret, RootCAs: roots,
			Insecure: c.InsecureSkipVerify, NoDTLS: c.DisableDTLS || vpnkit.IsChained(up),
			TUNName: tun, DialContext: vpnkit.EndpointDialer(up)})
		return s, res, e
	})
}
