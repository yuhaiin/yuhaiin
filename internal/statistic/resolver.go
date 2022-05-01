package statistic

import (
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"google.golang.org/protobuf/proto"
)

type remoteResolver struct {
	config *protoconfig.Dns
	dns    dns.DNS
	dialer proxy.Proxy
}

func newRemoteResolver(dialer proxy.Proxy) *remoteResolver {
	return &remoteResolver{
		dialer: dialer,
	}
}

func (r *remoteResolver) Update(c *protoconfig.Setting) {
	if proto.Equal(r.config, c.Dns.Remote) {
		return
	}

	r.config = c.Dns.Remote

	r.dns = getDNS(r.config, r.dialer)
}

func (r *remoteResolver) LookupIP(host string) ([]net.IP, error) {
	if r.dns == nil {
		return nil, fmt.Errorf("dns not initialized")
	}

	return r.dns.LookupIP(host)
}
