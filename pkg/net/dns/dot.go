package dns

import (
	"crypto/tls"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
)

func NewDoT(host string, subnet *net.IPNet, p proxy.StreamProxy) dns.DNS {
	d := newTCP(host, "853", subnet, p)
	d.tls = &tls.Config{ServerName: d.host.Hostname(), ClientSessionCache: sessionCache}
	return d
}
