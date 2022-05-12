package dns

import (
	"crypto/tls"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
)

func NewDoT(host, servername string, subnet *net.IPNet, p proxy.StreamProxy) dns.DNS {
	d := newTCP(host, "853", subnet, p)
	if servername == "" {
		servername = d.host.Hostname()
	}
	d.tls = &tls.Config{ServerName: servername, ClientSessionCache: sessionCache}
	return d
}
