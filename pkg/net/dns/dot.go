package dns

import (
	"crypto/tls"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

func init() {
	Register(config.Dns_dot, func(c dns.Config, p proxy.Proxy) dns.DNS { return NewDoT(c, p) })
}

func NewDoT(config dns.Config, p proxy.StreamProxy) dns.DNS {
	d := newTCP(config, "853", p)
	if config.Servername == "" {
		config.Servername = d.host.Hostname()
	}
	d.tls = &tls.Config{ServerName: config.Servername}
	return d
}
