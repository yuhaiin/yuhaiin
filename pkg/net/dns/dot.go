package dns

import (
	"crypto/tls"

	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
)

func init() {
	Register(dns.Type_dot, NewDoT)
}

func NewDoT(config Config) (proxy.Resolver, error) {
	tlsConfig := &tls.Config{}
	d, err := newTCP(config, "853", tlsConfig)
	if err != nil {
		return nil, err
	}
	if config.Servername == "" {
		addr, err := ParseAddr(statistic.Type_tcp, config.Host, "853")
		if err != nil {
			return nil, err
		}
		config.Servername = addr.Hostname()
	}
	tlsConfig.ServerName = config.Servername
	return d, nil
}
