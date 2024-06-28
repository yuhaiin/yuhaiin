package dns

import (
	"crypto/tls"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
)

func init() {
	Register(dns.Type_dot, NewDoT)
}

func NewDoT(config Config) (netapi.Resolver, error) {
	tlsConfig := &tls.Config{}
	d, err := newTCP(config, "853", tlsConfig)
	if err != nil {
		return nil, err
	}
	if config.Servername == "" {
		addr, err := ParseAddr("tcp", config.Host, "853")
		if err != nil {
			return nil, err
		}
		config.Servername = addr.Hostname()
	}
	tlsConfig.ServerName = config.Servername
	return d, nil
}
