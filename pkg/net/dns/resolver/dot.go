package resolver

import (
	"crypto/tls"
)

func init() {
	Register("dot", NewDoT)
}

func NewDoT(config Config) (Transport, error) {
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
