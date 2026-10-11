package native

import (
	"fmt"
	"strings"
)

func (s *Session) occ() string {
	proto := "UDPv4"
	if s.cfg.Network == "tcp" {
		proto = "TCPv4_CLIENT"
	}
	return fmt.Sprintf("V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto %s,cipher %s,auth [null-digest],keysize 256,key-method 2,tls-client", proto, s.cfg.DataCiphers[0])
}
func (s *Session) peerInfo() string {
	return fmt.Sprintf("IV_VER=2.6.0\nIV_PLAT=yuhaiin\nIV_PROTO=2\nIV_NCP=2\nIV_CIPHERS=%s\n", strings.Join(s.cfg.DataCiphers, ":"))
}
