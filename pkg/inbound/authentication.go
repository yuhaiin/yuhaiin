package inbound

import contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"

// Clear only the runtime copy. Persisted shared secrets survive switching back
// to legacy mode; a user-only listener never passes them to a protocol server.
func withoutLegacyAuthentication(p contract.Protocol) contract.Protocol {
	switch p.Type {
	case contract.ProtocolHTTP:
		p.HTTP = new(*p.HTTP)
		p.HTTP.Username, p.HTTP.Password = "", ""
	case contract.ProtocolSocks5:
		p.Socks5 = new(*p.Socks5)
		p.Socks5.Username, p.Socks5.Password = "", ""
	case contract.ProtocolMixed:
		p.Mixed = new(*p.Mixed)
		p.Mixed.Username, p.Mixed.Password = "", ""
	case contract.ProtocolYuubinsya:
		p.Yuubinsya = new(*p.Yuubinsya)
		p.Yuubinsya.Password = ""
	case contract.ProtocolHysteria2:
		p.Hysteria2 = new(*p.Hysteria2)
		p.Hysteria2.Auth = ""
	}
	return p
}
