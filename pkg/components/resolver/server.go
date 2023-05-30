package resolver

import (
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

var _ proxy.DNSHandler = (*DnsServer)(nil)

type DnsServer struct {
	proxy.DNSHandler
	serverHost string
	resolver   proxy.Resolver
}

func NewDNSServer(resolver proxy.Resolver) *DnsServer {
	return &DnsServer{proxy.EmptyDNSServer, "", resolver}
}

func (a *DnsServer) Update(s *pc.Setting) {
	if a.serverHost == s.Dns.Server && a.DNSHandler != proxy.EmptyDNSServer {
		return
	}

	if a.DNSHandler != nil {
		if err := a.DNSHandler.Close(); err != nil {
			log.Error("close dns server failed", "err", err)
		}
	}

	a.DNSHandler = dns.NewDnsServer(s.Dns.Server, a.resolver)
	a.serverHost = s.Dns.Server
}
