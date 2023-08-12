package resolver

import (
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

var _ netapi.DNSHandler = (*DnsServer)(nil)

type DnsServer struct {
	netapi.DNSHandler
	serverHost string
	resolver   netapi.Resolver
}

func NewDNSServer(resolver netapi.Resolver) *DnsServer {
	return &DnsServer{netapi.EmptyDNSServer, "", resolver}
}

func (a *DnsServer) Update(s *pc.Setting) {
	if a.serverHost == s.Dns.Server && a.DNSHandler != netapi.EmptyDNSServer {
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
