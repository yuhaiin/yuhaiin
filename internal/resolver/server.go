package resolver

import (
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	id "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

var _ server.DNSServer = (*DnsServer)(nil)

type DnsServer struct {
	server.DNSServer
	serverHost string
	resolver   id.DNS
}

func NewDNSServer(resolver id.DNS) server.DNSServer {
	return &DnsServer{server.EmptyDNSServer, "", resolver}
}

func (a *DnsServer) Update(s *pc.Setting) {
	if a.serverHost == s.Dns.Server && a.DNSServer != server.EmptyDNSServer {
		return
	}

	if a.DNSServer != nil {
		if err := a.DNSServer.Close(); err != nil {
			log.Errorln("close dns server failed:", err)
		}
	}

	a.DNSServer = dns.NewDnsServer(s.Dns.Server, a.resolver)
	a.serverHost = s.Dns.Server
}
