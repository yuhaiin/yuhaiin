package resolver

import (
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

var _ server.DNSServer = (*DnsServer)(nil)

type DnsServer struct {
	server.DNSServer
	dnsserverHost string
	resolver      proxy.ResolverProxy
}

func NewDNSServer(resolver proxy.ResolverProxy) server.DNSServer {
	return &DnsServer{server.EmptyDNSServer, "", resolver}
}

func (a *DnsServer) Update(s *protoconfig.Setting) {
	if a.dnsserverHost == s.Dns.Server && a.DNSServer != server.EmptyDNSServer {
		return
	}

	if a.DNSServer != nil {
		if err := a.DNSServer.Close(); err != nil {
			log.Errorln("close dns server failed:", err)
		}
	}

	a.DNSServer = dns.NewDnsServer(s.Dns.Server, a.resolver)
	a.dnsserverHost = s.Dns.Server
}
