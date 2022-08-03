package router

import (
	"log"

	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

var _ server.DNSServer = (*dnsServer)(nil)

type dnsServer struct {
	server.DNSServer
	dnsserverHost string
	resolver      proxy.ResolverProxy
}

func newDNSServer(shunt proxy.ResolverProxy) *dnsServer {
	return &dnsServer{resolver: shunt, DNSServer: server.EmptyDNSServer}
}

func (a *dnsServer) Update(s *protoconfig.Setting) {
	if a.dnsserverHost == s.Dns.Server && a.DNSServer != server.EmptyDNSServer {
		return
	}

	if a.DNSServer != nil {
		if err := a.DNSServer.Close(); err != nil {
			log.Println("close dns server failed:", err)
		}
	}
	a.DNSServer = dns.NewDnsServer(s.Dns.Server, a.resolver)
	a.dnsserverHost = s.Dns.Server
}
