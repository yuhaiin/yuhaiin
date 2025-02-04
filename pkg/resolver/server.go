package resolver

import (
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

var _ netapi.DNSServer = (*DnsServer)(nil)

type DnsServer struct {
	netapi.DNSServer
	resolver   netapi.Resolver
	serverHost string
}

func NewDNSServer(resolver netapi.Resolver) *DnsServer {
	return &DnsServer{netapi.EmptyDNSServer, resolver, ""}
}

func (a *DnsServer) Update(s *pc.Setting) {
	if a.serverHost == s.GetDns().GetServer() && a.DNSServer != netapi.EmptyDNSServer {
		return
	}

	if a.DNSServer != nil {
		if err := a.DNSServer.Close(); err != nil {
			log.Error("close dns server failed", "err", err)
		}
	}

	a.DNSServer = server.NewServer(s.GetDns().GetServer(), a.resolver)
	a.serverHost = s.GetDns().GetServer()
}
