package resolver

import (
	"context"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

var _ netapi.DNSServer = (*DnsServer)(nil)

type DnsServer struct {
	ds         netapi.DNSServer
	mu         sync.RWMutex
	resolver   netapi.Resolver
	serverHost string
}

func NewDNSServer(resolver netapi.Resolver) *DnsServer {
	return &DnsServer{
		ds:       server.NewServer("", resolver),
		resolver: resolver,
	}
}

func (a *DnsServer) SetServer(s string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.serverHost == s {
		return
	}

	if err := a.ds.Close(); err != nil {
		log.Error("close dns server failed", "err", err)
	}

	a.ds = server.NewServer(s, a.resolver)
	a.serverHost = s
}

func (a *DnsServer) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ds.Close()
}

func (a *DnsServer) DoStream(ctx context.Context, req *netapi.DNSStreamRequest) error {
	a.mu.RLock()
	ds := a.ds
	a.mu.RUnlock()
	return ds.DoStream(ctx, req)
}

func (a *DnsServer) Do(ctx context.Context, req *netapi.DNSRawRequest) error {
	a.mu.RLock()
	ds := a.ds
	a.mu.RUnlock()
	return ds.Do(ctx, req)
}
