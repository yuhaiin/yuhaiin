package resolver

import (
	"context"
	"errors"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// DNSServer owns listeners and intercepted DNS traffic independently of the
// resolver pipeline. The resolver is borrowed and closed by the application.
type DNSServer struct {
	mu       sync.RWMutex
	resolver netapi.Resolver
	agent    netapi.DNSAgent
	host     string
	closed   bool
}

func NewDNSServer(resolver netapi.Resolver) *DNSServer {
	return &DNSServer{resolver: resolver, agent: server.NewServer("", resolver)}
}

func (s *DNSServer) SetServer(host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.host == host {
		return
	}
	if err := s.agent.Close(); err != nil {
		log.Error("close DNS server failed", "err", err)
	}
	s.agent = server.NewServer(host, s.resolver)
	s.host = host
}

func (s *DNSServer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.agent.Close()
}

func (s *DNSServer) DoStream(ctx context.Context, req *netapi.DNSStreamRequest) error {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return errors.New("DNS server is closed")
	}
	agent := s.agent
	s.mu.RUnlock()
	return agent.DoStream(ctx, req)
}

func (s *DNSServer) DoDatagram(ctx context.Context, req *netapi.DNSRawRequest) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return errors.New("DNS server is closed")
	}
	return s.agent.DoDatagram(ctx, req)
}
