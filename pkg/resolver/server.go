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
	observer []netapi.DNSObserver
	host     string
	closed   bool
}

// NewDNSServer optionally records DNS history of the local listeners with
// observer; intercepted requests bring their own trace.
func NewDNSServer(resolver netapi.Resolver, observer ...netapi.DNSObserver) *DNSServer {
	return &DNSServer{resolver: resolver, observer: observer, agent: server.NewServer("", resolver, observer...)}
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
	s.agent = server.NewServer(host, s.resolver, s.observer...)
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
		_ = req.Conn.Close()
		err := errors.New("DNS server is closed")
		req.Trace.Fail(netapi.DNSOutcomeDropped, netapi.DNSStageAdmission, "shutdown", err)
		req.Trace.Finish(err)
		return err
	}
	agent := s.agent
	s.mu.RUnlock()
	return agent.DoStream(ctx, req)
}

func (s *DNSServer) DoDatagram(ctx context.Context, req *netapi.DNSRawRequest) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		err := errors.New("DNS server is closed")
		req.Trace.Fail(netapi.DNSOutcomeDropped, netapi.DNSStageAdmission, "shutdown", err)
		req.Trace.Finish(err)
		return err
	}
	return s.agent.DoDatagram(ctx, req)
}
