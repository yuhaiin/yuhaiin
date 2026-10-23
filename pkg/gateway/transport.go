package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
)

// Selection pins the result of the existing Route/NodeRuntime selection for one
// HTTP request. Identity changes when the selected proxy instance changes.
type Selection struct {
	Label             string
	Identity          string
	TrafficScope      string
	TrafficGeneration *proxyauth.Identity
	Proxy             netapi.Proxy
	Destination       netapi.Address
}

type SelectOutbound func(context.Context, netapi.Address, route.Target) (Selection, error)

func ProxyIdentity(proxy netapi.Proxy) string {
	return netapi.ProxyIdentity(proxy)
}

type transportKey struct {
	identity, destination, origin, serverName, trust string
	trafficScope                                     string
	trafficGeneration                                *proxyauth.Identity
	connectMS, idleMS, requestMS, maxConns           int
}
type transportEntry struct {
	transport *http.Transport
	used      uint64
	refs      int
	retired   bool
}

// TransportPool bounds idle pool ownership. Evicted transports drain active
// streams and close their idle connections when the last borrower returns.
type TransportPool struct {
	mu       sync.Mutex
	entries  map[transportKey]*transportEntry
	clock    uint64
	capacity int
	closed   bool
}

func NewTransportPool(capacity int) *TransportPool {
	return &TransportPool{entries: make(map[transportKey]*transportEntry), capacity: max(capacity, 1)}
}

func (p *TransportPool) borrow(s Selection, origin string, u contract.Upstream) (*http.Transport, func(), error) {
	if s.Proxy == nil || s.Destination == nil || s.Identity == "" {
		return nil, nil, errors.New("outbound selection is incomplete")
	}
	key := transportKey{identity: s.Identity, destination: s.Destination.String(), origin: origin, serverName: u.ServerName, trust: u.TrustPEM, trafficScope: s.TrafficScope, trafficGeneration: s.TrafficGeneration, connectMS: u.ConnectTimeoutMS, idleMS: u.IdleTimeoutMS, requestMS: u.RequestTimeoutMS, maxConns: u.MaxConnections}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clock++
	e := p.entries[key]
	if e == nil {
		config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.ServerName}
		if u.TrustPEM != "" {
			roots, err := x509.SystemCertPool()
			if err != nil {
				roots = x509.NewCertPool()
			}
			if !roots.AppendCertsFromPEM([]byte(u.TrustPEM)) {
				return nil, nil, errors.New("upstream trust contains no certificates")
			}
			config.RootCAs = roots
		}
		tr := &http.Transport{
			Proxy: nil, ForceAttemptHTTP2: true, TLSClientConfig: config,
			MaxIdleConns: 64, MaxIdleConnsPerHost: 16, MaxConnsPerHost: u.MaxConnections,
			IdleConnTimeout: durationMS(u.IdleTimeoutMS, 90*time.Second), TLSHandshakeTimeout: 10 * time.Second,
			ResponseHeaderTimeout: durationMS(u.RequestTimeoutMS, 0), ExpectContinueTimeout: time.Second,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				ctx, cancel := context.WithTimeout(ctx, durationMS(u.ConnectTimeoutMS, 10*time.Second))
				defer cancel()
				// Transport dials may outlive their originating request; fork once more
				// so competing Happy Eyeballs attempts cannot mutate the request state.
				return s.Proxy.Conn(netapi.ForkContext(ctx), s.Destination)
			},
		}
		e = &transportEntry{transport: tr}
		if p.closed {
			e.retired = true
		} else {
			if len(p.entries) >= p.capacity {
				var oldest transportKey
				var victim *transportEntry
				for k, v := range p.entries {
					if victim == nil || v.used < victim.used {
						oldest, victim = k, v
					}
				}
				delete(p.entries, oldest)
				victim.retired = true
				victim.transport.CloseIdleConnections()
			}
			p.entries[key] = e
		}
	}
	e.used = p.clock
	e.refs++
	return e.transport, sync.OnceFunc(func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		e.refs--
		if e.retired && e.refs == 0 {
			e.transport.CloseIdleConnections()
		}
	}), nil
}

func (p *TransportPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for k, e := range p.entries {
		e.retired = true
		e.transport.CloseIdleConnections()
		delete(p.entries, k)
	}
	return nil
}
func durationMS(ms int, fallback time.Duration) time.Duration {
	if ms <= 0 {
		return fallback
	}
	return time.Duration(ms) * time.Millisecond
}
