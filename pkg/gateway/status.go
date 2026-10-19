package gateway

import (
	"context"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
)

func (m *Manager) Status() contract.RuntimeStatus {
	s := m.current.Load()
	result := contract.RuntimeStatus{Revision: s.config.Revision, Gateways: []contract.GatewayStatus{}}
	for _, config := range s.config.Gateways {
		g := s.gateways[config.ID]
		c := g.engine.Counters
		status := contract.GatewayStatus{ID: config.ID, Enabled: config.Enabled, Requests: c.Requests.Load(), Blocked: c.Blocked.Load(), Forwarded: c.Forwarded.Load(), Errors: c.Errors.Load(), TLSFailures: c.TLSFailures.Load(), ProtocolFailures: c.ProtocolFailures.Load(), DurationNS: c.DurationNS.Load(), Upstreams: []contract.UpstreamStatus{}}
		status.FilterReports = g.engine.filters.reports
		if identity := g.engine.lastOutbound.Load(); identity != nil {
			status.LastOutbound = *identity
		}
		for _, config := range s.config.Upstreams {
			u := g.engine.upstreams[config.ID]
			if u == nil {
				continue
			}
			us := contract.UpstreamStatus{ID: config.ID, ActiveRequests: u.active.Load(), Backends: []contract.BackendStatus{}}
			for _, b := range u.backends {
				us.Backends = append(us.Backends, contract.BackendStatus{URL: b.url.String(), Healthy: b.unavailableUntil.Load() <= time.Now().UnixNano(), ActiveRequests: b.active.Load(), Failures: b.failures.Load()})
			}
			status.Upstreams = append(status.Upstreams, us)
		}
		result.Gateways = append(result.Gateways, status)
	}
	return result
}
func (m *Manager) CAStatus() contract.CAStatus {
	if m.Authority == nil {
		return contract.CAStatus{}
	}
	return m.Authority.Status()
}
func (m *Manager) GenerateCA(ctx context.Context, revision uint64) (contract.CAStatus, error) {
	return m.Authority.Generate(ctx, revision)
}
func (m *Manager) ImportCA(ctx context.Context, input contract.CAImport) (contract.CAStatus, error) {
	return m.Authority.Import(ctx, input)
}
