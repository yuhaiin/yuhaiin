package node

import (
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"time"
)

// A known unusable session is availability evidence, not a new transport failure.
// Compile it once per selector snapshot without changing passive counters or
// preventing an explicit manual selection from following its existing path.
func (r *NodeRuntime) nativeSelectionUnavailable(now time.Time) map[string]string {
	var unavailable map[string]string
	r.proxies.Range(func(id string, p *ProxyEntry) bool {
		if !p.mu.TryRLock() {
			return true
		}
		defer p.mu.RUnlock()
		provider, ok := p.Proxy.(contract.NodeRuntimeStatusProvider)
		if !ok {
			return true
		}
		v := provider.NodeRuntimeStatus()
		reason := ""
		switch v.State {
		case "authentication_failed":
			reason = "authentication_unavailable"
		case "closed", "disconnected", "failed", "reconnecting":
			reason = "session_unavailable"
		case "control_unavailable":
			reason = "control_unavailable"
		}
		if reason != "" && v.UpdatedAt > 0 && v.UpdatedAt <= now.Unix()+5 && now.Unix()-v.UpdatedAt <= 120 {
			if unavailable == nil {
				unavailable = make(map[string]string)
			}
			unavailable[id] = reason
		}
		return true
	})
	return unavailable
}
