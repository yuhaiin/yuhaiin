package tailscale

import (
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

var _ contract.NodeRuntimeStatusProvider = (*Tailscale)(nil)

// Control readiness is configuration evidence, not a peer WireGuard handshake.
func (t *Tailscale) NodeRuntimeStatus() contract.ProtocolRuntimeStatus {
	if !t.mu.TryLock() {
		return contract.ProtocolRuntimeStatus{State: "connecting", UpdatedAt: time.Now().Unix()}
	}
	client, closed := t.client, t.closed
	t.mu.Unlock()
	s := contract.ProtocolRuntimeStatus{State: "idle", UpdatedAt: time.Now().Unix()}
	if closed {
		s.State = "closed"
		return s
	}
	if client == nil {
		return s
	}
	status := client.Snapshot()
	if status.Ready {
		s.State = "configured"
	} else if status.Error != "" {
		s.State = "control_unavailable"
		s.LastError = "Tailnet control or transport is unavailable"
	} else {
		s.State = "connecting"
	}
	return s
}
