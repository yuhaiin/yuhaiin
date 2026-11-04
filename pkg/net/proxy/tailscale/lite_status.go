package tailscale

import (
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

var _ contract.NodeRuntimeStatusProvider = (*Lite)(nil)

// Observe cached state only; monitoring must not initialize a lazy identity.
func (t *Lite) NodeRuntimeStatus() contract.ProtocolRuntimeStatus {
	s := contract.ProtocolRuntimeStatus{State: "idle", UpdatedAt: time.Now().Unix()}
	if !t.owner.mu.TryLock() {
		s.State = "connecting"
		return s
	}
	client, closed := t.client, t.owner.closed
	t.owner.mu.Unlock()
	if closed {
		s.State = "closed"
		return s
	}
	if client == nil {
		return s
	}
	status := client.Snapshot()
	s.State = "connecting"
	if status.Error != "" {
		s.State = "control_unavailable"
		s.LastError = status.Error
	} else if status.Ready {
		s.State = "configured"
	}
	return s
}
