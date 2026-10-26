package tailscale

import (
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"tailscale.com/health"
)

var _ contract.NodeRuntimeStatusProvider = (*Tailscale)(nil)

// Control readiness is configuration evidence, not a peer WireGuard handshake.
func (t *Tailscale) NodeRuntimeStatus() contract.ProtocolRuntimeStatus {
	if !t.mu.TryLock() {
		return contract.ProtocolRuntimeStatus{State: "connecting", UpdatedAt: time.Now().Unix()}
	}
	server, closed := t.tsnet, t.closed
	t.mu.Unlock()
	s := contract.ProtocolRuntimeStatus{State: "idle", UpdatedAt: time.Now().Unix()}
	if closed {
		s.State = "closed"
		return s
	}
	if server == nil {
		return s
	}
	s.State = "connecting"
	system := server.Sys()
	if system == nil {
		return s
	}
	tracker, ok := system.HealthTracker.GetOK()
	if !ok || tracker == nil {
		return s
	}
	// Read native in-memory state only. LocalClient.Status would issue an RPC
	// (and LocalClient can Start), which must never run during snapshot ranking.
	if tracker.IsUnhealthy(health.IPNStateWarnable) {
		s.State = "control_unavailable"
		s.LastError = "Tailnet native backend is not running"
		return s
	}
	v4, v6 := server.TailscaleIPs()
	if v4.IsValid() || v6.IsValid() {
		s.State = "configured"
	}
	return s
}
