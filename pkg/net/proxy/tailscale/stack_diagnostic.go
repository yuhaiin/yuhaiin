package tailscale

import "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight"

// StackDiagnostic does not start tsnet, authenticate, or wait for IP assignment.
func (t *Tailscale) StackDiagnostic(limit int) lightweight.StackDiagnostics {
	if !t.mu.TryLock() {
		return lightweight.StackDiagnostics{}
	}
	server, closed := t.tsnet, t.closed
	t.mu.Unlock()
	if server == nil || closed {
		return lightweight.StackDiagnostics{}
	}
	network, ok := server.Tun.(*tailnetTun)
	if !ok {
		return lightweight.StackDiagnostics{}
	}
	network.mu.Lock()
	tun, closed := network.network, network.closed
	network.mu.Unlock()
	if closed {
		return lightweight.StackDiagnostics{}
	}
	return tun.StackDiagnostic(limit)
}
