package l2tp

import "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight"

// StackDiagnostic supports both routed IP and Ethernet tunnel adapters.
func (c *Client) StackDiagnostic(limit int) lightweight.StackDiagnostics {
	if provider, ok := c.network.(lightweight.DiagnosticProvider); ok {
		return provider.StackDiagnostic(limit)
	}
	return lightweight.StackDiagnostics{}
}

// StackDiagnostic never waits for a session or initiates a reconnect.
func (r *reconnectingClient) StackDiagnostic(limit int) lightweight.StackDiagnostics {
	r.mu.RLock()
	client, stopped := r.current, r.stopped
	r.mu.RUnlock()
	if client == nil || stopped {
		return lightweight.StackDiagnostics{}
	}
	return client.StackDiagnostic(limit)
}
