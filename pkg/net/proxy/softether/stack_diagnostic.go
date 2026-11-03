package softether

import "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight"

// StackDiagnostic passively samples the existing inner TCP/IP stack.
func (c *Client) StackDiagnostic(limit int) lightweight.StackDiagnostics {
	return c.network.StackDiagnostic(limit)
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
