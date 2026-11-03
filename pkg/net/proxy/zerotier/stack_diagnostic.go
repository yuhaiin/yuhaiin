//go:build (((linux && !android) || darwin) && (amd64 || arm64)) || (windows && amd64) || (android && arm64 && cgo)

package zerotier

import "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight"

// StackDiagnostic never waits for controller approval or assigned addresses.
func (c *Client) StackDiagnostic(limit int) lightweight.StackDiagnostics {
	c.mu.RLock()
	active := c.active
	c.mu.RUnlock()
	if active == nil {
		return lightweight.StackDiagnostics{}
	}
	return active.tun.StackDiagnostic(limit)
}
