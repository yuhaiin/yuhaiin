package vpnkit

import "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight"

// StackDiagnostic passively samples the existing inner TCP/IP stack.
func (c *Client) StackDiagnostic(limit int) lightweight.StackDiagnostics {
	return c.network.StackDiagnostic(limit)
}
