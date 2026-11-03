package masque

import "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight"

// StackDiagnostic passively samples the existing inner TCP/IP stack.
func (c *Masque) StackDiagnostic(limit int) lightweight.StackDiagnostics {
	return c.dev.StackDiagnostic(limit)
}
