//go:build linux && !android

package platform

import (
	"context"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/nft"
)

// NewBackend returns this platform's backend. Yuhaiin's own sockets are
// identified by the Socket Protection mark (SO_MARK).
func NewBackend() protection.Backend {
	return nft.NewBackend(func() uint32 {
		if p := dialer.CurrentSocketProtector(); p != nil {
			return p.Mark
		}
		return 0
	})
}

// PrepareStartup runs before Yuhaiin opens any socket.
func PrepareStartup(context.Context) {}
