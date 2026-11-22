package platform

import (
	"context"

	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/wfp"
)

// NewBackend returns this platform's backend.
func NewBackend() protection.Backend { return wfp.NewBackend() }

// PrepareStartup runs before Yuhaiin opens any socket.
func PrepareStartup(context.Context) {}
