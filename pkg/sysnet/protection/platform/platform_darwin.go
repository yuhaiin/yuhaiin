package platform

import (
	"context"

	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/helper"
)

// NewBackend returns this platform's backend.
func NewBackend() protection.Backend { return helper.NewBackend() }

// PrepareStartup runs before Yuhaiin opens any socket.
func PrepareStartup(ctx context.Context) { helper.PrepareStartup(ctx) }
