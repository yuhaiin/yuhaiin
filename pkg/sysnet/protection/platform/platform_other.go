//go:build !darwin && !windows && (!linux || android)

package platform

import (
	"context"

	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
)

// NewBackend returns this platform's backend.
func NewBackend() protection.Backend { return protection.Unsupported{} }

// PrepareStartup runs before Yuhaiin opens any socket.
func PrepareStartup(context.Context) {}
