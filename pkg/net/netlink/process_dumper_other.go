//go:build !linux || android

package netlink

import "github.com/Asutorufa/yuhaiin/pkg/net/netapi"

// NewProcessDumper returns the platform's socket owner lookup.
func NewProcessDumper() netapi.ProcessDumper { return HostProcessDumper{} }
