//go:build !darwin

package helper

import (
	"context"

	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
)

// Supported reports whether this platform has the protection service.
const Supported = false

func RunDaemon(context.Context) error             { return protection.ErrUnsupported }
func BootID() string                              { return "" }
func EnsureGroup(context.Context) (int, error)    { return 0, protection.ErrUnsupported }
func DeleteGroup(context.Context) error           { return nil }
func DaemonLoaded(context.Context) bool           { return false }
func InstallDaemon(context.Context, string) error { return protection.ErrUnsupported }
func EnsureDaemon(context.Context) error          { return protection.ErrUnsupported }
func StopDaemon(context.Context) error            { return nil }
func UninstallDaemon(context.Context) error       { return nil }
func RestartDaemon(context.Context) error         { return protection.ErrUnsupported }
func EnsureCurrent(context.Context)               {}
