//go:build !linux && !darwin && !windows

package updatecmd

import (
	"context"
	"errors"

	updatepkg "github.com/Asutorufa/yuhaiin/pkg/update"
)

type unsupportedUpdateInstaller struct{}

func NewInstaller(string) updatepkg.Installer { return unsupportedUpdateInstaller{} }
func (unsupportedUpdateInstaller) Supported() (bool, string) {
	return false, "automatic updates are not supported on this platform"
}
func (unsupportedUpdateInstaller) Start(context.Context, string) error {
	return errors.New("automatic updates are not supported on this platform")
}
func Install([]string) error {
	return errors.New("automatic updates are not supported on this platform")
}
