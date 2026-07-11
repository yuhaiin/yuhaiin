//go:build !linux && !darwin && !windows

package main

import (
	"context"
	"errors"

	updatepkg "github.com/Asutorufa/yuhaiin/pkg/update"
)

type unsupportedUpdateInstaller struct{}

func newUpdateInstaller() updatepkg.Installer { return unsupportedUpdateInstaller{} }
func (unsupportedUpdateInstaller) Supported() (bool, string) {
	return false, "automatic updates are not supported on this platform"
}
func (unsupportedUpdateInstaller) Start(context.Context, string) error {
	return errors.New("automatic updates are not supported on this platform")
}
func updateHelper([]string) error {
	return errors.New("automatic updates are not supported on this platform")
}
