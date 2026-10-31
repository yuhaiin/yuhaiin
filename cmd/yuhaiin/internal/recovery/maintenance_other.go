//go:build !linux

package recoverycmd

import (
	"errors"
)

func Capture([]string) error {
	return errors.New("installed-service recovery maintenance is unavailable on this platform; use the offline recovery CLI")
}
func RestartCapture(args []string) error {
	return Capture(args)
}

func Restore(args []string) error        { return Capture(args) }
func RestartRestore(args []string) error { return Capture(args) }
