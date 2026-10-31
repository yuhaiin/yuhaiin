//go:build !linux

package updatecmd

import "errors"

func ProtectedInstall([]string) error {
	return errors.New("protected update host is unavailable; use offline recovery")
}
func RecoverProtected([]string) error {
	return errors.New("protected update host is unavailable; use offline recovery")
}
