//go:build !darwin

package servicehost

import "errors"

func SuperviseDarwin([]string) error {
	return errors.New("launchd maintenance is unavailable on this platform")
}
