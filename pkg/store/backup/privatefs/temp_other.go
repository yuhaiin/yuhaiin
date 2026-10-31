//go:build !windows

// Package privatefs creates temporary backup material with private access.
package privatefs

import "os"

func MkdirTemp(parent, prefix string) (string, error) {
	return os.MkdirTemp(parent, prefix+"*")
}

func CreateTemp(parent, prefix string) (*os.File, error) {
	return os.CreateTemp(parent, prefix+"*")
}
