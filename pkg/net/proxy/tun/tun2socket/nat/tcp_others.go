//go:build !linux
// +build !linux

package nat

func setSocketOptions(fd uintptr) {}
