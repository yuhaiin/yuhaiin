//go:build !linux && !android
// +build !linux,!android

package nat

func setSocketOptions(fd uintptr) {}
