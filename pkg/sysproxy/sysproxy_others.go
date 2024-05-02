//go:build !linux && !windows && !android && !darwin
// +build !linux,!windows,!android,!darwin

package sysproxy

func SetSysProxy(_, _, _, _ string) {}
func UnsetSysProxy()                {}
