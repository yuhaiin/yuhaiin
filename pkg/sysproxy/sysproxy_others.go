//go:build (!linux || android) && !windows && !darwin
// +build !linux android
// +build !windows
// +build !darwin

package sysproxy

func SetSysProxy(_, _, _, _ string) {}
func UnsetSysProxy()                {}
