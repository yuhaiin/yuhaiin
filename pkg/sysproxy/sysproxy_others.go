//go:build lite || (!linux && !windows && !android && !darwin)
// +build lite !linux,!windows,!android,!darwin

package sysproxy

func SetSysProxy(_, _, _, _, _ string) {}
func UnsetSysProxy(string)             {}
