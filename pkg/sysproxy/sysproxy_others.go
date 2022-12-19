//go:build openwrt || (!linux && !windows && !android)
// +build openwrt !linux,!windows,!android

package sysproxy

func SetSysProxy(_, _ string) {}
func UnsetSysProxy()          {}
