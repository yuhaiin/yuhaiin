//+build !linux,!windows

package sysproxy

func SetSysProxy(_, _ string) {}
func UnsetSysProxy()          {}
