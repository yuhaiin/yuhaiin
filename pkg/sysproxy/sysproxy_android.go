//go:build !lite
// +build !lite

package sysproxy

func SetSysProxy(_, _, _, _ string) {}
func UnsetSysProxy()                {}
