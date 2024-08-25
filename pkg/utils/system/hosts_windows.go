package system

import (
	"golang.org/x/sys/windows"
)

func init() {
	hostsFilePath = systemDirectory() + "/Drivers/etc/hosts"
}

func systemDirectory() string {
	s, err := windows.GetSystemDirectory()
	if err != nil {
		return `C:\Windows\System32`
	}
	return s
}
