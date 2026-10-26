package app

import "golang.org/x/sys/windows"

func recoveryAvailableBytes(directory string) (uint64, error) {
	name, err := windows.UTF16PtrFromString(directory)
	if err != nil {
		return 0, err
	}
	var available uint64
	err = windows.GetDiskFreeSpaceEx(name, &available, nil, nil)
	return available, err
}
