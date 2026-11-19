//go:build windows

package processpath

import "golang.org/x/sys/windows"

// Host returns the flavor of this platform with the current NT device to
// drive letter table. It queries every drive letter, so call it when an
// index is built, not per lookup; the index keeps the table it was built
// with.
func Host() Flavor { return Windows.WithDevices(driveDevices()) }

// HostSyntax returns the flavor of this platform without querying devices.
func HostSyntax() Flavor { return Windows }

func driveDevices() map[string]string {
	devices := map[string]string{}
	buf := make([]uint16, windows.MAX_PATH)
	for letter := 'A'; letter <= 'Z'; letter++ {
		drive := string(letter) + ":"
		name, err := windows.UTF16PtrFromString(drive)
		if err != nil {
			continue
		}
		n, err := windows.QueryDosDevice(name, &buf[0], uint32(len(buf)))
		if err != nil || n == 0 {
			continue
		}
		// The first NUL-terminated string is the current target; SUBST
		// drives report \??\C:\dir, which is not a device and is skipped.
		target := windows.UTF16ToString(buf[:n])
		if len(target) > 8 && target[:8] == `\Device\` {
			devices[target] = drive
		}
	}
	return devices
}
