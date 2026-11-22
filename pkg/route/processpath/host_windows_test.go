package processpath

import (
	"os"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// TestWindowsDeviceTable maps the system drive's NT device path back to the
// drive letter with the live QueryDosDevice table.
func TestWindowsLiveDeviceTable(t *testing.T) {
	drive := os.Getenv("SystemDrive")
	if len(drive) != 2 {
		t.Skip("no system drive")
	}
	buf := make([]uint16, windows.MAX_PATH)
	name, _ := windows.UTF16PtrFromString(drive)
	n, err := windows.QueryDosDevice(name, &buf[0], uint32(len(buf)))
	if err != nil {
		t.Skip(err)
	}
	device := windows.UTF16ToString(buf[:n])
	b := NewBuilder(Host())
	_, _ = b.Add(drive+`\Windows\**`, "windows")
	ix := b.Build()
	for _, path := range []string{
		device + `\Windows\System32\cmd.exe`,
		strings.ToLower(drive) + `/windows/system32/CMD.EXE`,
		`\\?\` + drive + `\Windows\System32\cmd.exe`,
	} {
		if !slices.Contains(ix.Match(path), "windows") {
			t.Errorf("%q did not match %s\\Windows\\** (device %s)", path, drive, device)
		}
	}
}
