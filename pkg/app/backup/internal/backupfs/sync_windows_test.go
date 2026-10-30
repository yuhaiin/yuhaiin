package backupfs

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func requireWindowsRecoveryVolume(t *testing.T, directory string) {
	t.Helper()
	qualify := func(message string) {
		t.Helper()
		if os.Getenv("YUH_WINDOWS_RECOVERY_REQUIRE") == "1" {
			t.Fatal(message)
		}
		t.Skip(message)
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		qualify("Windows durable recovery requires an elevated process")
	}
	file, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var filesystem [32]uint16
	if err := windows.GetVolumeInformationByHandle(windows.Handle(file.Fd()), nil, 0, nil, nil, nil, &filesystem[0], uint32(len(filesystem))); err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(windows.UTF16ToString(filesystem[:]), "NTFS") {
		qualify("Windows durable recovery qualification requires a local NTFS volume")
	}
}

func TestWindowsRecoveryDirectoryDurability(t *testing.T) {
	directory := t.TempDir()
	requireWindowsRecoveryVolume(t, directory)
	if err := SyncDirectory(directory); err != nil {
		t.Fatal("cannot durably commit a recovery directory on elevated NTFS", err)
	}
}
