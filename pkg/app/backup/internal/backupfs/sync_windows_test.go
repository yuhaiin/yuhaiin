package backupfs

import (
	"errors"
	"os"
	"path/filepath"
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

func TestWindowsRecoveryReadOnlyFileDurability(t *testing.T) {
	directory := t.TempDir()
	requireWindowsRecoveryVolume(t, directory)
	path := filepath.Join(directory, "original.key")
	if err := os.WriteFile(path, []byte("old identity fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := Sync(file); err != nil {
		t.Fatal("cannot durably preserve a read-only original", err)
	}
}

func TestWindowsRecoveryFlushFailureIsNotCommitted(t *testing.T) {
	directory := t.TempDir()
	requireWindowsRecoveryVolume(t, directory)
	file, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	fault := errors.New("injected volume flush failure")
	called := false
	err = syncWindowsRecoveryFile(file, func(windows.Handle) error {
		called = true
		return fault
	})
	if !called || !errors.Is(err, fault) {
		t.Fatal("a failed volume flush was reported as a durable commit", called, err)
	}
}
