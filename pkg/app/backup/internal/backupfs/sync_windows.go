package backupfs

import (
	"errors"
	"os"
	"runtime"
	"strings"

	"golang.org/x/sys/windows"
)

// Sync commits recovery data and namespace changes on a local NTFS volume.
// Windows cannot fsync a read-only directory like Unix. A writable volume handle
// can flush both data and metadata; opening it requires elevated access. This
// intentionally expensive operation belongs to offline recovery, never routing.
func Sync(file *os.File) error {
	return syncWindowsRecoveryFile(file, windows.FlushFileBuffers)
}

func syncWindowsRecoveryFile(file *os.File, flush func(windows.Handle) error) error {
	defer runtime.KeepAlive(file)
	handle := windows.Handle(file.Fd())
	var filesystem [32]uint16
	var flags uint32
	if err := windows.GetVolumeInformationByHandle(handle, nil, 0, nil, nil, &flags, &filesystem[0], uint32(len(filesystem))); err != nil {
		return err
	}
	if flags&windows.FILE_PERSISTENT_ACLS == 0 || !strings.EqualFold(windows.UTF16ToString(filesystem[:]), "NTFS") {
		return errors.Join(errors.ErrUnsupported, errors.New("durable Windows recovery requires local NTFS with persistent ACLs"))
	}
	path, err := windowsRecoveryVolume(handle)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	volume, err := windows.CreateFile(name, windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return errors.Join(errors.New("durable Windows recovery requires elevated volume-flush access"), err)
	}
	// A failed flush must never be treated as a successful recovery commit.
	return errors.Join(flush(volume), windows.CloseHandle(volume))
}

func windowsRecoveryVolume(file windows.Handle) (string, error) {
	const volumeNameGUID = 0x1 // GetFinalPathNameByHandleW VOLUME_NAME_GUID.
	const maxPath = 32768
	buffer := make([]uint16, 512)
	for range 3 {
		count, err := windows.GetFinalPathNameByHandle(file, &buffer[0], uint32(len(buffer)), volumeNameGUID)
		if err != nil {
			return "", err
		}
		if count == 0 || count >= maxPath {
			break
		}
		if int(count) >= len(buffer) {
			buffer = make([]uint16, int(count)+1)
			continue
		}
		path := windows.UTF16ToString(buffer[:count])
		// A volume handle has no trailing backslash. Refuse UNC/device paths
		// instead of substituting an unrelated drive or ignoring the sync.
		if !strings.HasPrefix(path, `\\?\Volume{`) {
			break
		}
		volume, _, ok := strings.Cut(path, `}\`)
		if ok {
			return volume + "}", nil
		}
		break
	}
	return "", errors.Join(errors.ErrUnsupported, errors.New("recovery file has no bounded local volume identity"))
}
