package backupfs

import (
	"errors"
	"path/filepath"
	"uuid"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
)

const recoveryDiskReserve = 256 << 20

func ImportPath(id string) (string, error) {
	value, err := uuid.Parse(id)
	if err != nil || value == (uuid.UUID{}) || value.String() != id {
		return "", errors.New("invalid recovery import identifier")
	}
	return filepath.Join(".recovery-imports", id, "archive.yhb"), nil
}
func CheckStagingSpace(directory string, bytes int64) error {
	if bytes < 0 || bytes > contract.MaxRecoveryDataBytes {
		return errors.New("recovery staging exceeds its size budget")
	}
	available, err := recoveryAvailableBytes(directory)
	if err != nil {
		return errors.New("cannot establish available recovery staging space")
	}
	if available < uint64(bytes)+recoveryDiskReserve {
		return errors.New("insufficient recovery staging space; preserve at least 256 MiB for the active deployment")
	}
	return nil
}
