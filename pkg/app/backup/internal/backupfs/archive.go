package backupfs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"uuid"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
)

func ArchivePath(directory, id string) (string, error) {
	value, err := uuid.Parse(id)
	if err != nil || value == (uuid.UUID{}) || value.String() != id {
		return "", errors.New("invalid backup identifier")
	}
	return filepath.Join(directory, ".recovery-archives", id+".yhb"), nil
}
func DigestArchive(ctx context.Context, path string) (int64, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer file.Close()
	return DigestArchiveFile(ctx, file)
}
func DigestArchiveFile(ctx context.Context, file *os.File) (int64, string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return 0, "", err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > contract.MaxRecoveryDataBytes {
		return 0, "", errors.New("managed encrypted archive exceeds its 100 GiB limit")
	}
	hash := sha256.New()
	buffer := make([]byte, 32<<10)
	var count int64
	for {
		if err := ctx.Err(); err != nil {
			return 0, "", err
		}
		n, err := file.Read(buffer)
		if n > 0 {
			count += int64(n)
			if count > info.Size() {
				return 0, "", errors.New("encrypted archive grew during verification")
			}
			_, _ = hash.Write(buffer[:n])
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, "", err
		}
	}
	after, err := file.Stat()
	if err != nil || count != info.Size() || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return 0, "", errors.New("encrypted archive changed during verification")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return 0, "", err
	}
	return count, hex.EncodeToString(hash.Sum(nil)), nil
}
