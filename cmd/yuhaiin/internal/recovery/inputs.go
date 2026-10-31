package recoverycmd

import (
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
)

func readJSONFile(path string, output any, private bool) error {
	file, err := os.Open(path)
	if err != nil {
		return errors.New("cannot open recovery JSON input")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 || (private && runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return errors.New("recovery JSON input must be a bounded regular file; S3 settings require owner-only permissions")
	}
	data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return errors.New("recovery JSON input exceeds its size limit")
	}
	if err := json.Unmarshal(data, output); err != nil {
		return errors.New("invalid recovery JSON input")
	}
	return nil
}

func readSecretFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > 1025 {
		return "", errors.New("backup key/passphrase must be a regular file of at most 1025 bytes")
	}
	// Opening the file is the OS authorization check. Enforce private Unix
	// permissions; Windows access is governed by its existing account ACLs.
	if info.Mode().Perm()&0o077 != 0 && runtime.GOOS != "windows" {
		return "", errors.New("backup key/passphrase file must have owner-only permissions (0600)")
	}
	data, err := io.ReadAll(io.LimitReader(file, 1026))
	if err != nil {
		return "", err
	}
	if len(data) > 1025 {
		return "", errors.New("backup key/passphrase file exceeds limit")
	}
	value := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if value == "" || len(value) > 1024 {
		return "", errors.New("empty or overlong backup key/passphrase")
	}
	return value, nil
}
