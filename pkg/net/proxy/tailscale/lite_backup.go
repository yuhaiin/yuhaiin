package tailscale

import (
	"errors"
	"os"
	"path/filepath"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

// LiteRecoveryDirectory is separate from every tsnet identity namespace.
func LiteRecoveryDirectory(base string, input contract.TailscaleLite) (string, error) {
	return liteStatePath(base, Config{AuthKey: input.AuthKey, Hostname: input.Hostname, ControlURL: input.ControlURL})
}

func LiteRecoveryFiles(base string, input contract.TailscaleLite) ([]string, error) {
	directory, err := LiteRecoveryDirectory(base, input)
	if err != nil {
		return nil, err
	}
	file := filepath.Join(directory, "lite.json")
	info, err := os.Lstat(file)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("tailscale-lite identity backup source is not a regular file")
	}
	return []string{file}, nil
}
