package tailscale

import (
	"errors"
	"os"
	"path/filepath"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

// RecoveryFiles describes only this configured identity's persistent files.
// It does not construct a client, migrate state or contact a control server.
func RecoveryFiles(base string, input contract.Tailscale) ([]string, error) {
	directory, err := statePath(base, Config{AuthKey: input.AuthKey, Hostname: input.Hostname, ControlURL: input.ControlURL})
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		if input.Hostname == "" {
			directory = filepath.Join(base, "tailscale")
		} else if input.Hostname != "." && input.Hostname != ".." && filepath.Base(input.Hostname) == input.Hostname {
			directory = filepath.Join(base, "tailscale", input.Hostname)
		}
	} else if err != nil {
		return nil, err
	}
	files := []string{}
	for _, name := range []string{"lite.json", "tailscaled.state"} {
		path := filepath.Join(directory, name)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, errors.New("tailnet identity backup source is not a regular file")
		}
		files = append(files, path)
	}
	return files, nil
}
