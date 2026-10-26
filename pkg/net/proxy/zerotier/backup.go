package zerotier

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	zt "github.com/yuhaiin/zerotier-go"
)

var stateObjectName = regexp.MustCompile(`^[0-9]+-[0-9a-f]{16}-[0-9a-f]{16}\.state$`)

// RecoveryFiles is owned by the protocol that creates the native FileStore.
// Only its state-object files are included, never temporary files or logs.
func RecoveryFiles(base string, input contract.ZeroTier) ([]string, error) {
	id, err := zt.ParseNetworkID(input.NetworkID)
	if err != nil {
		return nil, err
	}
	name := input.Identity
	if name == "" {
		name = id.String()
	}
	if !safeIdentity.MatchString(name) {
		return nil, errors.New("invalid ZeroTier identity namespace")
	}
	directory := filepath.Join(base, "zerotier", name)
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	files := []string{}
	for _, entry := range entries {
		if !stateObjectName.MatchString(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("zerotier state object is not a regular file")
		}
		files = append(files, filepath.Join(directory, entry.Name()))
	}
	return files, nil
}
