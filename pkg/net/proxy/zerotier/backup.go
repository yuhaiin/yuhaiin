package zerotier

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

var stateObjectName = regexp.MustCompile(`^[0-9]+-[0-9a-f]{16}-[0-9a-f]{16}\.state$`)
var safeIdentity = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// RecoveryFiles is owned by the protocol that creates the native FileStore.
// Only its state-object files are included, never temporary files or logs.
func RecoveryFiles(base string, input contract.ZeroTier) ([]string, error) {
	// Keep inventory usable on unsupported native targets. Importing the native
	// bridge here would bypass unsupported.go and pull purego into every build.
	id, err := strconv.ParseUint(input.NetworkID, 16, 64)
	if len(input.NetworkID) != 16 || err != nil || id == 0 {
		return nil, errors.New("invalid ZeroTier network identifier")
	}
	name := input.Identity
	if name == "" {
		name = fmt.Sprintf("%016x", id)
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
