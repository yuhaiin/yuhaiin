// Package helper is the privileged Network Protection service of macOS and
// its command line recovery.
//
// The service runs as its own LaunchDaemon (io.github.yuhaiin.protection),
// independent of the Yuhaiin core. It owns the kill switch's PF anchor, the
// managed pf.conf lines, its PF enable reference and the saved protection
// state; the core only asks it for status and sends policy updates over a
// local socket. Because the rules live in the kernel and the service restores
// them at boot, protection holds while the core is stopped, crashed or
// killed.
package helper

import (
	"bytes"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/pf"
)

// Fixed locations. The service accepts no paths from clients.
const (
	Label     = "io.github.yuhaiin.protection"
	PlistPath = "/Library/LaunchDaemons/" + Label + ".plist"
	StateDir  = pf.BackupDir
	StateFile = StateDir + "/state.json"
	SocketDir = "/var/run/io.github.yuhaiin"
	Socket    = SocketDir + "/protection.sock"
	// GroupName is the group of the Yuhaiin process's sockets, which the
	// kill switch lets through to proxy servers and direct destinations.
	GroupName = "_yuhaiin"
	// Binary is the stable command line location the service runs from.
	Binary = "/usr/local/bin/yuhaiin"
)

const stateVersion = 1

// State is the saved protection state. It is the single source of truth for
// whether protection is requested: the core asks for it, and the command
// line recovery changes it without the core.
type State struct {
	Version     int  `json:"version"`
	Enabled     bool `json:"enabled"`
	StartAtBoot bool `json:"startAtBoot"`
	// Policy is the persistent part of the last applied policy.
	Policy protection.Policy `json:"policy"`
	// Token is the PF enable reference taken in boot session TokenBoot.
	Token     string `json:"token,omitzero"`
	TokenBoot string `json:"tokenBoot,omitzero"`
	// AppliedBoot is the boot session protection was last applied in.
	AppliedBoot string `json:"appliedBoot,omitzero"`
	GroupID     int    `json:"groupId,omitzero"`
	UpdatedAt   int64  `json:"updatedAt,omitzero"`
	// ChangedBy records who changed Enabled last (api, cli, recovery).
	ChangedBy string `json:"changedBy,omitzero"`
}

// ErrCorrupt marks a state file that exists but cannot be read.
var ErrCorrupt = errors.New("the saved protection state is damaged")

// LoadState reads path. A missing file is the zero state with exists false.
func LoadState(path string) (s State, exists bool, err error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return State{Version: stateVersion}, false, nil
	}
	if err != nil {
		return State{}, true, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return State{}, true, fmt.Errorf("%w: %s: %v", ErrCorrupt, path, err)
	}
	if s.Version != stateVersion {
		return State{}, true, fmt.Errorf("%w: %s: unknown version %d", ErrCorrupt, path, s.Version)
	}
	if s.Enabled {
		if err := s.Policy.Validate(); err != nil {
			return State{}, true, fmt.Errorf("%w: %s: %v", ErrCorrupt, path, err)
		}
	}
	return s, true, nil
}

// SaveState writes s durably (synced temporary file, rename, synced
// directory). The directory is created root-only.
func SaveState(path string, s State) error {
	s.Version = stateVersion
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(s, json.Deterministic(true))
	if err != nil {
		return err
	}
	if err := pf.WriteFileAtomic(path, data, 0o600); err != nil {
		return err
	}
	// Read back what was written: success is only reported for a state
	// that is really on disk.
	check, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(check, data) {
		return fmt.Errorf("%s: written state does not read back", path)
	}
	return nil
}

// quarantine moves a damaged state file aside so it can be inspected.
func quarantine(path string) {
	_ = os.Rename(path, path+".damaged")
}
