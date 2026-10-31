package update

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"

	buildversion "github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/update/compatibility"
)

// Only the running helper can describe its own binary's migration catalog.
// Unknown older history entries remain unknown; metadata is never invented by
// looking at a version string or executing an archived program.
func saveCurrentCompatibility(executable, archived string) error {
	running, err := os.Executable()
	if err != nil {
		return err
	}
	source, err := os.Stat(executable)
	if err != nil {
		return err
	}
	self, err := os.Stat(running)
	if err != nil {
		return err
	}
	if !os.SameFile(source, self) {
		return nil
	}
	architecture := buildversion.ReleaseArch
	if architecture == "" {
		architecture = runtime.GOARCH
	}
	manifest, err := compatibility.Describe(context.Background(), archived, runtime.GOOS, architecture)
	if err != nil {
		return err
	}
	// A repeated archive of the same executable can already have the same sealed
	// descriptor. Never replace a differing sidecar silently.
	old, err := readCompatibilityFile(archived + compatibility.Suffix)
	if err == nil {
		if old.SHA256 != manifest.SHA256 || old.Size != manifest.Size {
			return errors.New("archived compatibility metadata changed")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeStagedCompatibility(archived, manifest)
}

func readCompatibilityFile(path string) (compatibility.Manifest, error) {
	var empty compatibility.Manifest
	info, err := os.Lstat(path)
	if err != nil {
		return empty, err
	}
	if !info.Mode().IsRegular() || info.Size() > compatibility.MaxManifestBytes || (runtime.GOOS != "windows" && info.Mode().Perm()&0022 != 0) {
		return empty, errors.New("invalid compatibility sidecar type, size or permissions")
	}
	file, err := os.Open(path)
	if err != nil {
		return empty, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, compatibility.MaxManifestBytes+1))
	if err != nil {
		return empty, err
	}
	return compatibility.Parse(data)
}
func historyCompatibility(dataDir, id string) (compatibility.Manifest, error) {
	if !validHistoryID(id) {
		return compatibility.Manifest{}, errors.New("invalid history ID")
	}
	binary, _ := historyPaths(HistoryDirectory(dataDir), id)
	m, err := readCompatibilityFile(binary + compatibility.Suffix)
	if err == nil && m.SHA256 != id {
		return compatibility.Manifest{}, errors.New("history descriptor differs from executable identity")
	}
	return m, err
}
