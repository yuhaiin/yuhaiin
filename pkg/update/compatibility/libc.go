package compatibility

import (
	"debug/buildinfo"
	"debug/elf"
	"errors"
	"github.com/Asutorufa/yuhaiin/internal/sqliteabi"
	"io"
	"runtime"
	"slices"
	"strings"
)

// MinimumGlibc is the ABI baseline verified for the embedded engine.
const MinimumGlibc = sqliteabi.MinimumGlibc

// LinuxABI chooses a compatible release variant for the current host.
func LinuxABI() string { return sqliteabi.LinuxABI() }

// RequiresGlibc inspects the target without executing it. Even a CGO-disabled
// executable can require glibc when PureGo loads the embedded Linux library.
func RequiresGlibc(path string) (bool, error) {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return false, err
	}
	var goos, cgo, tags string
	for _, setting := range info.Settings {
		switch setting.Key {
		case "GOOS":
			goos = setting.Value
		case "CGO_ENABLED":
			cgo = setting.Value
		case "-tags":
			tags = setting.Value
		}
	}
	if goos != "linux" {
		return false, nil
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/yuhaiin/purego-sqlite-embed" && (cgo != "1" || slices.Contains(strings.Split(tags, ","), "sqlite_purego")) {
			return true, nil
		}
	}
	binary, err := elf.Open(path)
	if err != nil {
		return false, err
	}
	defer binary.Close()
	for _, program := range binary.Progs {
		if program.Type != elf.PT_INTERP {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(program.Open(), 4096))
		if err != nil {
			return false, err
		}
		return !strings.Contains(string(data), "ld-musl-"), nil
	}
	return false, nil
}

// VerifyHostLibc prevents installing a glibc target on musl or a loader-free
// host, including manually staged candidates and rollback history entries.
func VerifyHostLibc(path string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	needs, err := RequiresGlibc(path)
	if err != nil {
		return err
	}
	if !needs {
		return nil
	}
	if LinuxABI() != "glibc" {
		return errors.New("release executable requires glibc >= " + MinimumGlibc + "; select the fully static Linux asset")
	}
	binary, err := elf.Open(path)
	if err != nil {
		return err
	}
	defer binary.Close()
	symbols, err := binary.ImportedSymbols()
	if errors.Is(err, elf.ErrNoSymbols) {
		return nil
	}
	if err != nil {
		return err
	}
	checked := make(map[string]bool)
	for _, symbol := range symbols {
		version, ok := strings.CutPrefix(symbol.Version, "GLIBC_")
		if !ok || checked[version] {
			continue
		}
		checked[version] = true
		if !sqliteabi.SupportsGlibc(version) {
			return errors.New("release executable needs unsupported " + symbol.Version + "; select the fully static Linux asset")
		}
	}
	return nil
}
