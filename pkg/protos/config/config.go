package config

import (
	"os"
	"os/exec"
	"path/filepath"

	"github.com/Asutorufa/yuhaiin/pkg/log"
)

func DefaultConfigDir() (Path string) {
	var err error
	Path, err = os.UserConfigDir()
	if err == nil {
		Path = filepath.Join(Path, "yuhaiin")
		return
	}

	file, err := exec.LookPath(os.Args[0])
	if err != nil {
		log.Warn("lookpath failed", "err", err)
		Path = filepath.Join(".", "yuhaiin")
		return
	}
	execPath, err := filepath.Abs(file)
	if err != nil {
		log.Warn("get file abs failed", "err", err)
		Path = filepath.Join(".", "yuhaiin")
		return
	}

	Path = filepath.Join(filepath.Dir(execPath), "config")
	return
}

type DB interface {
	Batch(f ...func(*Setting) error) error
	View(f ...func(*Setting) error) error
	Dir() string
}
