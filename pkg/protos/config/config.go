package config

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
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
		log.Println(err)
		Path = filepath.Join(".", "yuhaiin")
		return
	}
	execPath, err := filepath.Abs(file)
	if err != nil {
		log.Println(err)
		Path = filepath.Join(".", "yuhaiin")
		return
	}

	Path = filepath.Join(filepath.Dir(execPath), "config")
	return
}
