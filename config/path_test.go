package config

import (
	"os"
	"path"
	"path/filepath"
	"testing"
)

func TestGetPythonPath(t *testing.T) {
	t.Log(ConPath)
}

func TestGetEnvPath(t *testing.T) {
	t.Log(GetEnvPath("go"))
}

func TestGetPath(t *testing.T) {
	t.Log(os.UserConfigDir())
	t.Log(os.UserCacheDir())
	t.Log(os.UserHomeDir())
	t.Log(path.Join("/mnt/ss", "a"))
	t.Log(filepath.Dir("./"))
}
