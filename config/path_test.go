package config

import (
	"testing"
)

func TestGetPythonPath(t *testing.T) {
	t.Log(configPath)
	t.Log(GetPythonPath())
}
