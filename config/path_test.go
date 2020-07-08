package config

import (
	"testing"
)

func TestGetPythonPath(t *testing.T) {
	t.Log(ConPath)
}

func TestGetEnvPath(t *testing.T) {
	t.Log(GetEnvPath("go"))
}
