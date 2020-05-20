package config

import (
	"testing"
)

func TestGetPythonPath(t *testing.T) {
	t.Log(ConPath)
	t.Log(GetPythonPath())
}
