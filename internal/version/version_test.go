package version

import (
	"os"
	"testing"
)

func TestVersion(t *testing.T) {
	Output(os.Stdout)
	t.Log(String())
}
