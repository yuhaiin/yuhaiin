package nebula

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

func TestRecoveryRebindRetainsNebulaOptionsAndInlineMaterial(t *testing.T) {
	raw := "pki:\n  ca: ca.crt\n  cert: host.crt\n  key: host.key\nlisten:\n  port: 4242\n"
	result, err := RebindRecoveryFiles(raw, func(path string) (string, error) { return filepath.Join("/restored", path), nil })
	if err != nil {
		t.Fatal(err)
	}
	files, err := RecoveryFiles(contract.Nebula{ConfigYAML: result})
	want := []string{filepath.Join("/restored", "ca.crt"), filepath.Join("/restored", "host.crt"), filepath.Join("/restored", "host.key")}
	if err != nil || !slices.Equal(files, want) {
		t.Fatal("PKI was not rebound", files, err)
	}
	if _, err := RebindRecoveryFiles(raw, func(string) (string, error) { return "", errors.New("missing authenticated dependency") }); err == nil {
		t.Fatal("missing key dependency was ignored")
	}
}
