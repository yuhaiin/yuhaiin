package nebula

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
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

func TestRecoveryRebindPreservesYAMLComments(t *testing.T) {
	raw := "# restore this node\npki:\n  ca: \"ca.crt\" # CA path\n  cert: 'host.crt'\n  key: host.key\nlisten:\n  port: 4242\n"
	result, err := RebindRecoveryFiles(raw, func(path string) (string, error) {
		return filepath.Join("/restored", path), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"# restore this node",
		"# CA path",
		"listen:",
		"port: 4242",
	} {
		if !strings.Contains(result, fragment) {
			t.Errorf("rebound YAML lost %q: %s", fragment, result)
		}
	}
	files, err := RecoveryFiles(contract.Nebula{ConfigYAML: result})
	want := []string{"/restored/ca.crt", "/restored/host.crt", "/restored/host.key"}
	if err != nil || !slices.Equal(files, want) {
		t.Fatalf("rebound YAML changed PKI options: %v, %v", files, err)
	}
}

func TestRecoveryRebindKeepsInlinePEM(t *testing.T) {
	raw := "pki:\n  ca: |\n    -----BEGIN CERTIFICATE-----\n    placeholder\n    -----END CERTIFICATE-----\n  cert: host.crt\n  key: host.key\n"
	var resolved []string
	result, err := RebindRecoveryFiles(raw, func(path string) (string, error) {
		resolved = append(resolved, path)
		return filepath.Join("/restored", path), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, "-----BEGIN CERTIFICATE-----") ||
		!strings.Contains(result, "-----END CERTIFICATE-----") {
		t.Fatalf("inline CA was not retained: %s", result)
	}
	if !slices.Equal(resolved, []string{"host.crt", "host.key"}) {
		t.Fatalf("unexpected path resolutions: %v", resolved)
	}
}
