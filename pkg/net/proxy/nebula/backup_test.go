package nebula

import (
	"slices"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

func TestRecoveryFilesResolvesPKIWithoutConstructingTunnel(t *testing.T) {
	files, err := RecoveryFiles(contract.Nebula{ConfigYAML: "pki:\n  ca: ./ca.crt\n  cert: ./host.crt\n  key: ./host.key\n"})
	if err != nil || !slices.Equal(files, []string{"./ca.crt", "./host.crt", "./host.key"}) {
		t.Fatalf("PKI references: %v %v", files, err)
	}
	files, err = RecoveryFiles(contract.Nebula{ConfigYAML: "pki:\n  ca: '-----BEGIN NEBULA CERTIFICATE-----'\n  cert: '-----BEGIN NEBULA CERTIFICATE-----'\n  key: '-----BEGIN NEBULA X25519 PRIVATE KEY-----'\n"})
	if err != nil || len(files) != 0 {
		t.Fatal("inline private inputs treated as file paths")
	}
	for _, raw := range []string{"", "pki: {}", "pki:\n  ca: ca.crt\n  cert: host.crt\n  key: 'pkcs11:token=fixture'\n"} {
		if _, err := RecoveryFiles(contract.Nebula{ConfigYAML: raw}); err == nil {
			t.Fatal("missing or externally bound identity was silently omitted")
		}
	}
}
