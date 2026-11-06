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
	for _, raw := range []string{"", "pki: {}", "pki: null", "pki:\n  ca: ca.crt\n  cert: host.crt\n  key: 'pkcs11:token=fixture'\n"} {
		if inventory, err := RecoveryInventory(contract.Nebula{ConfigYAML: raw}); err != nil || !inventory.NeedsReconfiguration {
			t.Fatal("missing or externally bound identity was not recorded", err)
		}
		if _, err := RebindRecoveryFiles(raw, func(path string) (string, error) { return path, nil }); err != nil {
			t.Fatal("valid unmet requirement blocked rebinding", err)
		}
	}
	for _, raw := range []string{
		"pki: {ca: [a, b]}",
		"pki: {ca: a, ca: b}",
		"pki: {}\npki: {}",
		"pki: {<<: {key: /source/private.key}}",
		"<<: {pki: {key: /source/private.key}}",
	} {
		if _, err := RecoveryInventory(contract.Nebula{ConfigYAML: raw}); err == nil {
			t.Fatal("ambiguous PKI inventory accepted", raw)
		}
	}
}
