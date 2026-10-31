package testfixture

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	gateway "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	node "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	managementtls "github.com/Asutorufa/yuhaiin/pkg/management/tls"
	"github.com/Asutorufa/yuhaiin/pkg/store"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
)

// Deployment includes native identity files for protocol-inventory tests.
func Deployment(t *testing.T) (string, *age.X25519Identity) {
	t.Helper()
	return deployment(t, true)
}

// BasicDeployment retains real configuration/identity SQLite, management TLS,
// gateway CA and certificate dependencies without unrelated native VPN profiles.
func BasicDeployment(t *testing.T) (string, *age.X25519Identity) {
	t.Helper()
	return deployment(t, false)
}

func deployment(t *testing.T, native bool) (string, *age.X25519Identity) {
	t.Helper()
	directory := t.TempDir()
	db, err := OpenState(t.Context(), filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := backupstore.New(db.DB()).RecordRecoveryRuntime(t.Context(), contractrecovery.Runtime{ManagementAuth: true, ManagementTLS: "self_signed", WorkingDirectory: directory}); err != nil {
		t.Fatal(err)
	}
	if err := backupstore.New(db.DB()).Save(t.Context(), contract.Option{InstanceName: "fixture-source", Interval: 3600, S3: contract.S3{Enabled: true, AccessKey: "fixture-access", SecretKey: "fixture-secret", Bucket: "fixture", EndpointURL: "https://example.invalid"}}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := managementtls.LoadOrCreate(directory, []string{"localhost"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.NewGatewayStore(db.DB()).SaveCA(t.Context(), []byte("fixture-gateway-ca"), []byte("fixture-private-gateway-key"), 0); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"site.crt", "site.key"} {
		if err := os.WriteFile(filepath.Join(directory, file), []byte("fixture "+file), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	nodes := []node.Node{{ID: "tls", Name: "TLS", Origin: "manual", Chain: []node.Protocol{{Type: "tls_termination", TLSTermination: &node.TLSTermination{TLS: node.ServerTLS{Certificates: []node.Certificate{{CertFilePath: "site.crt", KeyFilePath: "site.key"}}}}}}}}
	if native {
		nodes = append(nodes,
			node.Node{ID: "tail", Name: "Tailnet", Origin: "manual", Chain: []node.Protocol{{Type: "tailscale", Tailscale: &node.Tailscale{AuthKey: "tskey-fixture", Hostname: "fixture-host"}}}},
			node.Node{ID: "zt", Name: "ZeroTier", Origin: "manual", Chain: []node.Protocol{{Type: "zerotier", ZeroTier: &node.ZeroTier{NetworkID: "8056c2e21c000001", Identity: "fixture"}}}})
	}
	for _, item := range nodes {
		if err := store.NewNodeStore(db.DB()).Save(t.Context(), item, 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.NewGatewayStore(db.DB()).Save(t.Context(), gateway.Config{Gateways: []gateway.Gateway{{ID: "site", Name: "Site", CertificateFile: "site.crt", KeyFile: "site.key", Default: gateway.Action{Type: "reject", Status: 503}}}}); err != nil {
		t.Fatal(err)
	}
	paths := []string{"logs/huge.log", "cache/large.tmp"}
	if native {
		paths = append(paths, "tailscale/fixture-host/tailscaled.state", "zerotier/fixture/1-0000000000000000-0000000000000000.state", "zerotier/fixture/.zt-state-temporary", "zerotier/fixture/ignored.log")
	}
	for _, path := range paths {
		full := filepath.Join(directory, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("fixture identity or ignored file"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.DB().ExecContext(t.Context(), "INSERT INTO statistics_kv(key,value_int,updated_at) VALUES('total_upload',42,1)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().ExecContext(t.Context(), "INSERT INTO traffic_hourly(bucket_start_utc,upload_bytes,download_bytes,updated_at) VALUES(1,100,200,1)"); err != nil {
		t.Fatal(err)
	}
	identities, err := OpenManagement(t.Context(), filepath.Join(directory, "management.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.DB().ExecContext(t.Context(), "INSERT INTO management_users(id,login,role,client_salt,credential,created_at,updated_at) VALUES('owner','owner','admin',randomblob(16),randomblob(32),1,1)"); err != nil {
		t.Fatal(err)
	}
	if err := identities.Close(); err != nil {
		t.Fatal(err)
	}
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return directory, key
}
