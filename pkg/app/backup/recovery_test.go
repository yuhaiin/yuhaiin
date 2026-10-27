package backup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	gateway "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	node "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	managementtls "github.com/Asutorufa/yuhaiin/pkg/management/tls"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

func recoveryDeployment(t *testing.T) (string, *age.X25519Identity) {
	t.Helper()
	directory := t.TempDir()
	db, err := sqlite.Open(t.Context(), filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := backupstore.New(db.DB()).RecordRecoveryRuntime(t.Context(), contract.RecoveryRuntime{ManagementAuth: true, ManagementTLS: "self_signed", WorkingDirectory: directory}); err != nil {
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
	nodes := []node.Node{
		{ID: "tail", Name: "Tailnet", Origin: "manual", Chain: []node.Protocol{{Type: "tailscale", Tailscale: &node.Tailscale{AuthKey: "tskey-fixture", Hostname: "fixture-host"}}}},
		{ID: "zt", Name: "ZeroTier", Origin: "manual", Chain: []node.Protocol{{Type: "zerotier", ZeroTier: &node.ZeroTier{NetworkID: "8056c2e21c000001", Identity: "fixture"}}}},
		{ID: "tls", Name: "TLS", Origin: "manual", Chain: []node.Protocol{{Type: "tls_termination", TLSTermination: &node.TLSTermination{TLS: node.ServerTLS{Certificates: []node.Certificate{{CertFilePath: "site.crt", KeyFilePath: "site.key"}}}}}}},
	}
	for _, item := range nodes {
		if err := store.NewNodeStore(db.DB()).Save(t.Context(), item, 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.NewGatewayStore(db.DB()).Save(t.Context(), gateway.Config{Gateways: []gateway.Gateway{{ID: "site", Name: "Site", CertificateFile: "site.crt", KeyFile: "site.key", Default: gateway.Action{Type: "reject", Status: 503}}}}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"tailscale/fixture-host/tailscaled.state", "zerotier/fixture/1-0000000000000000-0000000000000000.state", "zerotier/fixture/.zt-state-temporary", "zerotier/fixture/ignored.log", "logs/huge.log", "cache/large.tmp"} {
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
	identities, err := sqlite.OpenManagement(t.Context(), filepath.Join(directory, "management.db"))
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

func TestFullRecoveryCreatesCoherentOwnedEncryptedSet(t *testing.T) {
	directory, key := recoveryDeployment(t)
	destination := filepath.Join(t.TempDir(), "full.yhb")
	manifest, err := CreateOfflineRecovery(t.Context(), directory, destination, backupstore.RecoveryEncryption{Recipient: key.Recipient().String()}, RecoveryCreateOptions{ConfirmedMaintenance: true})
	if err != nil {
		t.Fatal(err)
	}
	if !manifest.CompleteInventory || manifest.Runtime == nil || manifest.InstanceID == "" || manifest.Version != 2 {
		t.Fatal("complete snapshot metadata missing")
	}
	expected := map[string]bool{"state.db": false, "management.db": false, "management-tls.pem": false, "site.crt": false, "site.key": false, "tailscale/fixture-host/tailscaled.state": false, "zerotier/fixture/1-0000000000000000-0000000000000000.state": false}
	for _, file := range manifest.Files {
		if _, ok := expected[file.Path]; !ok {
			t.Fatalf("unowned data included: %s", file.Path)
		}
		expected[file.Path] = true
	}
	for path, present := range expected {
		if !present {
			t.Fatalf("required deployment file omitted: %s", path)
		}
	}
	archive, err := os.Open(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	staged, err := backupstore.PrepareRecoveryArchive(t.Context(), archive, t.TempDir(), backupstore.RecoveryDecryption{Identity: key.String()})
	if err != nil {
		t.Fatal(err)
	}
	defer staged.Close()
	state, err := sqlite.OpenSnapshotReader(t.Context(), filepath.Join(staged.Directory(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	var count int
	if err := state.QueryRowContext(t.Context(), "SELECT count(*) FROM traffic_hourly").Scan(&count); err != nil || count != 0 {
		t.Fatal("default backup retained optional history")
	}
	if err := state.QueryRowContext(t.Context(), "SELECT value_int FROM statistics_kv WHERE key='total_upload'").Scan(&count); err != nil || count != 42 {
		t.Fatal("full backup dropped cumulative counters")
	}
	cert, private, _, err := store.NewGatewayStore(state).LoadCA(t.Context())
	if err != nil || !bytes.Equal(cert, []byte("fixture-gateway-ca")) || !bytes.Equal(private, []byte("fixture-private-gateway-key")) {
		t.Fatal("full backup lost Gateway CA")
	}
	identity, err := sqlite.OpenSnapshotReader(t.Context(), filepath.Join(staged.Directory(), "management.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Close()
	if err := identity.QueryRowContext(t.Context(), "SELECT count(*) FROM management_users WHERE id='owner' AND credential IS NOT NULL").Scan(&count); err != nil || count != 1 {
		t.Fatal("management verifier state missing")
	}
	source, err := sqlite.OpenSnapshotReader(t.Context(), filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if err := source.QueryRowContext(t.Context(), "SELECT count(*) FROM statistics_kv WHERE key='total_upload'").Scan(&count); err != nil || count != 1 {
		t.Fatal("backup altered source history")
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := CreateOfflineRecovery(t.Context(), directory, filepath.Join(t.TempDir(), "history.yhb"), backupstore.RecoveryEncryption{Recipient: key.Recipient().String()}, RecoveryCreateOptions{ConfirmedMaintenance: true, IncludeHistory: true})
	if err != nil {
		t.Fatal(err)
	}
	if again.InstanceID != manifest.InstanceID || !again.IncludesHistory {
		t.Fatal("instance identity or history choice changed")
	}
}

func TestFullRecoveryExcludesActiveOwnersAndHonorsCancellation(t *testing.T) {
	directory, key := recoveryDeployment(t)
	destination := filepath.Join(t.TempDir(), "full.yhb")
	encryption := backupstore.RecoveryEncryption{Recipient: key.Recipient().String()}
	if _, err := CreateOfflineRecovery(t.Context(), directory, destination, encryption, RecoveryCreateOptions{}); err == nil {
		t.Fatal("maintenance acknowledgement not required")
	}
	owner, err := lockfile.Acquire(filepath.Join(directory, ".configuration.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateOfflineRecovery(t.Context(), directory, destination, encryption, RecoveryCreateOptions{ConfirmedMaintenance: true}); err == nil {
		t.Fatal("active lifecycle owner ignored")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sqlite.OpenManagement(t.Context(), filepath.Join(directory, "management.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateOfflineRecovery(t.Context(), directory, destination, encryption, RecoveryCreateOptions{ConfirmedMaintenance: true}); err == nil {
		t.Fatal("active embedded database owner ignored")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := CreateOfflineRecovery(ctx, directory, destination, encryption, RecoveryCreateOptions{ConfirmedMaintenance: true}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled full backup accepted")
	}
	leftovers, _ := filepath.Glob(filepath.Join(directory, ".recovery-snapshot-*"))
	if len(leftovers) != 0 {
		t.Fatal("failed backup leaked private staging")
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed backup published an archive")
	}
}

func TestFullRecoveryCapturesExternalDependenciesAndRejectsMissingOnes(t *testing.T) {
	directory, key := recoveryDeployment(t)
	outside := filepath.Join(t.TempDir(), "external.pem")
	if err := os.WriteFile(outside, []byte("external certificate fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sqlite.Open(t.Context(), filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := store.NewNodeStore(db.DB()).Get(t.Context(), "tls")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Chain[0].TLSTermination.TLS.Certificates[0].CertFilePath = outside
	if err := store.NewNodeStore(db.DB()).Save(t.Context(), cfg, 0); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	manifest, err := CreateOfflineRecovery(t.Context(), directory, filepath.Join(t.TempDir(), "full.yhb"), backupstore.RecoveryEncryption{Recipient: key.Recipient().String()}, RecoveryCreateOptions{ConfirmedMaintenance: true})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, file := range manifest.Files {
		if file.SourcePath == outside {
			found = true
			if filepath.IsAbs(file.Path) {
				t.Fatal("external destination escaped archive namespace")
			}
		}
	}
	if !found {
		t.Fatal("external dependency omitted")
	}
	if err := os.Remove(outside); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateOfflineRecovery(t.Context(), directory, filepath.Join(t.TempDir(), "broken.yhb"), backupstore.RecoveryEncryption{Recipient: key.Recipient().String()}, RecoveryCreateOptions{ConfirmedMaintenance: true}); err == nil {
		t.Fatal("missing required dependency silently omitted")
	}
}

func TestFullRecoveryRefusesIncompleteInventoryAndUnsafeWebRoot(t *testing.T) {
	for _, fault := range []string{"missing-management", "invalid-node", "invalid-inbound", "whole-data-web-root"} {
		t.Run(fault, func(t *testing.T) {
			directory, key := recoveryDeployment(t)
			switch fault {
			case "missing-management":
				if err := os.Remove(filepath.Join(directory, "management.db")); err != nil {
					t.Fatal(err)
				}
			default:
				db, err := sqlite.Open(t.Context(), filepath.Join(directory, "state.db"))
				if err != nil {
					t.Fatal(err)
				}
				switch fault {
				case "invalid-node":
					_, err = db.DB().ExecContext(t.Context(), "UPDATE nodes_v2 SET data_json='{}' WHERE id='tls'")
				case "invalid-inbound":
					_, err = db.DB().ExecContext(t.Context(), "INSERT INTO inbounds_v2(id,name,enabled,network_type,protocol_type,transport_types_json,data_json,updated_at) VALUES('broken','Broken',0,'tcp','http','[]','{}',1)")
				case "whole-data-web-root":
					err = backupstore.New(db.DB()).RecordRecoveryRuntime(t.Context(), contract.RecoveryRuntime{ManagementTLS: "disabled", WorkingDirectory: directory, ExternalWebDirectory: directory})
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
			}
			destination := filepath.Join(t.TempDir(), "full.yhb")
			if _, err := CreateOfflineRecovery(t.Context(), directory, destination, backupstore.RecoveryEncryption{Recipient: key.Recipient().String()}, RecoveryCreateOptions{ConfirmedMaintenance: true}); err == nil {
				t.Fatal("incomplete/unsafe inventory was marked complete")
			}
			if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid full backup was published")
			}
			staging, _ := filepath.Glob(filepath.Join(directory, ".recovery-snapshot-*"))
			if len(staging) != 0 {
				t.Fatal("failed inventory leaked plaintext staging")
			}
		})
	}
}
