package recovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/backupfs"
	testfixture "github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/testfixture"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	backuparchive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

func TestFullRecoveryReservesCiphertextBesideTheStillAllocatedSnapshot(t *testing.T) {
	directory, key := testfixture.Deployment(t)
	destination := filepath.Join(t.TempDir(), "full.yhb")
	var snapshot string
	var ciphertextBudget int64
	_, err := Create(t.Context(), directory, destination, backuparchive.Encryption{Recipient: key.Recipient().String()}, CreateOptions{ConfirmedMaintenance: true, checkSpace: func(path string, bytes int64) error {
		if strings.HasPrefix(filepath.Base(path), ".recovery-snapshot-") {
			snapshot = path
		}
		if path == filepath.Dir(destination) && bytes > 0 {
			ciphertextBudget = bytes
			if _, err := os.Stat(filepath.Join(snapshot, "state.db")); err != nil {
				t.Fatal("ciphertext admission forgot concurrent plaintext allocation", err)
			}
		}
		return backupfs.CheckStagingSpace(path, bytes)
	}})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(destination)
	if err != nil || ciphertextBudget < info.Size() || ciphertextBudget <= 2<<20 {
		t.Fatal("ciphertext/manifest/framing were not budgeted", ciphertextBudget, err)
	}
}

func TestFullRecoveryRefusesInsufficientSpaceAtEveryOutputBoundary(t *testing.T) {
	for _, boundary := range []string{"source_reserve", "destination_reserve", "configuration_snapshot", "management_snapshot", "dependency", "ciphertext"} {
		t.Run(boundary, func(t *testing.T) {
			directory, key := testfixture.Deployment(t)
			// Allocate the ordinary stable backup ID before the unchanged-source
			// assertion; first capture otherwise legitimately initializes it.
			if _, err := sqlite.RecoveryInstanceID(t.Context(), filepath.Join(directory, "state.db"), true); err != nil {
				t.Fatal(err)
			}
			sourceHashes := map[string][32]byte{}
			for _, name := range []string{"state.db", "management.db", "management-tls.pem", "site.key"} {
				data, err := os.ReadFile(filepath.Join(directory, name))
				if err != nil {
					t.Fatal(err)
				}
				sourceHashes[name] = sha256.Sum256(data)
			}
			destination := filepath.Join(t.TempDir(), "full.yhb")
			denied := errors.New("fixture filesystem cannot preserve its reserve")
			positive, rejected := 0, false
			options := CreateOptions{ConfirmedMaintenance: true, checkSpace: func(path string, bytes int64) error {
				stage := strings.HasPrefix(filepath.Base(path), ".recovery-snapshot-")
				if stage && bytes > 0 {
					positive++
				}
				fail := boundary == "source_reserve" && path == directory && bytes == 0 ||
					boundary == "destination_reserve" && path == filepath.Dir(destination) && bytes == 0 ||
					boundary == "configuration_snapshot" && stage && positive == 1 ||
					boundary == "management_snapshot" && stage && positive == 2 ||
					boundary == "dependency" && stage && positive == 3 ||
					boundary == "ciphertext" && path == filepath.Dir(destination) && bytes > 0
				if fail {
					rejected = true
					return denied
				}
				return nil
			}}
			_, err := Create(t.Context(), directory, destination, backuparchive.Encryption{Recipient: key.Recipient().String()}, options)
			if !errors.Is(err, denied) || !rejected {
				t.Fatal("space rejection was bypassed", boundary, positive, err)
			}
			if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed capture published an archive", err)
			}
			for _, parent := range []string{directory, filepath.Dir(destination)} {
				entries, err := os.ReadDir(parent)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), ".recovery-snapshot-") || strings.HasPrefix(entry.Name(), ".recovery-write-") {
						t.Fatal("space rejection retained private staging", entry.Name())
					}
				}
			}
			for name, expected := range sourceHashes {
				data, err := os.ReadFile(filepath.Join(directory, name))
				if err != nil || sha256.Sum256(data) != expected {
					t.Fatal("space rejection changed source state", name, err)
				}
			}
			source, err := testfixture.OpenState(t.Context(), filepath.Join(directory, "state.db"))
			if err != nil {
				t.Fatal("source no longer opens after failed capture", err)
			}
			if err := source.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFullRecoveryCreatesCoherentOwnedEncryptedSet(t *testing.T) {
	directory, key := testfixture.Deployment(t)
	destination := filepath.Join(t.TempDir(), "full.yhb")
	manifest, err := Create(t.Context(), directory, destination, backuparchive.Encryption{Recipient: key.Recipient().String()}, CreateOptions{ConfirmedMaintenance: true})
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
	staged, err := backuparchive.Prepare(t.Context(), archive, t.TempDir(), backuparchive.Decryption{Identity: key.String()})
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
	again, err := Create(t.Context(), directory, filepath.Join(t.TempDir(), "history.yhb"), backuparchive.Encryption{Recipient: key.Recipient().String()}, CreateOptions{ConfirmedMaintenance: true, IncludeHistory: true})
	if err != nil {
		t.Fatal(err)
	}
	if again.InstanceID != manifest.InstanceID || !again.IncludesHistory {
		t.Fatal("instance identity or history choice changed")
	}
}

func TestFullRecoveryExcludesActiveOwnersAndHonorsCancellation(t *testing.T) {
	directory, key := testfixture.Deployment(t)
	destination := filepath.Join(t.TempDir(), "full.yhb")
	encryption := backuparchive.Encryption{Recipient: key.Recipient().String()}
	if _, err := Create(t.Context(), directory, destination, encryption, CreateOptions{}); err == nil {
		t.Fatal("maintenance acknowledgement not required")
	}
	owner, err := lockfile.Acquire(filepath.Join(directory, ".configuration.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Create(t.Context(), directory, destination, encryption, CreateOptions{ConfirmedMaintenance: true}); err == nil {
		t.Fatal("active lifecycle owner ignored")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := testfixture.OpenManagement(t.Context(), filepath.Join(directory, "management.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Create(t.Context(), directory, destination, encryption, CreateOptions{ConfirmedMaintenance: true}); err == nil {
		t.Fatal("active embedded database owner ignored")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Create(ctx, directory, destination, encryption, CreateOptions{ConfirmedMaintenance: true}); !errors.Is(err, context.Canceled) {
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
	directory, key := testfixture.Deployment(t)
	outside := filepath.Join(t.TempDir(), "external.pem")
	if err := os.WriteFile(outside, []byte("external certificate fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := testfixture.OpenState(t.Context(), filepath.Join(directory, "state.db"))
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
	manifest, err := Create(t.Context(), directory, filepath.Join(t.TempDir(), "full.yhb"), backuparchive.Encryption{Recipient: key.Recipient().String()}, CreateOptions{ConfirmedMaintenance: true})
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
	if _, err := Create(t.Context(), directory, filepath.Join(t.TempDir(), "broken.yhb"), backuparchive.Encryption{Recipient: key.Recipient().String()}, CreateOptions{ConfirmedMaintenance: true}); err == nil {
		t.Fatal("missing required dependency silently omitted")
	}
}

func TestFullRecoveryRefusesIncompleteInventoryAndUnsafeWebRoot(t *testing.T) {
	for _, fault := range []string{"missing-management", "invalid-node", "invalid-inbound", "whole-data-web-root"} {
		t.Run(fault, func(t *testing.T) {
			directory, key := testfixture.Deployment(t)
			switch fault {
			case "missing-management":
				if err := os.Remove(filepath.Join(directory, "management.db")); err != nil {
					t.Fatal(err)
				}
			default:
				db, err := testfixture.OpenState(t.Context(), filepath.Join(directory, "state.db"))
				if err != nil {
					t.Fatal(err)
				}
				switch fault {
				case "invalid-node":
					_, err = db.DB().ExecContext(t.Context(), "UPDATE nodes_v2 SET data_json='{}' WHERE id='tls'")
				case "invalid-inbound":
					_, err = db.DB().ExecContext(t.Context(), "INSERT INTO inbounds_v2(id,name,enabled,network_type,protocol_type,transport_types_json,data_json,updated_at) VALUES('broken','Broken',0,'tcp','http','[]','{}',1)")
				case "whole-data-web-root":
					err = backupstore.New(db.DB()).RecordRecoveryRuntime(t.Context(), contractrecovery.Runtime{ManagementTLS: "disabled", WorkingDirectory: directory, ExternalWebDirectory: directory})
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
			}
			destination := filepath.Join(t.TempDir(), "full.yhb")
			if _, err := Create(t.Context(), directory, destination, backuparchive.Encryption{Recipient: key.Recipient().String()}, CreateOptions{ConfirmedMaintenance: true}); err == nil {
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
