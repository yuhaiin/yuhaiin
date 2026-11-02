package recovery

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	testfixture "github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/testfixture"
	nodecontract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tailscale"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
	backuparchive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
)

func TestRecoveryKeepsLiteAndTSNetIdentitiesSeparate(t *testing.T) {
	source, key := testfixture.Deployment(t)
	input := nodecontract.TailscaleLite{AuthKey: "tskey-lite-fixture", Hostname: "fixture-host"}
	db, err := testfixture.OpenState(t.Context(), filepath.Join(source, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	node := nodecontract.Node{ID: "lite", Name: "Lite", Origin: "manual", Enabled: true, Chain: []nodecontract.Protocol{{Type: "tailscale-lite", TailscaleLite: &input}}}
	if err := store.NewNodeStore(db.DB()).Save(t.Context(), node, 0); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	directory, err := tailscale.LiteRecoveryDirectory(source, input)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	content := []byte("fixture lite identity")
	if err := os.WriteFile(filepath.Join(directory, "lite.json"), content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "ignored.log"), []byte("not identity"), 0600); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(t.TempDir(), "full.yhb")
	manifest, err := Create(t.Context(), source, archivePath, backuparchive.Encryption{Recipient: key.Recipient().String()}, CreateOptions{ConfirmedMaintenance: true})
	if err != nil {
		t.Fatal(err)
	}
	liteFiles := 0
	for _, file := range manifest.Files {
		if strings.HasPrefix(file.Path, "tailscale-lite/") {
			liteFiles++
			if filepath.Base(file.Path) != "lite.json" || file.Role != "protocol_identity" {
				t.Fatal("incorrect lite inventory", file)
			}
		}
	}
	if liteFiles != 1 {
		t.Fatal("missing lite identity", liteFiles)
	}
	archive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"original", "clone"} {
		t.Run(mode, func(t *testing.T) {
			target := t.TempDir()
			preview, err := Preview(t.Context(), target, bytes.NewReader(archive), backuparchive.Decryption{Identity: key.String()}, mode)
			if err != nil {
				t.Fatal(err)
			}
			result, err := Restore(t.Context(), target, bytes.NewReader(archive), backuparchive.Decryption{Identity: key.String()}, RestoreOptions{Mode: mode, ConfirmedMaintenance: true, ConfirmBackupID: manifest.ID, ConfirmSourceInstanceID: manifest.InstanceID, ConfirmTargetInstanceID: preview.TargetInstanceID, ConfirmSourceStopped: true, ConfirmCredentialRevival: true})
			if err != nil {
				t.Fatal(err)
			}
			files, err := tailscale.LiteRecoveryFiles(target, input)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "clone" {
				if len(files) != 0 {
					t.Fatal("clone retained lite identity", files)
				}
			} else {
				if len(files) != 1 {
					t.Fatal("original lost lite identity", files)
				}
				got, err := os.ReadFile(files[0])
				if err != nil || !bytes.Equal(got, content) {
					t.Fatal("lite identity changed", err)
				}
				old, err := tailscale.RecoveryFiles(target, nodecontract.Tailscale{AuthKey: "tskey-fixture", Hostname: "fixture-host"})
				if err != nil || len(old) != 1 || old[0] == files[0] {
					t.Fatal("tsnet identity lost or shared", old, err)
				}
			}
			restored, err := sqlite.OpenSnapshotReader(t.Context(), filepath.Join(target, "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			saved, err := store.NewNodeStore(restored).Get(t.Context(), "lite")
			if err != nil {
				t.Fatal(err)
			}
			if err := restored.Close(); err != nil {
				t.Fatal(err)
			}
			if saved.Chain[0].Type != "tailscale-lite" || saved.Chain[0].TailscaleLite == nil {
				t.Fatal("restored the wrong runtime", saved)
			}
			if mode == "clone" && saved.Enabled {
				t.Fatal("clone retained an active outbound")
			}
			if err := Rollback(target, result.TransactionID, true); err != nil {
				t.Fatal(err)
			}
			if files, err := tailscale.LiteRecoveryFiles(target, input); err != nil || len(files) != 0 {
				t.Fatal("rollback retained lite identity", files, err)
			}
			if _, err := os.Stat(filepath.Join(target, "state.db")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("rollback retained restored database", err)
			}
		})
	}
}
