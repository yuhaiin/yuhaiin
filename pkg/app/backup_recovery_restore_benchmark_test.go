package app

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"filippo.io/age"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
)

func BenchmarkFullRecoveryRestoreExternalRecipient(b *testing.B) {
	if runtime.GOOS == "windows" {
		b.Skip("offline activation requires directory synchronization")
	}
	for _, size := range []int64{1 << 20, 16 << 20, 64 << 20} {
		b.Run(fmt.Sprintf("%dMiB", size>>20), func(b *testing.B) {
			source := b.TempDir()
			assets := filepath.Join(source, "web")
			if err := os.Mkdir(assets, 0o700); err != nil {
				b.Fatal(err)
			}
			file, err := os.Create(filepath.Join(assets, "fixture.bin"))
			if err != nil {
				b.Fatal(err)
			}
			if err := file.Truncate(size); err != nil {
				b.Fatal(err)
			}
			if err := file.Close(); err != nil {
				b.Fatal(err)
			}
			db, err := sqlite.Open(b.Context(), filepath.Join(source, "state.db"))
			if err != nil {
				b.Fatal(err)
			}
			if err := store.NewBackupStore(db.DB()).RecordRecoveryRuntime(b.Context(), contract.RecoveryRuntime{ManagementTLS: "disabled", WorkingDirectory: source, ExternalWebDirectory: assets}); err != nil {
				b.Fatal(err)
			}
			if err := db.Close(); err != nil {
				b.Fatal(err)
			}
			identity, err := age.GenerateX25519Identity()
			if err != nil {
				b.Fatal(err)
			}
			archive := filepath.Join(b.TempDir(), "full.yhb")
			manifest, err := CreateOfflineRecovery(b.Context(), source, archive, store.RecoveryEncryption{Recipient: identity.Recipient().String()}, RecoveryCreateOptions{ConfirmedMaintenance: true})
			if err != nil {
				b.Fatal(err)
			}
			target := b.TempDir()
			key := store.RecoveryDecryption{Identity: identity.String()}
			options := RecoveryRestoreOptions{Mode: "original", ConfirmedMaintenance: true, ConfirmBackupID: manifest.ID,
				ConfirmSourceInstanceID: manifest.InstanceID, ConfirmTargetInstanceID: "empty", ConfirmSourceStopped: true, ConfirmCredentialRevival: true}
			b.SetBytes(size)
			b.ReportAllocs()
			for b.Loop() {
				input, err := os.Open(archive)
				if err != nil {
					b.Fatal(err)
				}
				_, restoreErr := RestoreOfflineRecovery(b.Context(), target, input, key, options)
				if err := input.Close(); err != nil || restoreErr != nil {
					b.Fatal(restoreErr, err)
				}
				b.StopTimer()
				// This is a task-owned empty target with no service/owners. Real
				// startup and rollback are measured by separate integration tests.
				if err := os.RemoveAll(target); err != nil {
					b.Fatal(err)
				}
				if err := os.Mkdir(target, 0o700); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
			}
		})
	}
}
