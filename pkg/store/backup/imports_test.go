package backup

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"uuid"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestRecoveryAdmissionSerializesCapturesAndOtherRestores(t *testing.T) {
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	owner := New(db.DB())
	preview := func() RecoveryImportRecord {
		t.Helper()
		item := RecoveryImportRecord{ID: uuid.New().String(), PreviewID: uuid.New().String(), State: "uploading", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), Size: 1, SHA256: strings.Repeat("0", 64), Owner: "fixture", Plan: "private-plan"}
		if err := owner.AddRecoveryImport(t.Context(), item); err != nil {
			t.Fatal(err)
		}
		item.State = "previewed"
		if err := owner.SaveRecoveryImport(t.Context(), item, "uploading"); err != nil {
			t.Fatal(err)
		}
		item.State, item.Activation = "activating", new(contractrecovery.ImportActivateRequest{ID: item.ID})
		return item
	}
	first, second := preview(), preview()
	job := RecoveryJob{ID: uuid.New().String(), State: "queued", CreatedAt: time.Now()}
	if err := owner.EnqueueRecovery(t.Context(), job); err != nil {
		t.Fatal(err)
	}
	if err := owner.AdmitRecoveryImport(t.Context(), first); !errors.Is(err, contract.ErrBusy) {
		t.Fatal("restore raced an admitted capture", err)
	}
	if _, err := db.DB().ExecContext(t.Context(), "DELETE FROM backup_recovery_history WHERE id=?", job.ID); err != nil {
		t.Fatal(err)
	}
	if err := owner.AdmitRecoveryImport(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if err := owner.AdmitRecoveryImport(t.Context(), second); !errors.Is(err, contract.ErrBusy) {
		t.Fatal("two restorations were admitted", err)
	}
	if err := owner.SaveRecoveryImport(t.Context(), second, "previewed"); err == nil {
		t.Fatal("migration 23 did not protect alternate state writers")
	}
	if err := owner.EnqueueRecovery(t.Context(), job); !errors.Is(err, contract.ErrBusy) {
		t.Fatal("capture raced an admitted restore", err)
	}
	first.State, first.Activation = "uploaded", nil
	if err := owner.SaveRecoveryImport(t.Context(), first, "activating"); err != nil {
		t.Fatal(err)
	}
	if err := owner.AdmitRecoveryImport(t.Context(), second); err != nil {
		t.Fatal("retired maintenance kept admission blocked", err)
	}
}
