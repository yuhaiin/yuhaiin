package recovery

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/testfixture"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	backuparchive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
)

// A deployment reached through a symbolic-link alias (macOS /var ->
// /private/var, a symlinked mount) must keep its files owned by the
// deployment, refuse a web root containing it, and still rebind references
// spelled through the alias on restore.
func TestRecoveryClassifiesDeploymentAliasAsInside(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory symlinks need privileges on Windows")
	}
	directory, key := testfixture.Deployment(t)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(directory, alias); err != nil {
		t.Fatal(err)
	}
	setRuntime := func(runtime contractrecovery.Runtime) {
		db, err := testfixture.OpenState(t.Context(), filepath.Join(directory, "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if err := backupstore.New(db.DB()).RecordRecoveryRuntime(t.Context(), runtime); err != nil {
			t.Fatal(err)
		}
	}
	setRuntime(contractrecovery.Runtime{ManagementAuth: true, ManagementTLS: "self_signed", WorkingDirectory: alias})
	path := filepath.Join(t.TempDir(), "full.yhb")
	manifest, err := Create(t.Context(), directory, path, backuparchive.Encryption{Recipient: key.Recipient().String()}, CreateOptions{ConfirmedMaintenance: true})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, file := range manifest.Files {
		if file.Path == "site.crt" {
			found = file.SourcePath == filepath.Join(alias, "site.crt")
		}
		if filepath.Dir(file.Path) == "dependencies" {
			t.Fatal("deployment file reached through an alias became an external dependency", file.Path)
		}
	}
	if !found {
		t.Fatal("aliased deployment file lost its configured reference", manifest.Files)
	}
	archive, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	target, _ := testfixture.Deployment(t)
	if _, err := Preview(t.Context(), target, bytes.NewReader(archive), backuparchive.Decryption{Identity: key.String()}, "original"); err != nil {
		t.Fatal("aliased reference was not rebound on restore", err)
	}

	setRuntime(contractrecovery.Runtime{ManagementAuth: true, ManagementTLS: "self_signed", WorkingDirectory: alias, ExternalWebDirectory: alias})
	if _, err := Create(t.Context(), directory, filepath.Join(t.TempDir(), "web.yhb"), backuparchive.Encryption{Recipient: key.Recipient().String()}, CreateOptions{ConfirmedMaintenance: true}); err == nil {
		t.Fatal("a web root aliasing the whole deployment was accepted")
	}
}
