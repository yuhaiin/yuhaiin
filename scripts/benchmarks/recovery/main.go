// Generates task-owned, zero-payload fixtures for standalone restore RSS checks.
// Private decryption material is placed in a separate private directory and is
// never printed. The JSON describes paths/identifiers for a fresh empty target.
package main

import (
	"context"
	"encoding/json/v2"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	recovery "github.com/Asutorufa/yuhaiin/pkg/app/backup/recovery"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	backuparchive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() (resultErr error) {
	size := flag.Int64("size-mib", 64, "zero-filled asset size, 1..1024 MiB")
	flag.Parse()
	if *size < 1 || *size > 1024 || flag.NArg() != 0 {
		return fmt.Errorf("size-mib must be 1..1024")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	root, err := os.MkdirTemp("", ".recovery-resource-fixture-*")
	if err != nil {
		return err
	}
	defer func() {
		if resultErr != nil {
			_ = os.RemoveAll(root)
		}
	}()
	keyDirectory, err := os.MkdirTemp("", ".recovery-resource-key-*")
	if err != nil {
		return err
	}
	defer func() {
		if resultErr != nil {
			_ = os.RemoveAll(keyDirectory)
		}
	}()
	identityFile := filepath.Join(keyDirectory, "identity")
	recipient, err := backuparchive.GenerateIdentityFile(ctx, identityFile)
	if err != nil {
		return err
	}
	source, target := filepath.Join(root, "source"), filepath.Join(root, "target")
	assets := filepath.Join(source, "web")
	for _, directory := range []string{assets, target} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return err
		}
	}
	file, err := os.OpenFile(filepath.Join(assets, "fixture.bin"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	err = file.Truncate(*size << 20)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	db, err := sqlite.Open(ctx, filepath.Join(source, "state.db"))
	if err != nil {
		return err
	}
	err = backupstore.New(db.DB()).RecordRecoveryRuntime(ctx, contractrecovery.Runtime{ManagementTLS: "disabled", WorkingDirectory: source, ExternalWebDirectory: assets})
	closeErr = db.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	archive := filepath.Join(root, "full.yhb")
	manifest, err := recovery.Create(ctx, source, archive, backuparchive.Encryption{Recipient: recipient}, recovery.CreateOptions{ConfirmedMaintenance: true})
	if err != nil {
		return err
	}
	return json.MarshalWrite(os.Stdout, struct {
		Root         string `json:"root"`
		KeyDirectory string `json:"keyDirectory"`
		IdentityFile string `json:"identityFile"`
		Archive      string `json:"archive"`
		Target       string `json:"target"`
		BackupID     string `json:"backupId"`
		InstanceID   string `json:"instanceId"`
	}{root, keyDirectory, identityFile, archive, target, manifest.ID, manifest.InstanceID})
}
