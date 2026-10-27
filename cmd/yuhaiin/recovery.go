package main

import (
	"context"
	"encoding/json/v2"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/app"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/store"
)

func recoveryCommand(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return executeRecoveryCommand(ctx, args, os.Stdout)
}

// These commands never start the server or a network listener. Verification
// does not open deployment databases; creation and activation require stopped
// writer owners. Restoration is committed only by a later healthy server start.
func executeRecoveryCommand(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: yuhaiin recovery <keygen|create|verify|preview|restore|rollback> -help")
	}
	action := args[0]
	flags := flag.NewFlagSet("recovery", flag.ContinueOnError)
	timeout := flags.Duration("timeout", 30*time.Minute, "maximum command duration (up to 24h)")
	archive := flags.String("archive", "", "encrypted recovery archive")
	identityFile := flags.String("identity-file", "", "private X25519 identity file; newly created for keygen")
	passphraseFile := flags.String("passphrase-file", "", "private file containing the recovery passphrase")
	stagingParent := flags.String("staging-parent", os.TempDir(), "parent for temporary private verification staging")
	directory := flags.String("path", configuration.DataDir.Load(), "deployment data directory for backup or recovery")
	managementAuth := flags.Bool("management-auth", false, "management identities were enabled, for explicit startup inputs")
	recipient := flags.String("recipient", "", "external public age X25519 recipient for create")
	maintenance := flags.Bool("maintenance", false, "confirm server and external identity/certificate writers are stopped")
	includeHistory := flags.Bool("include-history", false, "include optional traffic and connection history")
	tlsMode := flags.String("management-tls", "", "override recorded management TLS mode: disabled, self_signed, files")
	certFile := flags.String("https-cert", "", "management certificate file for explicit startup inputs")
	keyFile := flags.String("https-key", "", "management private key file for explicit startup inputs")
	workingDirectory := flags.String("working-directory", "", "absolute working directory for explicit startup inputs")
	externalWeb := flags.String("eweb", "", "external web assets for explicit startup inputs")
	mode := flags.String("mode", "", "explicit recovery mode: original or clone")
	confirmBackup := flags.String("confirm-backup", "", "backup UUID from preview")
	confirmSource := flags.String("confirm-source-instance", "", "source instance UUID from preview")
	confirmTarget := flags.String("confirm-target-instance", "", "target identity from preview, including empty/unreadable")
	sourceStopped := flags.Bool("source-stopped", false, "confirm original deployment will not run with restored machine identities")
	restoreCredentials := flags.Bool("restore-credentials", false, "acknowledge restoring older credential/device validity state")
	transaction := flags.String("transaction-id", "", "pending transaction UUID for offline rollback")
	allowVersionChange := flags.Bool("allow-version-change", false, "acknowledge reviewed application version difference; unsupported schemas remain rejected")
	adoptStartup := flags.Bool("adopt-startup", false, "persist the restored TLS/authentication/listener/file inputs for subsequent server starts")

	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if *timeout <= 0 || *timeout > 24*time.Hour {
		return errors.New("recovery timeout must be between zero and 24 hours")
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	if flags.NArg() != 0 {
		return errors.New("unexpected recovery arguments")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	switch action {
	case "rollback":
		if *transaction == "" || *archive != "" || *identityFile != "" || *passphraseFile != "" {
			return errors.New("rollback requires -transaction-id, -path and -maintenance")
		}
		if err := app.RollbackOfflineRecovery(*directory, *transaction, *maintenance); err != nil {
			return err
		}
		return json.MarshalWrite(output, struct {
			State string `json:"state"`
		}{"rolled_back"})
	case "keygen":
		if *identityFile == "" || *archive != "" || *passphraseFile != "" {
			return errors.New("keygen requires only -identity-file")
		}
		recipient, err := store.GenerateRecoveryIdentityFile(ctx, *identityFile)
		if err != nil {
			return err
		}
		return json.MarshalWrite(output, struct {
			Recipient string `json:"recipient"`
		}{recipient})
	case "create":
		if *archive == "" || *identityFile != "" || (*recipient == "") == (*passphraseFile == "") {
			return errors.New("create requires -archive and one public -recipient or private -passphrase-file")
		}
		key := store.RecoveryEncryption{Recipient: *recipient}
		if *passphraseFile != "" {
			value, err := readRecoverySecretFile(*passphraseFile)
			if err != nil {
				return err
			}
			key.Passphrase = value
		}
		var inputs *contract.RecoveryRuntime
		if *managementAuth || *tlsMode != "" || *workingDirectory != "" || *certFile != "" || *keyFile != "" || *externalWeb != "" {
			inputs = &contract.RecoveryRuntime{ManagementAuth: *managementAuth, ManagementTLS: *tlsMode, CertificateFile: *certFile, KeyFile: *keyFile, WorkingDirectory: *workingDirectory, ExternalWebDirectory: *externalWeb}
		}
		manifest, err := app.CreateOfflineRecovery(ctx, *directory, *archive, key, app.RecoveryCreateOptions{ConfirmedMaintenance: *maintenance, IncludeHistory: *includeHistory, Runtime: inputs})
		if err != nil {
			return err
		}
		return json.MarshalWrite(output, manifest)
	case "verify", "preview", "restore":
		if *archive == "" || (*identityFile == "") == (*passphraseFile == "") {
			return errors.New("verify, preview and restore require -archive and one private key/passphrase file")
		}
		var key store.RecoveryDecryption
		if *identityFile != "" {
			value, err := readRecoverySecretFile(*identityFile)
			if err != nil {
				return err
			}
			key.Identity = value
		} else {
			value, err := readRecoverySecretFile(*passphraseFile)
			if err != nil {
				return err
			}
			key.Passphrase = value
		}
		source, err := os.Open(*archive)
		if err != nil {
			return err
		}
		defer source.Close()
		if info, err := source.Stat(); err != nil || !info.Mode().IsRegular() {
			return errors.New("recovery archive must be a regular file")
		}
		if action == "preview" {
			preview, err := app.PreviewOfflineRecovery(ctx, *directory, source, key, *mode)
			if err != nil {
				return err
			}
			return json.MarshalWrite(output, preview)
		}
		if action == "restore" {
			result, err := app.RestoreOfflineRecovery(ctx, *directory, source, key, app.RecoveryRestoreOptions{Mode: *mode, AdoptStartup: *adoptStartup,
				ConfirmedMaintenance: *maintenance, ConfirmBackupID: *confirmBackup, ConfirmSourceInstanceID: *confirmSource,
				ConfirmTargetInstanceID: *confirmTarget, ConfirmSourceStopped: *sourceStopped, ConfirmCredentialRevival: *restoreCredentials,
				AllowVersionChange: *allowVersionChange})
			if err != nil {
				return err
			}
			return json.MarshalWrite(output, result)
		}
		prepared, err := store.PrepareRecoveryArchive(ctx, source, *stagingParent, key)
		if err != nil {
			return err
		}
		defer prepared.Close()
		return json.MarshalWrite(output, prepared.Manifest)
	default:
		return errors.New("unknown recovery action; use keygen, create, verify, preview, restore or rollback")
	}
}

func readRecoverySecretFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > 1025 {
		return "", errors.New("backup key/passphrase must be a regular file of at most 1025 bytes")
	}
	// Opening the file is the OS authorization check. Enforce private Unix
	// permissions; Windows access is governed by its existing account ACLs.
	if info.Mode().Perm()&0o077 != 0 && runtime.GOOS != "windows" {
		return "", errors.New("backup key/passphrase file must have owner-only permissions (0600)")
	}
	data, err := io.ReadAll(io.LimitReader(file, 1026))
	if err != nil {
		return "", err
	}
	if len(data) > 1025 {
		return "", errors.New("backup key/passphrase file exceeds limit")
	}
	value := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if value == "" || len(value) > 1024 {
		return "", errors.New("empty or overlong backup key/passphrase")
	}
	return value, nil
}

func recordRecoveryStartup(ctx context.Context, state app.SQLStore, inputs contract.RecoveryRuntime) error {
	workingDirectory, err := os.Getwd()
	if err != nil {
		return err
	}
	inputs.WorkingDirectory = workingDirectory
	db, err := state.SQLDB(ctx)
	if err != nil {
		return err
	}
	return store.NewBackupStore(db).RecordRecoveryRuntime(ctx, inputs)
}
