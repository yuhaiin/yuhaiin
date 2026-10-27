package recovery

import (
	"context"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
	"uuid"

	"github.com/Asutorufa/yuhaiin/internal/version"
	backupfs "github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/backupfs"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	backuparchive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

type RestoreOptions struct {
	Mode                     string
	ConfirmedMaintenance     bool
	ConfirmBackupID          string
	ConfirmSourceInstanceID  string
	ConfirmTargetInstanceID  string
	ConfirmSourceStopped     bool
	ConfirmCredentialRevival bool
	AllowVersionChange       bool
	AdoptStartup             bool
}

// Preview decrypts and validates a complete archive and computes
// confined destinations. It performs no writes to the target deployment.
func Preview(ctx context.Context, directory string, input io.Reader, key backuparchive.Decryption, mode string) (contract.RecoveryRestorePreview, error) {
	prepared, err := backuparchive.Prepare(ctx, input, os.TempDir(), key)
	if err != nil {
		return contract.RecoveryRestorePreview{}, err
	}
	defer prepared.Close()
	preview, _, err := prepareRecoveryRestore(ctx, directory, prepared, mode)
	return preview, err
}

func Restore(ctx context.Context, directory string, input io.Reader, key backuparchive.Decryption, options RestoreOptions) (contract.RecoveryRestoreResult, error) {
	var empty contract.RecoveryRestoreResult
	if !options.ConfirmedMaintenance {
		return empty, errors.New("restore requires a confirmed maintenance window with all writers stopped")
	}
	directory, err := backupfs.CanonicalDirectory(directory)
	if err != nil {
		return empty, err
	}
	lifecycle, err := lockfile.Acquire(filepath.Join(directory, ".configuration.lock"))
	if err != nil {
		return empty, err
	}
	defer lifecycle.Close()
	if err := requireRecoveryLifecycle(directory, lifecycle); err != nil {
		return empty, err
	}
	if tx, err := readRecoveryTransaction(directory); err != nil || (tx != nil && tx.Phase != "committed") {
		return empty, errors.Join(errors.New("complete or roll back the existing recovery first"), err)
	}
	prepared, err := backuparchive.Prepare(ctx, input, directory, key)
	if err != nil {
		return empty, err
	}
	defer prepared.Close()
	preview, tx, err := prepareRecoveryRestore(ctx, directory, prepared, options.Mode)
	if err != nil {
		return empty, err
	}
	if options.ConfirmBackupID != preview.Manifest.ID || options.ConfirmSourceInstanceID != preview.Manifest.InstanceID || options.ConfirmTargetInstanceID != preview.TargetInstanceID {
		return empty, errors.New("restore requires matching backup, source-instance and target-instance confirmations from preview")
	}
	if preview.Manifest.Build.Version != version.Version && !options.AllowVersionChange {
		return empty, errors.New("backup application version differs; review compatibility and use explicit offline version-change acknowledgement")
	}
	if options.Mode == "original" && (!options.ConfirmSourceStopped || !options.ConfirmCredentialRevival) {
		return empty, errors.New("original-instance recovery requires confirmation that the original is stopped and that old credentials/device identities may become valid again")
	}
	tx.AdoptStartup = options.AdoptStartup
	tx.PreviousStartup, err = readRecoveryStartupBinding(directory)
	if err != nil {
		return empty, err
	}
	if err := activateRecoverySet(ctx, directory, tx, nil); err != nil {
		return empty, err
	}
	return recoveryResult(*tx, tx.Phase), nil
}

func recoveryTargetID(ctx context.Context, directory string) (string, error) {
	path := filepath.Join(directory, "state.db")
	if info, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return "empty", nil
	} else if err != nil {
		return "", err
	} else if !info.Mode().IsRegular() {
		return "", errors.New("target database must be a regular file")
	}
	id, err := sqlite.RecoveryInstanceID(ctx, path, false)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "", err
	}
	if err != nil {
		// An explicit unreadable confirmation permits recovery when the old
		// instance cannot start. Raw originals still enter the recovery point.
		return "unreadable", nil
	}
	return id, nil
}

func prepareRecoveryRestore(ctx context.Context, directory string, prepared *backuparchive.Prepared, mode string) (contract.RecoveryRestorePreview, *recoveryTransaction, error) {
	var empty contract.RecoveryRestorePreview
	if mode != "original" && mode != "clone" {
		return empty, nil, errors.New("recovery mode must explicitly be original or clone")
	}
	manifest := prepared.Manifest
	if !manifest.CompleteInventory || manifest.Runtime == nil || manifest.Version < 2 {
		return empty, nil, errors.New("automatic restore requires a complete version-2 deployment inventory")
	}
	if manifest.Build.Platform != runtime.GOOS || manifest.Build.Architecture != runtime.GOARCH {
		return empty, nil, errors.New("restore platform/architecture differs; use a reviewed offline migration")
	}
	directory, err := backupfs.CanonicalDirectory(directory)
	if err != nil {
		return empty, nil, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return empty, nil, err
	}
	defer root.Close()
	if err := ctx.Err(); err != nil {
		return empty, nil, err
	}
	bound, err := sqlite.RecoveryInstanceID(ctx, filepath.Join(prepared.Directory(), "state.db"), false)
	if err != nil || bound != manifest.InstanceID {
		return empty, nil, errors.New("archive instance identifier disagrees with its configuration database")
	}
	targetID, err := recoveryTargetID(ctx, directory)
	if err != nil {
		return empty, nil, err
	}
	preview := contract.RecoveryRestorePreview{Manifest: manifest, Mode: mode, TargetInstanceID: targetID, InstanceID: manifest.InstanceID, Runtime: *manifest.Runtime, Warnings: []string{"service_restart_required", "recovery_point_contains_private_identity_material"}}
	if manifest.Build.Version != version.Version {
		preview.Warnings = append(preview.Warnings, "application_version_differs_requires_offline_review")
	}
	if mode == "clone" {
		preview.InstanceID = uuid.New().String()
		preview.Warnings = append(preview.Warnings, "clone_credentials_reset", "clone_outbounds_and_listeners_disabled", "clone_protocol_reenrollment_required", "clone_s3_credentials_and_schedules_disabled")
	} else {
		preview.Warnings = append(preview.Warnings, "original_instance_must_be_stopped", "revoked_credentials_may_be_restored", "quota_and_usage_state_can_move_backwards")
	}
	if targetID != "empty" && targetID != manifest.InstanceID {
		preview.Warnings = append(preview.Warnings, "different_or_damaged_target_identity_will_be_replaced")
	}
	projection, err := projectRecoveryFiles(manifest)
	if err != nil {
		return empty, nil, err
	}
	if err := projectRecoveryTailnetIdentities(ctx, prepared.Directory(), manifest, &projection); err != nil {
		return empty, nil, err
	}
	resolve := func(value string) (string, error) {
		original := recoveryAbsolute(manifest.Runtime.WorkingDirectory, value)
		mapped, ok := projection.sources[original]
		if !ok {
			return "", errors.New("configuration references a file absent from the authenticated inventory")
		}
		return filepath.Join(directory, filepath.FromSlash(mapped)), nil
	}
	preview.Runtime.WorkingDirectory = directory
	if preview.Runtime.ManagementTLS == "files" {
		preview.Runtime.CertificateFile, err = resolve(preview.Runtime.CertificateFile)
		if err == nil {
			preview.Runtime.KeyFile, err = resolve(preview.Runtime.KeyFile)
		}
		if err != nil {
			return empty, nil, err
		}
	}
	if preview.Runtime.ExternalWebDirectory != "" {
		preview.Runtime.ExternalWebDirectory = filepath.Join(directory, filepath.FromSlash(projection.web))
	}
	if err := relocateRecoveryFiles(prepared.Directory(), projection.files); err != nil {
		return empty, nil, err
	}
	if err := rewriteRecoveryConfiguration(ctx, prepared.Directory(), preview.InstanceID, &preview.Runtime, resolve, mode); err != nil {
		return empty, nil, err
	}
	tx := &recoveryTransaction{Version: 1, ID: uuid.New().String(), BackupID: manifest.ID, InstanceID: preview.InstanceID, Phase: "activating", Stage: filepath.Base(prepared.Directory()), CreatedAt: time.Now().UTC(), Runtime: preview.Runtime}
	deletions, err := recoveryIdentityReplacements(ctx, prepared.Directory(), directory)
	if err != nil {
		return empty, nil, err
	}
	for _, path := range deletions {
		if _, exists := projection.files[path]; !exists {
			projection.files[path] = ""
		}
	}
	for _, name := range []string{"state.db", "management.db"} {
		for _, suffix := range []string{"-wal", "-shm", "-journal"} {
			projection.files[name+suffix] = ""
		}
	}
	if mode == "clone" {
		for path := range projection.files {
			if strings.HasPrefix(path, "tailscale/") || strings.HasPrefix(path, "zerotier/") || path == "management-tls.pem" && preview.Runtime.ManagementTLS == "self_signed" {
				projection.files[path] = ""
			}
		}
		projection.files["management.db"] = "management.db"
		if preview.Runtime.ManagementTLS == "self_signed" {
			projection.files["management-tls.pem"] = ""
		}
	} else if _, exists := projection.files["management.db"]; !exists {
		projection.files["management.db"] = ""
	}
	for _, path := range slices.Sorted(maps.Keys(projection.files)) {
		exists, err := backupfs.Destination(root, filepath.FromSlash(path), false)
		if err != nil {
			return empty, nil, err
		}
		install := projection.files[path] != ""
		tx.Moves = append(tx.Moves, recoveryMove{Path: filepath.FromSlash(path), HadOriginal: exists, Install: install})
		preview.Files = append(preview.Files, contract.RecoveryChange{Path: path, Replace: exists, Install: install})
	}
	if err := tx.validate(); err != nil {
		return empty, nil, err
	}
	return preview, tx, nil
}
