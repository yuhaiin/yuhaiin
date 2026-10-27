package recovery

import (
	"context"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/backupfs"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	backuparchive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

const maxPreparedImportBytes = 4 << 20

type sealedImportFile struct {
	Path          string `json:"path"`
	Size          int64  `json:"size"`
	SHA256        string `json:"sha256"`
	SchemaVersion int    `json:"schemaVersion,omitzero"`
}

type preparedImportPlan struct {
	Version     int                             `json:"version"`
	Transaction recoveryTransaction             `json:"transaction"`
	Preview     contract.RecoveryRestorePreview `json:"preview"`
	Files       []sealedImportFile              `json:"files"`
}

// Seal projected contents, including rewritten SQLite and clone identities,
// rather than reusing source-manifest digests that no longer describe staging.
func sealImport(ctx context.Context, directory string, tx *recoveryTransaction, preview contract.RecoveryRestorePreview) (*preparedImportPlan, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	plan := &preparedImportPlan{Version: 1, Transaction: *tx, Preview: preview}
	var total int64
	for _, move := range tx.Moves {
		if !move.Install {
			continue
		}
		name := filepath.Join(tx.Stage, move.Path)
		if exists, err := backupfs.Destination(root, name, false); err != nil || !exists {
			return nil, errors.New("prepared recovery file is unavailable")
		}
		file, err := root.Open(name)
		if err != nil {
			return nil, err
		}
		digest, size, hashErr := hashRecoveryOriginal(ctx, file, backuparchive.MaxDataBytes-total)
		hashErr = errors.Join(hashErr, file.Sync(), file.Close())
		if hashErr != nil {
			return nil, hashErr
		}
		total += size
		sealed := sealedImportFile{Path: move.Path, Size: size, SHA256: digest}
		if kind := importDatabaseKind(move.Path); kind != "" {
			sealed.SchemaVersion, err = sqlite.InspectBackupSnapshot(ctx, filepath.Join(directory, name), kind)
			if err != nil {
				return nil, err
			}
		}
		plan.Files = append(plan.Files, sealed)
	}
	if err := backupfs.SyncDirectory(filepath.Join(directory, tx.Stage)); err != nil {
		return nil, err
	}
	return plan, nil
}

func importDatabaseKind(path string) string {
	switch path {
	case "state.db":
		return "configuration"
	case "management.db":
		return "management"
	}
	return ""
}

func readImportPlan(item backupstore.RecoveryImportRecord) (*preparedImportPlan, error) {
	var plan preparedImportPlan
	if len(item.Plan) == 0 || len(item.Plan) > maxPreparedImportBytes || json.Unmarshal([]byte(item.Plan), &plan, json.RejectUnknownMembers(true)) != nil || plan.Version != 1 {
		return nil, errors.New("unsupported prepared recovery plan; preview the archive again")
	}
	tx := &plan.Transaction
	if err := tx.validate(); err != nil {
		return nil, err
	}
	name, err := backupfs.ImportPath(item.ID)
	if err != nil || filepath.Dir(tx.Stage) != filepath.Dir(name) || tx.Stage != item.Stage || tx.ID != item.PreviewID || tx.Phase != "activating" || tx.AdoptStartup || tx.PreviousStartup != nil {
		return nil, errors.New("prepared recovery plan does not match its owned import")
	}
	preview := &plan.Preview
	if item.Preview == nil || preview.Mode != "original" && preview.Mode != "clone" || tx.BackupID != preview.Manifest.ID || tx.InstanceID != preview.InstanceID || tx.Runtime != preview.Runtime || !preview.Manifest.CompleteInventory || preview.Manifest.Version != 2 {
		return nil, errors.New("prepared recovery preview is inconsistent")
	}
	if err := backuparchive.ValidateManifest(preview.Manifest); err != nil {
		return nil, err
	}
	// The registry's public preview must describe the exact opaque plan being
	// confirmed, including destinations and identity warnings, not stale UI data.
	public, err := json.Marshal(item.Preview)
	if err != nil {
		return nil, err
	}
	actual, err := json.Marshal(preview)
	if err != nil || string(public) != string(actual) {
		return nil, errors.New("recovery preview changed; preview the archive again")
	}
	if len(preview.Files) != len(tx.Moves) || len(plan.Files) > len(tx.Moves) {
		return nil, errors.New("prepared recovery inventory is inconsistent")
	}
	sealed := map[string]sealedImportFile{}
	var total int64
	for _, file := range plan.Files {
		digest, err := hex.DecodeString(file.SHA256)
		if err != nil || len(digest) != 32 || file.Size < 0 || file.Size > backuparchive.MaxDataBytes-total || sealed[file.Path].SHA256 != "" {
			return nil, errors.New("invalid prepared recovery file seal")
		}
		if kind := importDatabaseKind(file.Path); kind != "" && file.SchemaVersion < 1 || kind == "" && file.SchemaVersion != 0 {
			return nil, errors.New("invalid prepared database schema seal")
		}
		total += file.Size
		sealed[file.Path] = file
	}
	for i, move := range tx.Moves {
		change := preview.Files[i]
		if filepath.ToSlash(move.Path) != change.Path || move.Install != change.Install || move.HadOriginal != change.Replace {
			return nil, errors.New("prepared replacement differs from its preview")
		}
		if move.Install {
			if sealed[move.Path].SHA256 == "" {
				return nil, errors.New("prepared recovery file lacks a seal")
			}
			delete(sealed, move.Path)
		}
	}
	if len(sealed) != 0 {
		return nil, errors.New("prepared recovery seal has unowned files")
	}
	return &plan, nil
}

// ValidateImportActivation checks exact-preview consent before a host may stop
// the service. File integrity, current identity and SQLite ownership are checked
// again under the offline lifecycle lock by ActivateImport.
func ValidateImportActivation(ctx context.Context, item backupstore.RecoveryImportRecord, request contract.RecoveryImportActivateRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if (item.State != "previewed" && item.State != "activating") || !item.ExpiresAt.After(time.Now()) {
		return errors.New("recovery preview is unavailable or expired")
	}
	plan, err := readImportPlan(item)
	if err != nil {
		return err
	}
	preview := plan.Preview
	if request.ID != item.ID || request.ConfirmPreviewID != item.PreviewID || request.ConfirmBackupID != preview.Manifest.ID || request.ConfirmSourceInstanceID != preview.Manifest.InstanceID || request.ConfirmTargetInstanceID != preview.TargetInstanceID || request.ConfirmResultInstanceID != preview.InstanceID {
		return errors.New("restore requires matching preview, backup, source, target and resulting instance confirmations")
	}
	if !request.ConfirmMaintenance || !request.ConfirmStartupChanges {
		return errors.New("restore requires confirmation of service interruption, data replacement and restored TLS/authentication/listener inputs")
	}
	if !preview.Runtime.ManagementAuth {
		return errors.New("the installed Web restore host requires management authentication; use a compatible offline host")
	}
	if preview.Manifest.Build.Version != version.Version || preview.Manifest.Build.Platform != runtime.GOOS || preview.Manifest.Build.Architecture != runtime.GOARCH {
		return errors.New("web restore requires the same application version and platform; use a reviewed offline migration")
	}
	if preview.Mode == "original" && (!request.ConfirmSourceStopped || !request.ConfirmCredentialRevival) {
		return errors.New("original-instance recovery requires stopped-source and revoked-credential revival acknowledgement")
	}
	if preview.Mode == "clone" && !request.ConfirmCloneEnrollment {
		return errors.New("clone recovery requires acknowledgement of credential reset, disabled outbounds/listeners and device re-enrollment")
	}
	if preview.TargetInstanceID != preview.InstanceID && !request.ConfirmIdentityReplacement {
		return errors.New("restore replaces a different deployment identity; explicit acknowledgement is required")
	}
	return nil
}

// ActivateImport installs a previously authenticated and sealed preview. It
// acquires the existing lifecycle lock and refuses active SQLite owners. The
// ordinary startup transaction remains responsible for commit or rollback.
func ActivateImport(ctx context.Context, directory string, item backupstore.RecoveryImportRecord, request contract.RecoveryImportActivateRequest) (contract.RecoveryRestoreResult, error) {
	var empty contract.RecoveryRestoreResult
	if item.State != "activating" {
		return empty, errors.New("recovery import has not been admitted for maintenance")
	}
	if err := ValidateImportActivation(ctx, item, request); err != nil {
		return empty, err
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
	if err := GuardMaintenance(directory); err != nil {
		return empty, err
	}
	plan, err := readImportPlan(item)
	if err != nil {
		return empty, err
	}
	target, err := recoveryTargetID(ctx, directory)
	if err != nil || target != plan.Preview.TargetInstanceID {
		return empty, errors.New("target deployment identity changed after preview")
	}
	if err := verifyImportFiles(ctx, directory, plan); err != nil {
		return empty, err
	}
	tx := &plan.Transaction
	root, err := os.OpenRoot(directory)
	if err != nil {
		return empty, err
	}
	defer root.Close()
	paths := map[string]bool{}
	for i := range tx.Moves {
		move := &tx.Moves[i]
		paths[filepath.ToSlash(move.Path)] = true
		// WAL/SHM/journal files may disappear during the required clean shutdown.
		// Their current originals are still saved if present, never installed.
		if sqliteSidecar(move.Path) {
			move.HadOriginal, err = backupfs.Destination(root, move.Path, false)
			if err != nil {
				return empty, err
			}
		}
	}
	removals, err := recoveryIdentityReplacements(ctx, filepath.Join(directory, tx.Stage), directory)
	if err != nil {
		return empty, err
	}
	for _, path := range removals {
		if !paths[path] {
			return empty, errors.New("protocol identity inventory changed after preview; preview again")
		}
	}
	tx.AdoptStartup = true
	tx.PreviousStartup, err = readRecoveryStartupBinding(directory)
	if err != nil {
		return empty, err
	}
	if err := activateRecoverySet(ctx, directory, tx, nil); err != nil {
		return empty, err
	}
	return recoveryResult(*tx, tx.Phase), nil
}

func sqliteSidecar(path string) bool {
	for _, database := range []string{"state.db", "management.db"} {
		for _, suffix := range []string{"-wal", "-shm", "-journal"} {
			if path == database+suffix {
				return true
			}
		}
	}
	return false
}

func verifyImportFiles(ctx context.Context, directory string, plan *preparedImportPlan) error {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, sealed := range plan.Files {
		name := filepath.Join(plan.Transaction.Stage, sealed.Path)
		if present, err := backupfs.Destination(root, name, false); err != nil || !present {
			return errors.New("prepared recovery file is missing or aliased")
		}
		file, err := root.Open(name)
		if err != nil {
			return err
		}
		info, statErr := file.Stat()
		digest, size, hashErr := hashRecoveryOriginal(ctx, file, sealed.Size)
		hashErr = errors.Join(statErr, hashErr, file.Close())
		if err := ctx.Err(); err != nil {
			return err
		}
		if hashErr != nil || info.Mode().Perm()&0o077 != 0 || size != sealed.Size || digest != sealed.SHA256 {
			return errors.New("prepared recovery file changed after preview")
		}
		if kind := importDatabaseKind(sealed.Path); kind != "" {
			schema, err := sqlite.InspectBackupSnapshot(ctx, filepath.Join(directory, name), kind)
			if err != nil || schema != sealed.SchemaVersion {
				return errors.New("prepared recovery database schema changed after preview")
			}
		}
	}
	id, err := sqlite.RecoveryInstanceID(ctx, filepath.Join(directory, plan.Transaction.Stage, "state.db"), false)
	if err != nil || id != plan.Transaction.InstanceID {
		return errors.New("prepared recovery database identity changed after preview")
	}
	return nil
}
