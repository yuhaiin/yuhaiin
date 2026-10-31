package recovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"uuid"

	"filippo.io/age"
	"github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/testfixture"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	nodecontract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tailscale"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	backuparchive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

type preparedImportSource struct {
	directory string
	data      []byte
	identity  string
}

func newPreparedImportSource(t *testing.T) *preparedImportSource {
	t.Helper()
	directory, key := testfixture.BasicDeployment(t)
	return preparedImportSourceFrom(t, directory, key)
}

func preparedImportSourceFrom(t *testing.T, directory string, key *age.X25519Identity) *preparedImportSource {
	t.Helper()
	archive := filepath.Join(t.TempDir(), "full.yhb")
	if _, err := Create(t.Context(), directory, archive, backuparchive.Encryption{Recipient: key.Recipient().String()}, CreateOptions{ConfirmedMaintenance: true}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlite.RequireClosed(filepath.Join(directory, "state.db"), filepath.Join(directory, "management.db")); err != nil {
		t.Fatal(err)
	}
	return &preparedImportSource{directory: directory, data: data, identity: key.String()}
}

func preparedImportFixture(t *testing.T, mode string, online bool) (string, backupstore.RecoveryImportRecord, contractrecovery.ImportActivateRequest, *sqlite.Store) {
	t.Helper()
	return newPreparedImportSource(t).prepare(t, mode, online)
}

func (source *preparedImportSource) prepare(t *testing.T, mode string, online bool) (string, backupstore.RecoveryImportRecord, contractrecovery.ImportActivateRequest, *sqlite.Store) {
	t.Helper()
	directory := t.TempDir()
	// Only immutable test deployments whose actual owners have closed are copied.
	// Reuse source initialization/encryption without sharing mutable target state;
	// production snapshots continue to use the SQLite snapshot API.
	if err := os.CopyFS(directory, os.DirFS(source.directory)); err != nil {
		t.Fatal(err)
	}
	if err := filepath.WalkDir(source.directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source.directory, path)
		if err != nil {
			return err
		}
		return os.Chmod(filepath.Join(directory, relative), info.Mode().Perm())
	}); err != nil {
		t.Fatal(err)
	}
	data := source.data
	var err error
	var live *sqlite.Store
	if online {
		live, err = testfixture.OpenState(t.Context(), filepath.Join(directory, "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = live.Close() })
	}
	id := uuid.New().String()
	if err := os.MkdirAll(filepath.Join(directory, ".recovery-imports", id), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, ".recovery-imports", id, "archive.yhb"), data, 0600); err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareImport(t.Context(), directory, id, bytes.NewReader(data), backuparchive.Decryption{Identity: source.identity}, mode)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = prepared.Close() })
	item := backupstore.RecoveryImportRecord{ID: id, PreviewID: prepared.ID, State: "activating", CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(30 * time.Minute), Preview: &prepared.Preview, Stage: prepared.Stage, Plan: prepared.Plan, Owner: "fixture"}
	digest := sha256.Sum256(data)
	item.Size, item.SHA256 = int64(len(data)), hex.EncodeToString(digest[:])
	preview := prepared.Preview
	request := contractrecovery.ImportActivateRequest{ID: id, ConfirmPreviewID: prepared.ID, ConfirmBackupID: preview.Manifest.ID, ConfirmSourceInstanceID: preview.Manifest.InstanceID, ConfirmTargetInstanceID: preview.TargetInstanceID, ConfirmResultInstanceID: preview.InstanceID,
		ConfirmMaintenance: true, ConfirmStartupChanges: true, ConfirmSourceStopped: true, ConfirmCredentialRevival: true, ConfirmIdentityReplacement: true, ConfirmCloneEnrollment: true}
	return directory, item, request, live
}

func TestPreparedImportRequiresExactPreviewAndDestructiveConsent(t *testing.T) {
	source := newPreparedImportSource(t)
	for _, mode := range []string{"original", "clone"} {
		t.Run(mode, func(t *testing.T) {
			_, item, request, _ := source.prepare(t, mode, false)
			if err := ValidateImportActivation(t.Context(), item, request); err != nil {
				t.Fatal(err)
			}
			for _, fault := range []string{"import", "preview", "backup", "source", "target", "result", "maintenance", "startup", "mode_consent", "expired", "legacy_plan"} {
				t.Run(fault, func(t *testing.T) {
					current := item
					input := request
					switch fault {
					case "import":
						input.ID = uuid.New().String()
					case "preview":
						input.ConfirmPreviewID = uuid.New().String()
					case "backup":
						input.ConfirmBackupID = uuid.New().String()
					case "source":
						input.ConfirmSourceInstanceID = uuid.New().String()
					case "target":
						input.ConfirmTargetInstanceID = "empty"
					case "result":
						input.ConfirmResultInstanceID = uuid.New().String()
					case "maintenance":
						input.ConfirmMaintenance = false
					case "startup":
						input.ConfirmStartupChanges = false
					case "mode_consent":
						if mode == "clone" {
							input.ConfirmCloneEnrollment = false
						} else {
							input.ConfirmCredentialRevival = false
						}
					case "expired":
						current.ExpiresAt = time.Now().Add(-time.Second)
					case "legacy_plan":
						current.Plan = `{"version":1,"id":"old-preview"}`
					}
					if err := ValidateImportActivation(t.Context(), current, input); err == nil {
						t.Fatal("unconfirmed or stale restore admitted")
					}
				})
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if err := ValidateImportActivation(ctx, item, request); !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation ignored", err)
			}
			if mode == "clone" {
				request.ConfirmIdentityReplacement = false
				if err := ValidateImportActivation(t.Context(), item, request); err == nil {
					t.Fatal("replacement with a clone identity was not confirmed")
				}
			}
		})
	}
}

func TestPreparedImportRejectsChangedStagingWithoutTouchingDeployment(t *testing.T) {
	directory, baseline, request, _ := preparedImportFixture(t, "original", false)
	before, err := os.ReadFile(filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, baseline.Stage, "site.key")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Each refused activation must leave the same target and plan usable. Restore
	// only the faulted staged key between cases; no scenario or assertion is skipped.
	for _, fault := range []string{"content", "growth", "missing", "alias", "permissions", "plan_destination", "preview"} {
		t.Run(fault, func(t *testing.T) {
			item := baseline
			t.Cleanup(func() {
				if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Error(err)
				}
				if err := os.WriteFile(path, original, 0600); err != nil {
					t.Error(err)
				}
			})
			switch fault {
			case "content":
				if err := os.WriteFile(path, []byte("other key of same kind"), 0600); err != nil {
					t.Fatal(err)
				}
			case "growth":
				f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.Write([]byte("extra"))
				if err := errors.Join(err, f.Close()); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "alias":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(directory, "site.key"), path); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "plan_destination":
				item.Plan = strings.ReplaceAll(item.Plan, `"path":"site.key"`, `"path":"other.key"`)
			case "preview":
				copy := *item.Preview
				copy.Warnings = append(append([]string(nil), copy.Warnings...), "modified")
				item.Preview = &copy
			}
			if _, err := ActivateImport(t.Context(), directory, item, request); err == nil {
				t.Fatal("changed prepared import was installed")
			}
			after, err := os.ReadFile(filepath.Join(directory, "state.db"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed validation changed the deployment", err)
			}
			if _, err := os.Lstat(filepath.Join(directory, recoveryJournalName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed validation wrote an activation journal", err)
			}
		})
	}
}

func TestPreparedImportRequiresStoppedOwnersAndHandlesClosedWAL(t *testing.T) {
	source := newPreparedImportSource(t)
	for _, mode := range []string{"original", "clone"} {
		t.Run(mode, func(t *testing.T) {
			directory, item, request, live := source.prepare(t, mode, true)
			if _, err := ActivateImport(t.Context(), directory, item, request); err == nil {
				t.Fatal("active SQLite owner was overwritten")
			}
			if err := live.Close(); err != nil {
				t.Fatal(err)
			}
			result, err := ActivateImport(t.Context(), directory, item, request)
			if err != nil || result.State != "awaiting_startup" || !result.AdoptStartup {
				t.Fatal("offline sealed import did not enter controlled startup", err, result.State)
			}
			if err := CheckStartup(directory, ""); err == nil {
				t.Fatal("ordinary startup bypassed the pending transaction")
			}
			lifecycle, err := lockfile.Acquire(filepath.Join(directory, ".configuration.lock"))
			if err != nil {
				t.Fatal(err)
			}
			defer lifecycle.Close()
			startup, err := PrepareStartup(directory, lifecycle, result.Runtime)
			if err != nil {
				t.Fatal(err)
			}
			if err := startup.Abort(); err != nil {
				t.Fatal(err)
			}
			got, err := LastResult(directory)
			if err != nil || got == nil || got.State != "rolled_back" {
				t.Fatal("startup failure did not retain rollback result", err)
			}
			actual, err := sqlite.RecoveryInstanceID(t.Context(), filepath.Join(directory, "state.db"), false)
			if err != nil || actual != item.Preview.TargetInstanceID {
				t.Fatal("rollback did not restore the original instance", err)
			}
		})
	}
}

func TestPreparedImportRefusesChangedTargetIdentity(t *testing.T) {
	directory, item, request, _ := preparedImportFixture(t, "original", false)
	replacement := uuid.New().String()
	db, err := testfixture.OpenState(t.Context(), filepath.Join(directory, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	_, changeErr := db.DB().ExecContext(t.Context(), "UPDATE metadata SET value=? WHERE key='recovery_instance_id'", replacement)
	if err := errors.Join(changeErr, db.Close()); err != nil {
		t.Fatal(err)
	}
	if _, err := ActivateImport(t.Context(), directory, item, request); err == nil {
		t.Fatal("foreign target was overwritten using old consent")
	}
	actual, err := sqlite.RecoveryInstanceID(t.Context(), filepath.Join(directory, "state.db"), false)
	if err != nil || actual != replacement {
		t.Fatal("refused restore modified the foreign target", err)
	}
}

func TestPreparedImportPreservesNativeIdentityProjectionAndRollback(t *testing.T) {
	directory, key := testfixture.Deployment(t)
	source := preparedImportSourceFrom(t, directory, key)
	for _, mode := range []string{"original", "clone"} {
		t.Run(mode, func(t *testing.T) {
			target, item, request, _ := source.prepare(t, mode, false)
			modernDirectory, err := tailscale.RecoveryDirectory(target, nodecontract.Tailscale{AuthKey: "tskey-fixture", Hostname: "fixture-host"})
			if err != nil {
				t.Fatal(err)
			}
			modern := filepath.Join(modernDirectory, "tailscaled.state")
			if mode == "original" {
				relative, err := filepath.Rel(target, modern)
				if err != nil {
					t.Fatal(err)
				}
				staged := filepath.Join(target, item.Stage, relative)
				content, err := os.ReadFile(staged)
				if err != nil {
					t.Fatal(err)
				}
				changed := bytes.Clone(content)
				changed[0] ^= 1
				if err := os.WriteFile(staged, changed, 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := ActivateImport(t.Context(), target, item, request); err == nil {
					t.Fatal("same-size native identity tampering bypassed the sealed plan")
				}
				if err := os.WriteFile(staged, content, 0600); err != nil {
					t.Fatal(err)
				}
			}
			result, err := ActivateImport(t.Context(), target, item, request)
			if err != nil {
				t.Fatal(err)
			}
			legacy := filepath.Join(target, "tailscale", "fixture-host", "tailscaled.state")
			if _, err := os.Lstat(legacy); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("activation retained a competing legacy Tailnet identity", err)
			}
			if mode == "original" {
				content, err := os.ReadFile(modern)
				if err != nil || string(content) != "fixture identity or ignored file" {
					t.Fatal("sealed Web restore lost the native identity", err)
				}
			} else if _, err := os.Lstat(modern); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("clone activated the source machine identity", err)
			}
			lifecycle, err := lockfile.Acquire(filepath.Join(target, ".configuration.lock"))
			if err != nil {
				t.Fatal(err)
			}
			defer lifecycle.Close()
			startup, err := PrepareStartup(target, lifecycle, result.Runtime)
			if err != nil {
				t.Fatal(err)
			}
			if err := startup.Abort(); err != nil {
				t.Fatal(err)
			}
			original, err := os.ReadFile(legacy)
			if err != nil || string(original) != "fixture identity or ignored file" {
				t.Fatal("rollback lost the target's original native identity", err)
			}
			if _, err := os.Lstat(modern); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("rollback retained the newly projected identity", err)
			}
		})
	}
}
