package app

import (
	"context"
	"math"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
)

type scheduledRecoveryTest struct {
	calls    atomic.Int64
	requests chan string
}

func (s *scheduledRecoveryTest) Supported() (bool, string) { s.calls.Add(1); return true, "" }
func (s *scheduledRecoveryTest) StartRecovery(_ context.Context, id string, _ time.Duration) error {
	s.requests <- id
	return nil
}

func TestRecoveryScheduleUsesPersistedDueTimeAndRejectsInvalidImportedPolicy(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "due", true: "invalid-import"}[invalid], func(t *testing.T) {
			directory, key := recoveryDeployment(t)
			db, err := sqlite.Open(t.Context(), filepath.Join(directory, "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			owner := store.NewBackupStore(db.DB())
			options, err := owner.Get(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			options.Interval, options.S3.Enabled = 0, false
			options.Recovery = &contract.RecoveryPolicy{Enabled: true, Target: "local", Recipient: key.Recipient().String(), AllowMaintenance: true, IntervalMinutes: 60}
			if invalid {
				options.Recovery.IntervalMinutes = math.MaxUint64
			}
			// Import/store callers can bypass the interactive Save validator. The
			// scheduler must validate again before constructing any timer.
			if err := owner.Save(t.Context(), options); err != nil {
				t.Fatal(err)
			}
			previous := store.RecoveryJob{ID: uuid.New().String(), State: "queued", Target: "local", CreatedAt: time.Now().Add(-2 * time.Hour)}
			if err := owner.EnqueueRecovery(t.Context(), previous); err != nil {
				t.Fatal(err)
			}
			previous.State = "failed"
			if err := owner.SaveRecoveryJob(t.Context(), previous, "queued"); err != nil {
				t.Fatal(err)
			}
			manager := &scheduledRecoveryTest{requests: make(chan string, 2)}
			instance := &AppInstance{StartOptions: &StartOptions{RecoveryMaintenance: manager}}
			backup := NewBackup(owner, directory, instance, nil)
			defer backup.Close()
			if invalid {
				select {
				case <-manager.requests:
					t.Fatal("invalid policy launched maintenance")
				case <-time.After(50 * time.Millisecond):
				}
				if manager.calls.Load() != 0 {
					t.Fatal("invalid policy reached service control")
				}
				return
			}
			select {
			case id := <-manager.requests:
				job, err := owner.RecoveryJob(t.Context(), id)
				if err != nil || job.State != "queued" {
					t.Fatal("scheduled request was not persisted", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("overdue full backup did not run without a browser")
			}
			time.Sleep(50 * time.Millisecond)
			if manager.calls.Load() > 6 {
				t.Fatal("full schedule entered a repeated timer/service-control loop")
			}
			select {
			case <-manager.requests:
				t.Fatal("same interval requested another capture")
			default:
			}
		})
	}
}
