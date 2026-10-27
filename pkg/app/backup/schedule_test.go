package backup

import (
	"context"
	"errors"
	"math"
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
	"uuid"

	testfixture "github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/testfixture"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
)

type scheduledRecoveryTest struct {
	calls    atomic.Int64
	requests chan string
}

type recoveryRetryDialer struct {
	netapi.Proxy
	called chan struct{}
}

func (d recoveryRetryDialer) Conn(context.Context, netapi.Address) (net.Conn, error) {
	select {
	case d.called <- struct{}{}:
	default:
	}
	return nil, errors.New("isolated retry fixture")
}

func TestRecoveryPendingWorkRechecksAfterBusyWithoutAnotherConfigEvent(t *testing.T) {
	b, _ := recoveryTransferBackup(t, func(http.ResponseWriter, *http.Request) { t.Error("retry fixture used external network") })
	queuedArchiveFixture(t, b, "s3", time.Now())
	synctest.Test(t, func(t *testing.T) {
		called := make(chan struct{}, 1)
		b.proxy = recoveryRetryDialer{called: called}
		b.ctx, b.cancel = context.WithCancel(context.Background())
		b.done, b.changed = make(chan struct{}), make(chan struct{}, 1)
		b.mu.Lock() // A manual operation already owns the transfer lease.
		go b.schedule()
		synctest.Wait()
		b.mu.Unlock() // No configuration change or browser event follows.
		defer b.Close()
		time.Sleep(time.Minute)
		synctest.Wait()
		select {
		case <-called:
		default:
			t.Fatal("pending upload lost its only wakeup after a busy manual operation")
		}
	})
}

func (s *scheduledRecoveryTest) Supported() (bool, string) { s.calls.Add(1); return true, "" }
func (s *scheduledRecoveryTest) StartRecovery(_ context.Context, id string, _ time.Duration) error {
	s.requests <- id
	return nil
}

func TestRecoveryScheduleUsesPersistedDueTimeAndRejectsInvalidImportedPolicy(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "due", true: "invalid-import"}[invalid], func(t *testing.T) {
			directory, key := testfixture.Deployment(t)
			db, err := sqlite.Open(t.Context(), filepath.Join(directory, "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			owner := backupstore.New(db.DB())
			options, err := owner.Get(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			options.Interval, options.S3.Enabled = 0, false
			options.Recovery = &contractrecovery.Policy{Enabled: true, Target: "local", Recipient: key.Recipient().String(), AllowMaintenance: true, IntervalMinutes: 60}
			if invalid {
				options.Recovery.IntervalMinutes = math.MaxUint64
			}
			// Import/store callers can bypass the interactive Save validator. The
			// scheduler must validate again before constructing any timer.
			if err := owner.Save(t.Context(), options); err != nil {
				t.Fatal(err)
			}
			previous := backupstore.RecoveryJob{ID: uuid.New().String(), State: "queued", Target: "local", CreatedAt: time.Now().Add(-2 * time.Hour)}
			if err := owner.EnqueueRecovery(t.Context(), previous); err != nil {
				t.Fatal(err)
			}
			previous.State = "failed"
			if err := owner.SaveRecoveryJob(t.Context(), previous, "queued"); err != nil {
				t.Fatal(err)
			}
			manager := &scheduledRecoveryTest{requests: make(chan string, 2)}
			backup := New(owner, directory, manager, nil)
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
