package backup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	contractbackup "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
)

type Backup struct {
	store                   *backupstore.Store
	dir                     string
	proxy                   netapi.Proxy
	maintainer              RecoveryMaintainer
	mu                      sync.Mutex
	scheduleMu              sync.Mutex
	ctx                     context.Context
	cancel                  context.CancelFunc
	done                    chan struct{}
	changed                 chan struct{}
	scheduledCancel         context.CancelFunc
	scheduleStarted         time.Time
	recoveryReaders         map[string]int
	metricsVersion          atomic.Uint64
	metricsSnapshot         atomic.Pointer[backupMetricSnapshot]
	activeRecoveryDownloads atomic.Int64
	restoring               atomic.Bool
}

// New starts the shared backup scheduler. The optional maintainer coordinates
// installed-host operations; Close cancels and joins runtime transfer work.
func New(store *backupstore.Store, dir string, maintainer RecoveryMaintainer, proxy netapi.Proxy) *Backup {
	b := &Backup{
		store:      store,
		dir:        dir,
		maintainer: maintainer,
		proxy:      proxy,
	}

	b.ctx, b.cancel = context.WithCancel(context.Background())
	b.done, b.changed = make(chan struct{}), make(chan struct{}, 1)
	b.scheduleStarted = time.Now()
	if store != nil {
		if err := b.recoverInterruptedBackups(b.ctx); err != nil {
			log.Warn("backup history recovery failed")
		}
		b.refreshBackupMetrics(b.ctx)
		if err := b.pruneRecoveryImportsLocked(b.ctx, true); err != nil {
			log.Warn("recovery import cleanup failed")
		}
	}
	go b.schedule()
	return b
}

func (b *Backup) Save(ctx context.Context, opt contractbackup.Option) (contractbackup.Option, error) {
	if b.restoring.Load() {
		return contractbackup.Option{}, errBackupBusy
	}
	if b.store == nil {
		return contractbackup.Option{}, fmt.Errorf("backup store is unavailable")
	}
	if opt.Interval > 365*24*60 {
		return contractbackup.Option{}, errors.New("backup interval exceeds one year")
	}
	if opt.Recovery != nil {
		policy, err := backupstore.NormalizeRecoveryPolicy(*opt.Recovery)
		if err != nil {
			return contractbackup.Option{}, err
		}
		if policy.Enabled && policy.Target == "s3" && !opt.S3.Enabled {
			return contractbackup.Option{}, errors.New("scheduled full S3 backup requires enabled S3 settings")
		}
		if policy.Enabled && b.maintainer == nil {
			return contractbackup.Option{}, errors.New("scheduled full backups require an installed-service maintenance coordinator")
		}
		if policy.Enabled {
			if supported, reason := b.maintainer.Supported(); !supported {
				return contractbackup.Option{}, errors.New(reason)
			}
		}
		opt.Recovery = &policy
	}
	opt.LastBackupHash = ""
	if err := b.store.Save(ctx, opt); err != nil {
		return contractbackup.Option{}, err
	}

	b.reschedule()

	return b.store.Get(ctx)
}

func (b *Backup) Get(ctx context.Context) (contractbackup.Option, error) {
	if b.store == nil {
		return contractbackup.Option{}, errors.New("backup store is unavailable")
	}
	return b.store.Get(ctx)
}

var errBackupBusy = contractbackup.ErrBusy

func (b *Backup) operationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	stop := func() bool { return false }
	if b.ctx != nil {
		stop = context.AfterFunc(b.ctx, cancel)
		if b.ctx.Err() != nil {
			cancel()
		}
	}
	return ctx, func() { stop(); cancel() }
}

func (s *backupSnapshot) Close() error { return errors.Join(s.File.Close(), os.RemoveAll(s.directory)) }

func (b *Backup) Close() error {
	if b.cancel != nil {
		b.cancel()
		<-b.done
	}
	// Active manual work inherits cancellation as well as periodic work.
	b.mu.Lock()
	defer b.mu.Unlock()
	return nil
}
