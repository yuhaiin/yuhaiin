package route

import (
	"context"
	"database/sql"
	"errors"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/security/configchange"
	"github.com/Asutorufa/yuhaiin/pkg/security/secret"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

type ConfigurationRuntime interface {
	CommitConfiguration(context.Context, *sql.Tx, bool) error
	WithConfiguration(context.Context, func(context.Context) error) error
	PrefetchConfiguration(context.Context, []string) error
	ActivationStatus(context.Context) (contractroute.RuleActivationStatus, error)
}

// CommitConfiguration prepares the candidate held by the write transaction,
// commits policy/history/activation markers together and only then publishes.
func (r *Rules) CommitConfiguration(ctx context.Context, tx *sql.Tx, validate bool) (err error) {
	if owner, _ := ctx.Value(configurationLockKey{}).(*Rules); owner != r {
		return errors.New("configuration runtime must be locked before opening the target transaction")
	}
	if r.closed.Load() {
		return errors.New("route runtime is closed")
	}
	snapshot, err := plainstore.ReadRouteSnapshot(ctx, tx)
	if err != nil {
		return err
	}
	config := routeConfigFromStore(snapshot.Settings)
	config.Generation = snapshot.Revision
	ctx = context.WithValue(ctx, completeCandidateKey{}, true)
	return r.route.ms.UpdateSnapshot(ctx, snapshot, func(ctx context.Context, revision uint64, install func()) error {
		if validate {
			return configchange.ErrValidation
		}
		if err := plainstore.MarkRouteSnapshot(ctx, tx, revision); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		install()
		r.route.ms.list.resetRefreshInterval(snapshot.ListSettings.RefreshInterval)
		return nil
	}, config, func() { r.route.config.Store(config) })
}

type completeCandidateKey struct{}

type configurationLockKey struct{}

func (r *Rules) WithConfiguration(ctx context.Context, apply func(context.Context) error) error {
	// Same order as ordinary apply: runtime locks, then the database connection.
	// Taking these after BeginTx would deadlock a concurrent ordinary apply.
	r.applyMu.Lock()
	defer r.applyMu.Unlock()
	r.route.ms.list.contentMu.Lock()
	defer r.route.ms.list.contentMu.Unlock()
	if r.closed.Load() {
		return errors.New("route runtime is closed")
	}
	return apply(context.WithValue(ctx, configurationLockKey{}, r))
}

// PrefetchConfiguration runs under the runtime lock but before BeginTx. Network
// dials may consult other SQLite-backed control objects, so downloads must never
// run while the target transaction owns the sole connection.
func (r *Rules) PrefetchConfiguration(ctx context.Context, extraURLs []string) error {
	if owner, _ := ctx.Value(configurationLockKey{}).(*Rules); owner != r {
		return errors.New("configuration runtime is not locked")
	}
	book, ok := r.rules.(interface {
		Snapshot(context.Context) (plainstore.RouteSnapshot, error)
	})
	if !ok {
		return errors.New("routing snapshots are unavailable")
	}
	snapshot, err := book.Snapshot(ctx)
	if err != nil {
		return err
	}

	urls := make(map[string]bool)
	for _, url := range extraURLs {
		if url != "" {
			urls[url] = true
		}
	}
	add := func(url string) {
		if url != "" {
			if _, exists := urls[url]; !exists {
				urls[url] = false
			}
		}
	}
	add(snapshot.ListSettings.MaxMindDBDownloadURL)
	for _, list := range snapshot.Lists {
		if list.Source.Remote != nil {
			for _, url := range list.Source.Remote.URLs {
				add(url)
			}
		}
	}
	for url, required := range urls {
		if err := r.route.ms.list.downloader.DownloadIfNotExists(ctx, url, nil); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// An old unavailable source can be removed or disabled by this candidate.
			// The strict candidate compiler checks remaining references after mutation.
			if required {
				return secret.RemoteError(err)
			}
		}
	}
	return nil
}
