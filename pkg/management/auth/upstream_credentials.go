package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"uuid"

	"github.com/Asutorufa/yuhaiin/pkg/credential"
)

type UpstreamCredentials struct {
	store   *Store
	Changed func(string)
	cacheMu sync.Mutex
	epoch   atomic.Uint64
	cache   atomic.Pointer[upstreamSnapshot]
	closed  atomic.Bool
}

type upstreamSecret struct {
	value    credential.Value
	revision int64
}
type upstreamSnapshot struct {
	epoch  uint64
	values map[string]upstreamSecret
}

// Immutable snapshots keep credential resolution out of SQLite on new outbound
// connections. Mutations invalidate before notifying the node runtime. The epoch
// prevents a concurrent old read from publishing a valid-looking stale snapshot.
func (u *UpstreamCredentials) snapshot(ctx context.Context) (*upstreamSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if u.closed.Load() {
		return nil, sql.ErrConnDone
	}
	if s := u.cache.Load(); s != nil && s.epoch == u.epoch.Load() {
		return s, nil
	}
	u.cacheMu.Lock()
	defer u.cacheMu.Unlock()
	for {
		if u.closed.Load() {
			return nil, sql.ErrConnDone
		}
		epoch := u.epoch.Load()
		if s := u.cache.Load(); s != nil && s.epoch == epoch {
			return s, nil
		}
		rows, err := u.store.db.QueryContext(ctx, `SELECT id,type,username,password,revision FROM upstream_credentials`)
		if err != nil {
			return nil, err
		}
		s := &upstreamSnapshot{epoch: epoch, values: make(map[string]upstreamSecret)}
		for rows.Next() {
			var id string
			var secret upstreamSecret
			if err = rows.Scan(&id, &secret.value.Type, &secret.value.Username, &secret.value.Password, &secret.revision); err != nil {
				break
			}
			s.values[id] = secret
		}
		err = errors.Join(err, rows.Err(), rows.Close())
		if err != nil {
			return nil, err
		}
		if u.closed.Load() {
			return nil, sql.ErrConnDone
		}
		if epoch != u.epoch.Load() {
			continue
		}
		u.cache.Store(s)
		return s, nil
	}
}

func (u *UpstreamCredentials) close() {
	u.closed.Store(true)
	u.cacheMu.Lock()
	u.cache.Store(nil)
	u.cacheMu.Unlock()
}

type UpstreamCredentialRequest struct {
	Name string `json:"name"`
	credential.Value
}

func (u *UpstreamCredentials) List(ctx context.Context) ([]credential.Metadata, error) {
	rows, err := u.store.db.QueryContext(ctx, `SELECT id,name,type,revision FROM upstream_credentials ORDER BY name,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []credential.Metadata{}
	for rows.Next() {
		var m credential.Metadata
		if err := rows.Scan(&m.ID, &m.Name, &m.Type, &m.Revision); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
func (u *UpstreamCredentials) Lookup(ctx context.Context, id string) (credential.Value, int64, error) {
	if err := ctx.Err(); err != nil {
		return credential.Value{}, 0, err
	}
	s := u.cache.Load()
	if u.closed.Load() || s == nil || s.epoch != u.epoch.Load() {
		return credential.Value{}, 0, sql.ErrConnDone
	}
	v, ok := s.values[id]
	if !ok {
		return credential.Value{}, 0, sql.ErrNoRows
	}
	return v.value, v.revision, nil
}
func (u *UpstreamCredentials) Save(ctx context.Context, actor Principal, id string, r UpstreamCredentialRequest) (credential.Metadata, error) {
	if !actor.Allows(UpstreamCredentialsManage) {
		return credential.Metadata{}, ErrForbidden
	}
	if strings.TrimSpace(r.Name) == "" || len(r.Name) > 128 || r.Password == "" || len(r.Password) > 4096 || len(r.Username) > 255 ||
		(r.Type != credential.Password && r.Type != credential.UsernamePassword) || (r.Type == credential.Password && r.Username != "") {
		return credential.Metadata{}, ErrInvalid
	}
	tx, err := u.store.db.BeginTx(ctx, nil)
	if err != nil {
		return credential.Metadata{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if id == "" {
		id = uuid.New().String()
		_, err = tx.ExecContext(ctx, `INSERT INTO upstream_credentials(id,name,type,username,password) VALUES(?,?,?,?,?)`, id, r.Name, r.Type, r.Username, r.Password)
	} else {
		// Type is immutable, so a shared reference cannot silently change meaning.
		var result sql.Result
		result, err = tx.ExecContext(ctx, `UPDATE upstream_credentials SET name=?,username=?,password=?,revision=revision+1 WHERE id=? AND type=?`, r.Name, r.Username, r.Password, id, r.Type)
		if err == nil {
			if n, _ := result.RowsAffected(); n != 1 {
				return credential.Metadata{}, ErrConflict
			}
		}
	}
	if err != nil {
		return credential.Metadata{}, err
	}
	if err = recordEvent(ctx, tx, "upstream-credential.saved", actor.UserID, id); err != nil {
		return credential.Metadata{}, err
	}
	var revision int64
	if err = tx.QueryRowContext(ctx, `SELECT revision FROM upstream_credentials WHERE id=?`, id).Scan(&revision); err != nil {
		return credential.Metadata{}, err
	}
	if err = tx.Commit(); err != nil {
		return credential.Metadata{}, err
	}
	u.epoch.Add(1)
	refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	_, refreshErr := u.snapshot(refreshCtx)
	cancel()
	if u.Changed != nil {
		u.Changed(id)
	}
	return credential.Metadata{ID: id, Name: r.Name, Type: r.Type, Revision: revision}, refreshErr
}
func (u *UpstreamCredentials) Delete(ctx context.Context, actor Principal, id string) error {
	if !actor.Allows(UpstreamCredentialsManage) {
		return ErrForbidden
	}
	tx, err := u.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `DELETE FROM upstream_credentials WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return sql.ErrNoRows
	}
	if err = recordEvent(ctx, tx, "upstream-credential.deleted", actor.UserID, id); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	u.epoch.Add(1)
	refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	_, refreshErr := u.snapshot(refreshCtx)
	cancel()
	if u.Changed != nil {
		u.Changed(id)
	}
	return refreshErr
}
