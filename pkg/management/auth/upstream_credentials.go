package auth

import (
	"context"
	"database/sql"
	"strings"
	"uuid"

	"github.com/Asutorufa/yuhaiin/pkg/credential"
)

type UpstreamCredentials struct {
	store   *Store
	Changed func(string)
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
	var v credential.Value
	var revision int64
	err := u.store.db.QueryRowContext(ctx, `SELECT type,username,password,revision FROM upstream_credentials WHERE id=?`, id).Scan(&v.Type, &v.Username, &v.Password, &revision)
	return v, revision, err
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
	if u.Changed != nil {
		u.Changed(id)
	}
	return credential.Metadata{ID: id, Name: r.Name, Type: r.Type, Revision: revision}, nil
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
	if u.Changed != nil {
		u.Changed(id)
	}
	return nil
}
