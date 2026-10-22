package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"time"
	"uuid"
)

var (
	ErrInvalid      = errors.New("invalid management request")
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
	ErrConflict     = errors.New("management identity conflict")
)

type User struct {
	ID        string `json:"id"`
	Login     string `json:"login"`
	Role      string `json:"role"`
	Disabled  bool   `json:"disabled"`
	Enrolled  bool   `json:"enrolled"`
	CreatedAt int64  `json:"createdAt"`
	UpdatedAt int64  `json:"updatedAt"`
}

type Credential struct {
	ID        string       `json:"id"`
	UserID    string       `json:"userId"`
	Kind      string       `json:"kind"`
	Prefix    string       `json:"prefix"`
	Scopes    []Permission `json:"scopes"`
	CreatedAt int64        `json:"createdAt"`
	ExpiresAt int64        `json:"expiresAt"`
	Revoked   bool         `json:"revoked"`
}

type IssuedCredential struct {
	Credential
	Secret string `json:"secret"`
}

type SecurityEvent struct {
	ID         int64  `json:"id"`
	OccurredAt int64  `json:"occurredAt"`
	Event      string `json:"event"`
	ActorID    string `json:"actorId"`
	SubjectID  string `json:"subjectId"`
}

type Store struct{ db *sql.DB }

func NewStore(db *sql.DB) *Store { return &Store{db: db} }

const userColumns = `id, login, role, disabled, credential IS NOT NULL, created_at, updated_at`

type scanner interface{ Scan(...any) error }

func scanUser(row scanner) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Login, &u.Role, &u.Disabled, &u.Enrolled, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}

func (s *Store) User(ctx context.Context, id string) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM management_users WHERE id=?`, id))
}

func (s *Store) Users(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userColumns+` FROM management_users ORDER BY login`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func validUser(login, role string) bool {
	if len(login) < 1 || len(login) > 64 || (role != NoManagement && len(RolePermissions(role)) == 0) {
		return false
	}
	for _, c := range login {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-', c == '.':
		default:
			return false
		}
	}
	return true
}

// CreateUser never accepts a password. Enrollment is a separate, single-use
// capability exchange; pending users cannot authenticate or protect a last admin.
func (s *Store) CreateUser(ctx context.Context, actor, login, role string, bootstrap bool) (User, IssuedCredential, error) {
	if !validUser(login, role) || bootstrap && role != Admin {
		return User{}, IssuedCredential{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, IssuedCredential{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if bootstrap {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM management_users`).Scan(&count); err != nil {
			return User{}, IssuedCredential{}, err
		}
		if count != 0 {
			return User{}, IssuedCredential{}, ErrConflict
		}
	}
	now := time.Now().Unix()
	var total int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM management_users`).Scan(&total); err != nil {
		return User{}, IssuedCredential{}, err
	}
	if total >= 1024 {
		return User{}, IssuedCredential{}, ErrConflict
	}
	u := User{ID: uuid.New().String(), Login: login, Role: role, CreatedAt: now, UpdatedAt: now}
	if _, err := tx.ExecContext(ctx, `INSERT INTO management_users(id,login,role,client_salt,created_at,updated_at) VALUES(?,?,?,?,?,?)`, u.ID, u.Login, u.Role, clientSalt(), now, now); err != nil {
		return User{}, IssuedCredential{}, ErrConflict
	}
	issued, err := issueCredential(ctx, tx, u.ID, "enrollment", nil, now+900)
	if err != nil {
		return User{}, IssuedCredential{}, err
	}
	if err := recordEvent(ctx, tx, "user.created", actor, u.ID); err != nil {
		return User{}, IssuedCredential{}, err
	}
	return u, issued, tx.Commit()
}

func (s *Store) UpdateUser(ctx context.Context, actor, id, login, role string, disabled bool) error {
	if !validUser(login, role) {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// Increment on disable so re-enabling cannot resurrect credentials.
	result, err := tx.ExecContext(ctx, `UPDATE management_users SET login=?,role=?,disabled=?,
		generation=generation+CASE WHEN disabled=0 AND ?=1 THEN 1 ELSE 0 END,updated_at=? WHERE id=?`, login, role, disabled, disabled, time.Now().Unix(), id)
	if err != nil {
		return ErrConflict
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return sql.ErrNoRows
	}
	if err := recordEvent(ctx, tx, "user.updated", actor, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteUser(ctx context.Context, actor, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `DELETE FROM management_users WHERE id=?`, id)
	if err != nil {
		return ErrConflict
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return sql.ErrNoRows
	}
	if err := recordEvent(ctx, tx, "user.deleted", actor, id); err != nil {
		return err
	}
	return tx.Commit()
}

// ResetEnrollment is available to administrators and intentional local recovery.
// It invalidates sessions, tokens, and any previous enrollment in one transaction.
func (s *Store) ResetEnrollment(ctx context.Context, actor, id string) (IssuedCredential, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return IssuedCredential{}, err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `UPDATE management_users SET credential=NULL, server_salt=NULL, client_salt=?, generation=generation+1, updated_at=? WHERE id=?`, clientSalt(), time.Now().Unix(), id)
	if err != nil {
		return IssuedCredential{}, err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return IssuedCredential{}, sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `UPDATE management_credentials SET revoked=1 WHERE user_id=?`, id); err != nil {
		return IssuedCredential{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM management_oauth_links WHERE user_id=?`, id); err != nil {
		return IssuedCredential{}, err
	}
	issued, err := issueCredential(ctx, tx, id, "enrollment", nil, time.Now().Add(15*time.Minute).Unix())
	if err != nil {
		return IssuedCredential{}, err
	}
	if err := recordEvent(ctx, tx, "user.credentials_reset", actor, id); err != nil {
		return IssuedCredential{}, err
	}
	return issued, tx.Commit()
}

func issueCredential(ctx context.Context, tx *sql.Tx, owner, kind string, scopes []Permission, expiry int64) (IssuedCredential, error) {
	var generation int64
	if err := tx.QueryRowContext(ctx, `SELECT generation FROM management_users WHERE id=? AND disabled=0`, owner).Scan(&generation); err != nil {
		return IssuedCredential{}, ErrInvalid
	}
	// Bound persisted credentials, including revoked records. Expired/revoked
	// records can be pruned without retaining a reusable authentication secret.
	if _, err := tx.ExecContext(ctx, `DELETE FROM management_credentials WHERE user_id=? AND (revoked=1 OR (expires_at>0 AND expires_at<=?))`, owner, time.Now().Unix()); err != nil {
		return IssuedCredential{}, err
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM management_credentials WHERE user_id=?`, owner).Scan(&count); err != nil {
		return IssuedCredential{}, err
	}
	if count >= 64 {
		return IssuedCredential{}, ErrConflict
	}
	var entropy [32]byte
	_, _ = rand.Read(entropy[:])
	secret := "yu_" + base64.RawURLEncoding.EncodeToString(entropy[:])
	verifier := sha256.Sum256([]byte(secret))
	encoded, err := json.Marshal(scopes)
	if err != nil {
		return IssuedCredential{}, err
	}
	c := Credential{ID: uuid.New().String(), UserID: owner, Kind: kind, Prefix: secret[:11], Scopes: slices.Clone(scopes), CreatedAt: time.Now().Unix(), ExpiresAt: expiry}
	_, err = tx.ExecContext(ctx, `INSERT INTO management_credentials(id,user_id,kind,verifier,prefix,scopes,generation,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)`, c.ID, owner, kind, verifier[:], c.Prefix, string(encoded), generation, c.CreatedAt, expiry)
	if err == nil && kind == "session" {
		info, _ := ctx.Value(sessionInfoKey{}).(sessionInfo)
		err = saveSessionInfo(ctx, tx, c.ID, info)
	}
	return IssuedCredential{Credential: c, Secret: secret}, err
}

// IssueToken snapshots the owner's permissions, capped by the caller's scopes.
// Role promotion cannot silently broaden an already-issued token.
func (s *Store) IssueToken(ctx context.Context, actor Principal, owner string, scopes []Permission, expiry int64) (IssuedCredential, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return IssuedCredential{}, err
	}
	defer func() { _ = tx.Rollback() }()
	u, err := scanUser(tx.QueryRowContext(ctx, `SELECT `+userColumns+` FROM management_users WHERE id=?`, owner))
	if err != nil || u.Disabled || !u.Enrolled {
		return IssuedCredential{}, ErrInvalid
	}
	if owner != actor.UserID && !actor.Allows(TokensManage) {
		return IssuedCredential{}, ErrForbidden
	}
	allowed := RolePermissions(u.Role)
	if len(scopes) == 0 {
		scopes = allowed
	}
	for _, scope := range scopes {
		if !slices.Contains(allowed, scope) || !actor.Allows(scope) {
			return IssuedCredential{}, ErrForbidden
		}
	}
	if expiry != 0 && expiry <= time.Now().Unix() {
		return IssuedCredential{}, ErrInvalid
	}
	issued, err := issueCredential(ctx, tx, owner, "token", scopes, expiry)
	if err != nil {
		return IssuedCredential{}, err
	}
	if err := recordEvent(ctx, tx, "token.created", actor.UserID, issued.ID); err != nil {
		return IssuedCredential{}, err
	}
	return issued, tx.Commit()
}

func (s *Store) Authenticate(ctx context.Context, secret, kind string) (Principal, error) {
	if len(secret) != 46 || !strings.HasPrefix(secret, "yu_") {
		return Principal{}, ErrUnauthorized
	}
	verifier := sha256.Sum256([]byte(secret))
	var p Principal
	var role, encoded string
	var lastSeen int64
	err := s.db.QueryRowContext(ctx, `SELECT u.id,u.role,c.scopes,c.id,c.last_seen FROM management_credentials c JOIN management_users u ON u.id=c.user_id
		WHERE c.verifier=? AND c.kind=? AND c.revoked=0 AND u.disabled=0 AND u.credential IS NOT NULL
		AND c.generation=u.generation AND (c.expires_at=0 OR c.expires_at>?)`, verifier[:], kind, time.Now().Unix()).Scan(&p.UserID, &role, &encoded, &p.CredentialID, &lastSeen)
	if err != nil {
		return Principal{}, ErrUnauthorized
	}
	p.CredentialType = kind
	allowed := RolePermissions(role)
	if kind == "session" {
		if now := time.Now().Unix(); lastSeen < now-60 {
			_, _ = s.db.ExecContext(ctx, `UPDATE management_credentials SET last_seen=? WHERE id=? AND last_seen<?`, now, p.CredentialID, now-60)
		}
		p.Permissions = allowed
		return p, nil
	}
	var scopes []Permission
	if json.Unmarshal([]byte(encoded), &scopes) != nil {
		return Principal{}, ErrUnauthorized
	}
	for _, scope := range scopes {
		if slices.Contains(allowed, scope) {
			p.Permissions = append(p.Permissions, scope)
		}
	}
	return p, nil
}

func (s *Store) logout(ctx context.Context, secret string) error {
	verifier := sha256.Sum256([]byte(secret))
	_, err := s.db.ExecContext(ctx, `UPDATE management_credentials SET revoked=1 WHERE verifier=? AND kind='session'`, verifier[:])
	return err
}

func (s *Store) Credentials(ctx context.Context, owner string) ([]Credential, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,user_id,kind,prefix,scopes,created_at,expires_at,revoked FROM management_credentials WHERE user_id=? AND kind='token' ORDER BY created_at,id`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Credential{}
	for rows.Next() {
		var c Credential
		var encoded string
		if err := rows.Scan(&c.ID, &c.UserID, &c.Kind, &c.Prefix, &encoded, &c.CreatedAt, &c.ExpiresAt, &c.Revoked); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(encoded), &c.Scopes); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) Revoke(ctx context.Context, actor Principal, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var owner string
	if err := tx.QueryRowContext(ctx, `SELECT user_id FROM management_credentials WHERE id=? AND kind='token'`, id).Scan(&owner); err != nil {
		return err
	}
	if owner != actor.UserID && !actor.Allows(TokensManage) {
		return ErrForbidden
	}
	if _, err := tx.ExecContext(ctx, `UPDATE management_credentials SET revoked=1 WHERE id=?`, id); err != nil {
		return err
	}
	if err := recordEvent(ctx, tx, "token.revoked", actor.UserID, id); err != nil {
		return err
	}
	return tx.Commit()
}

// RotateToken atomically revokes the old verifier and issues a new opaque
// secret with the same owner, expiry and scopes. Failed rotation preserves the
// previous token. Reset/disabled/expired credentials cannot be revived here.
func (s *Store) RotateToken(ctx context.Context, actor Principal, id string) (IssuedCredential, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return IssuedCredential{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var owner, role, encoded string
	var expiry int64
	err = tx.QueryRowContext(ctx, `SELECT c.user_id,u.role,c.scopes,c.expires_at FROM management_credentials c JOIN management_users u ON u.id=c.user_id
		WHERE c.id=? AND c.kind='token' AND c.revoked=0 AND u.disabled=0 AND u.credential IS NOT NULL AND c.generation=u.generation AND (c.expires_at=0 OR c.expires_at>?)`, id, time.Now().Unix()).Scan(&owner, &role, &encoded, &expiry)
	if err != nil {
		return IssuedCredential{}, err
	}
	if owner != actor.UserID && !actor.Allows(TokensManage) {
		return IssuedCredential{}, ErrForbidden
	}
	var scopes []Permission
	if json.Unmarshal([]byte(encoded), &scopes) != nil {
		return IssuedCredential{}, ErrInvalid
	}
	for _, scope := range scopes {
		if !actor.Allows(scope) || !slices.Contains(RolePermissions(role), scope) {
			return IssuedCredential{}, ErrForbidden
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE management_credentials SET revoked=1 WHERE id=?`, id); err != nil {
		return IssuedCredential{}, err
	}
	issued, err := issueCredential(ctx, tx, owner, "token", scopes, expiry)
	if err != nil {
		return IssuedCredential{}, err
	}
	if err := recordEvent(ctx, tx, "token.rotated", actor.UserID, issued.ID); err != nil {
		return IssuedCredential{}, err
	}
	return issued, tx.Commit()
}

func recordEvent(ctx context.Context, tx *sql.Tx, event, actor, subject string) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO management_security_events(occurred_at,event,actor_id,subject_id) VALUES(?,?,?,?)`, time.Now().Unix(), event, actor, subject); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM management_security_events WHERE id <= (SELECT COALESCE(MAX(id),0)-1000 FROM management_security_events)`)
	return err
}

func (s *Store) audit(ctx context.Context, event, actor, subject string) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer func() { _ = tx.Rollback() }()
	if recordEvent(ctx, tx, event, actor, subject) == nil {
		_ = tx.Commit()
	}
}

func (s *Store) Events(ctx context.Context) ([]SecurityEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,occurred_at,event,actor_id,subject_id FROM management_security_events ORDER BY id DESC LIMIT 1000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SecurityEvent{}
	for rows.Next() {
		var e SecurityEvent
		if err := rows.Scan(&e.ID, &e.OccurredAt, &e.Event, &e.ActorID, &e.SubjectID); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
