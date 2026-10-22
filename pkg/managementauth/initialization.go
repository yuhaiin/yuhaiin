package managementauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"
	"uuid"
)

// InitializationCode is emitted only to the local startup output. Only its hash
// is persisted; neither the public status response nor audit events contain it.
type InitializationCode struct {
	Secret    string
	ExpiresAt int64
}

type InitializationStatus struct {
	Required  bool  `json:"required"`
	ExpiresAt int64 `json:"expiresAt"`
}

func (s *Store) InitializationStatus(ctx context.Context) (InitializationStatus, error) {
	var out InitializationStatus
	err := s.db.QueryRowContext(ctx, `SELECT NOT completed,expires_at FROM management_initialization WHERE id=1`).Scan(&out.Required, &out.ExpiresAt)
	return out, err
}

// StartInitialization rotates an unfinished setup on every actual app start.
// It creates no account and never reopens a completed installation.
func (s *Store) StartInitialization(ctx context.Context) (InitializationCode, error) {
	status, err := s.InitializationStatus(ctx)
	if err != nil || !status.Required {
		return InitializationCode{}, err
	}
	var entropy [32]byte
	_, _ = rand.Read(entropy[:])
	out := InitializationCode{Secret: "ys_" + base64.RawURLEncoding.EncodeToString(entropy[:]), ExpiresAt: time.Now().Add(15 * time.Minute).Unix()}
	verifier := sha256.Sum256([]byte(out.Secret))
	result, err := s.db.ExecContext(ctx, `UPDATE management_initialization SET verifier=?,client_salt=?,expires_at=? WHERE id=1 AND completed=0`, verifier[:], clientSalt(), out.ExpiresAt)
	if err != nil {
		return InitializationCode{}, err
	}
	n, err := result.RowsAffected()
	if err != nil || n == 0 {
		return InitializationCode{}, err
	}
	return out, nil
}

func (p *PasswordService) InitializationParameters(ctx context.Context, secret string) (PasswordParameters, error) {
	if len(secret) != 46 || !strings.HasPrefix(secret, "ys_") {
		return PasswordParameters{}, ErrUnauthorized
	}
	verifier := sha256.Sum256([]byte(secret))
	var salt []byte
	err := p.store.db.QueryRowContext(ctx, `SELECT client_salt FROM management_initialization WHERE id=1 AND completed=0 AND verifier=? AND expires_at>?`, verifier[:], time.Now().Unix()).Scan(&salt)
	if errors.Is(err, sql.ErrNoRows) {
		return PasswordParameters{}, ErrUnauthorized
	}
	if err != nil {
		return PasswordParameters{}, err
	}
	return parameters(salt), nil
}

// CompleteInitialization consumes the code, chooses the administrator's login,
// and stores its verifier atomically. Restart/expiry/replay races cannot create
// an account with a stale code, including after the expensive password hash.
func (p *PasswordService) CompleteInitialization(ctx context.Context, secret, login, credential string) error {
	if !validUser(login, Admin) {
		return ErrInvalid
	}
	if _, err := p.InitializationParameters(ctx, secret); err != nil {
		return err
	}
	serverSalt := clientSalt()
	passwordVerifier, err := p.hash(ctx, credential, serverSalt)
	if err != nil {
		return ErrInvalid
	}
	tx, err := p.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	verifier := sha256.Sum256([]byte(secret))
	var salt []byte
	// Reading the salt inside the same transaction also validates code freshness.
	if err := tx.QueryRowContext(ctx, `SELECT client_salt FROM management_initialization WHERE id=1 AND completed=0 AND verifier=? AND expires_at>?`, verifier[:], time.Now().Unix()).Scan(&salt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnauthorized
		}
		return err
	}
	now := time.Now().Unix()
	id := uuid.New().String()
	// A pending account from the optional local bootstrap may already use this
	// login. Finish that account and retire its old enrollment capability.
	var enrolled bool
	err = tx.QueryRowContext(ctx, `SELECT id,credential IS NOT NULL FROM management_users WHERE login=? COLLATE NOCASE`, login).Scan(&id, &enrolled)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_, err = tx.ExecContext(ctx, `INSERT INTO management_users(id,login,role,client_salt,server_salt,credential,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`, id, login, Admin, salt, serverSalt, passwordVerifier, now, now)
	case err == nil && !enrolled:
		_, err = tx.ExecContext(ctx, `UPDATE management_users SET login=?,role='admin',disabled=0,client_salt=?,server_salt=?,credential=?,generation=generation+1,updated_at=? WHERE id=?`, login, salt, serverSalt, passwordVerifier, now, id)
		if err == nil {
			_, err = tx.ExecContext(ctx, `UPDATE management_credentials SET revoked=1 WHERE user_id=?`, id)
		}
	case err == nil:
		return ErrConflict
	}
	if err != nil {
		return err
	}
	// The enrollment trigger permanently closes setup in this transaction.
	if err := recordEvent(ctx, tx, "management.initialized", id, id); err != nil {
		return err
	}
	return tx.Commit()
}

func initializationSecret(r *http.Request) string {
	scheme, secret, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Setup") || r.URL.Query().Has("token") {
		return ""
	}
	return secret
}
