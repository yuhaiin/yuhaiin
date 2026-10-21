package managementauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

const clientIterations = 600000
const serverMemory = 64 * 1024
const serverIterations = 3

type rateWindow struct {
	start time.Time
	count int
}

// PasswordService accepts only 32-byte client-derived credentials. Raw passwords
// never enter its API. Argon2id work is bounded independently of HTTP handlers.
type PasswordService struct {
	store  *Store
	key    []byte
	work   chan struct{}
	mu     sync.Mutex
	rates  map[string]rateWindow
	global rateWindow
}

func NewPasswordService(ctx context.Context, store *Store) (*PasswordService, error) {
	p := &PasswordService{store: store, work: make(chan struct{}, 2), rates: make(map[string]rateWindow)}
	if err := store.db.QueryRowContext(ctx, `SELECT setup FROM management_auth_setup WHERE id=1`).Scan(&p.key); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		key := clientSalt()
		if _, err := store.db.ExecContext(ctx, `INSERT INTO management_auth_setup(id,setup) VALUES(1,?) ON CONFLICT(id) DO NOTHING`, key); err != nil {
			return nil, err
		}
		if err := store.db.QueryRowContext(ctx, `SELECT setup FROM management_auth_setup WHERE id=1`).Scan(&p.key); err != nil {
			return nil, err
		}
	}
	if len(p.key) != 16 {
		return nil, errors.New("invalid management authentication setup")
	}
	return p, nil
}

func clientSalt() []byte {
	out := make([]byte, 16)
	_, _ = rand.Read(out)
	return out
}

func (p *PasswordService) allow(peer string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for key, window := range p.rates {
		if now.Sub(window.start) >= time.Minute {
			delete(p.rates, key)
		}
	}
	if now.Sub(p.global.start) >= time.Minute {
		p.global = rateWindow{start: now}
	}
	window := p.rates[peer]
	if window.start.IsZero() {
		window.start = now
	}
	if window.count >= 20 || p.global.count >= 120 || len(p.rates) >= 1024 {
		return false
	}
	window.count++
	p.global.count++
	p.rates[peer] = window
	return true
}

// Algorithm IDs are immutable parameter sets, persisted per user so a future
// version can introduce a new KDF without reinterpreting existing credentials.
type PasswordParameters struct {
	Algorithm     string `json:"algorithm"`
	Salt          string `json:"salt"`
	Iterations    int    `json:"iterations"`
	Digest        string `json:"digest"`
	Bytes         int    `json:"bytes"`
	Normalization string `json:"normalization"`
	Encoding      string `json:"encoding"`
}

func parameters(salt []byte) PasswordParameters {
	return PasswordParameters{"pbkdf2-sha256-v1", base64.RawURLEncoding.EncodeToString(salt), clientIterations, "SHA-256", 32, "NFC", "utf-8/base64url-unpadded"}
}

func (p *PasswordService) Parameters(ctx context.Context, login string) (PasswordParameters, error) {
	if len(login) > 64 {
		return PasswordParameters{}, ErrInvalid
	}
	var salt []byte
	err := p.store.db.QueryRowContext(ctx, `SELECT client_salt FROM management_users WHERE login=? COLLATE NOCASE`, login).Scan(&salt)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return PasswordParameters{}, err
		}
		hash := hmac.New(sha256.New, p.key)
		_, _ = hash.Write([]byte(strings.ToLower(login)))
		salt = hash.Sum(nil)[:16]
	}
	return parameters(salt), nil
}

func (p *PasswordService) hash(ctx context.Context, credential string, salt []byte) ([]byte, error) {
	if len(credential) != 43 {
		return nil, ErrUnauthorized
	}
	material, err := base64.RawURLEncoding.Strict().DecodeString(credential)
	if err != nil || len(material) != 32 || len(salt) != 16 {
		return nil, ErrUnauthorized
	}
	select {
	case p.work <- struct{}{}:
		defer func() { <-p.work }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return argon2.IDKey(material, salt, serverIterations, serverMemory, 1, 32), nil
}

func (p *PasswordService) Login(ctx context.Context, login, credential string) (IssuedCredential, error) {
	if len(login) > 64 {
		return IssuedCredential{}, ErrUnauthorized
	}
	var id string
	var salt, verifier []byte
	var generation int64
	err := p.store.db.QueryRowContext(ctx, `SELECT id,server_salt,credential,generation FROM management_users WHERE login=? COLLATE NOCASE AND disabled=0 AND credential IS NOT NULL`, login).Scan(&id, &salt, &verifier, &generation)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return IssuedCredential{}, err
		}
		salt = p.key[:16]
		verifier = make([]byte, 32)
	}
	actual, err := p.hash(ctx, credential, salt)
	if err != nil || subtle.ConstantTimeCompare(actual, verifier) != 1 || id == "" {
		p.store.audit(ctx, "login.failed", "", "")
		return IssuedCredential{}, ErrUnauthorized
	}
	tx, err := p.store.db.BeginTx(ctx, nil)
	if err != nil {
		return IssuedCredential{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var current int64
	err = tx.QueryRowContext(ctx, `SELECT generation FROM management_users WHERE id=? AND disabled=0 AND credential IS NOT NULL`, id).Scan(&current)
	if err != nil || current != generation {
		return IssuedCredential{}, ErrUnauthorized
	}
	session, err := issueCredential(ctx, tx, id, "session", nil, time.Now().Add(8*time.Hour).Unix())
	if err != nil {
		return IssuedCredential{}, err
	}
	if err := recordEvent(ctx, tx, "login.succeeded", id, id); err != nil {
		return IssuedCredential{}, err
	}
	return session, tx.Commit()
}

func enrollmentSecret(r *http.Request) string {
	scheme, secret, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Enrollment") || r.URL.Query().Has("token") || len(secret) != 46 {
		return ""
	}
	return secret
}

func (p *PasswordService) enrollment(ctx context.Context, secret string) (string, int64, []byte, error) {
	if len(secret) != 46 {
		return "", 0, nil, ErrUnauthorized
	}
	verifier := sha256.Sum256([]byte(secret))
	var id string
	var generation int64
	var salt []byte
	err := p.store.db.QueryRowContext(ctx, `SELECT u.id,u.generation,u.client_salt FROM management_credentials c JOIN management_users u ON u.id=c.user_id
 WHERE c.verifier=? AND c.kind='enrollment' AND c.revoked=0 AND c.expires_at>? AND u.disabled=0 AND c.generation=u.generation`, verifier[:], time.Now().Unix()).Scan(&id, &generation, &salt)
	if err != nil {
		return "", 0, nil, ErrUnauthorized
	}
	return id, generation, salt, nil
}

func (p *PasswordService) EnrollmentParameters(ctx context.Context, secret string) (PasswordParameters, error) {
	_, _, salt, err := p.enrollment(ctx, secret)
	if err != nil {
		return PasswordParameters{}, err
	}
	return parameters(salt), nil
}

func (p *PasswordService) Enroll(ctx context.Context, secret, credential string) error {
	id, generation, _, err := p.enrollment(ctx, secret)
	if err != nil {
		return err
	}
	salt := clientSalt() // independent server-side salt, never the client KDF salt
	verifier, err := p.hash(ctx, credential, salt)
	if err != nil {
		return ErrInvalid
	}
	tx, err := p.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	capability := sha256.Sum256([]byte(secret))
	result, err := tx.ExecContext(ctx, `UPDATE management_credentials SET revoked=1 WHERE verifier=? AND kind='enrollment' AND revoked=0 AND generation=? AND expires_at>?`, capability[:], generation, time.Now().Unix())
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return ErrUnauthorized
	}
	result, err = tx.ExecContext(ctx, `UPDATE management_users SET credential=?,server_salt=?,updated_at=? WHERE id=? AND generation=? AND disabled=0`, verifier, salt, time.Now().Unix(), id, generation)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return ErrUnauthorized
	}
	if err := recordEvent(ctx, tx, "user.enrolled", id, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Server) registerPasswords(mux *http.ServeMux, p *PasswordService) {
	s.public = make(map[string]bool)
	register := func(pattern string, handler http.HandlerFunc) {
		s.public[pattern] = true
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			peer, _ := netip.ParseAddrPort(r.RemoteAddr)
			if !p.allow(peer.Addr().Unmap().String()) {
				authError(w, http.StatusTooManyRequests)
				return
			}
			handler(w, r)
		})
	}
	register("POST /api/v2/auth/parameters", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Login string `json:"login"`
		}
		if !decode(r, w, &request) {
			return
		}
		out, err := p.Parameters(r.Context(), request.Login)
		respond(w, out, err)
	})
	register("POST /api/v2/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Login            string `json:"login"`
			ClientCredential string `json:"clientCredential"`
		}
		if !decode(r, w, &request) {
			return
		}
		out, err := p.Login(r.Context(), request.Login, request.ClientCredential)
		respond(w, out, err)
	})
	register("POST /api/v2/auth/enrollment/parameters", func(w http.ResponseWriter, r *http.Request) {
		out, err := p.EnrollmentParameters(r.Context(), enrollmentSecret(r))
		respond(w, out, err)
	})
	register("POST /api/v2/auth/enrollment", func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ClientCredential string `json:"clientCredential"`
		}
		if !decode(r, w, &request) {
			return
		}
		respond(w, struct{}{}, p.Enroll(r.Context(), enrollmentSecret(r), request.ClientCredential))
	})
}
