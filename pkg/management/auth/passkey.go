package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const passkeyLifetime = 5 * time.Minute
const maxPasskeys = 20
const maxPasskeyFlows = 512

// Passkeys are additional management sign-in methods. Their challenges never
// leave the server; their public keys live in the private management database.
type PasskeyService struct {
	store *Store
	mu    sync.Mutex
	flows map[string]passkeyFlow
}

type passkeyFlow struct {
	session   webauthn.SessionData
	origin    string
	rpID      string
	owner     string
	sessionID string
	name      string
	expires   time.Time
}

type passkeyUser struct {
	id, login   string
	credentials []webauthn.Credential
}

func (u *passkeyUser) WebAuthnID() []byte                         { return []byte(u.id) }
func (u *passkeyUser) WebAuthnName() string                       { return u.login }
func (u *passkeyUser) WebAuthnDisplayName() string                { return u.login }
func (u *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

type PasskeyInfo struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	RPID       string `json:"rpId"`
	CreatedAt  int64  `json:"createdAt"`
	LastUsedAt int64  `json:"lastUsedAt"`
}

func passkeyRP(origin string) (string, error) {
	u, err := url.Parse(origin)
	if err != nil || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", ErrForbidden
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || net.ParseIP(host) != nil || strings.Contains(host, "_") {
		return "", ErrForbidden
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && host == "localhost") {
		return "", ErrForbidden
	}
	if u.Port() != "" && (len(u.Port()) > 5 || u.Port()[0] == '0') {
		return "", ErrForbidden
	}
	if host != "localhost" && (!strings.Contains(host, ".") || strings.HasSuffix(host, ".localhost")) {
		return "", ErrForbidden
	}
	return host, nil
}

func (s *Server) passkeyRequest(r *http.Request) (*webauthn.WebAuthn, string, string, error) {
	origin, err := s.oauthOrigin(r) // Same trusted-Origin policy as OAuth.
	if err != nil {
		return nil, "", "", err
	}
	rpID, err := passkeyRP(origin)
	if err != nil {
		return nil, "", "", err
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: "yuhaiin",
		RPOrigins:     []string{origin},
	})
	return wa, origin, rpID, err
}

func (p *PasskeyService) put(f passkeyFlow) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, old := range p.flows {
		if time.Now().After(old.expires) {
			delete(p.flows, id)
		}
	}
	if len(p.flows) >= maxPasskeyFlows {
		return "", ErrConflict
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(token)
	f.expires = time.Now().Add(passkeyLifetime)
	p.flows[id] = f
	return id, nil
}

func (p *PasskeyService) take(id, origin, rpID string) (passkeyFlow, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f, ok := p.flows[id]
	delete(p.flows, id) // One attempt only, including invalid signatures.
	if !ok || f.origin != origin || f.rpID != rpID || time.Now().After(f.expires) {
		return passkeyFlow{}, ErrUnauthorized
	}
	return f, nil
}

func (p *PasskeyService) user(ctx context.Context, id, rpID string) (*passkeyUser, error) {
	var login string
	err := p.store.db.QueryRowContext(ctx, `SELECT login FROM management_users
        WHERE id=? AND disabled=0 AND credential IS NOT NULL`, id).Scan(&login)
	if err != nil {
		return nil, ErrUnauthorized
	}
	user := &passkeyUser{id: id, login: login}
	rows, err := p.store.db.QueryContext(ctx, `SELECT data FROM management_passkeys
        WHERE user_id=? AND rp_id=?`, id, rpID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var data []byte
		var cred webauthn.Credential
		if err = rows.Scan(&data); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(data, &cred); err != nil {
			return nil, err
		}
		user.credentials = append(user.credentials, cred)
	}
	return user, rows.Err()
}

func (p *PasskeyService) userForCredential(ctx context.Context, rpID string, rawID, handle []byte) (*passkeyUser, []byte, error) {
	var owner string
	var data []byte
	err := p.store.db.QueryRowContext(ctx, `SELECT user_id,data FROM management_passkeys
        WHERE credential_id=? AND rp_id=?`, rawID, rpID).Scan(&owner, &data)
	if err != nil || !bytes.Equal(handle, []byte(owner)) {
		return nil, nil, ErrUnauthorized
	}
	user, err := p.user(ctx, owner, rpID)
	if err != nil {
		return nil, nil, err
	}
	return user, data, nil
}

func (p *PasskeyService) list(ctx context.Context, owner string) ([]PasskeyInfo, error) {
	rows, err := p.store.db.QueryContext(ctx, `SELECT credential_id,name,rp_id,created_at,last_used_at
        FROM management_passkeys WHERE user_id=? ORDER BY created_at DESC`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PasskeyInfo{}
	for rows.Next() {
		var id []byte
		var v PasskeyInfo
		if err = rows.Scan(&id, &v.Name, &v.RPID, &v.CreatedAt, &v.LastUsedAt); err != nil {
			return nil, err
		}
		v.ID = base64.RawURLEncoding.EncodeToString(id)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (p *PasskeyService) remove(ctx context.Context, owner, id string) error {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(id)
	if err != nil || len(raw) == 0 || len(raw) > 1024 {
		return ErrInvalid
	}
	tx, err := p.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `DELETE FROM management_passkeys WHERE credential_id=? AND user_id=?`, raw, owner)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return sql.ErrNoRows
	}
	if err = recordEvent(ctx, tx, "passkey.removed", owner, owner); err != nil {
		return err
	}
	return tx.Commit()
}

type passkeyStart struct {
	FlowID  string `json:"flowId"`
	Options any    `json:"options"`
}

type passkeyFinish struct {
	FlowID     string          `json:"flowId"`
	Credential json.RawMessage `json:"credential"`
}

func passkeyResponse(r *http.Request, raw json.RawMessage) (*http.Request, error) {
	if len(raw) == 0 || len(raw) > 128<<10 {
		return nil, ErrInvalid
	}
	clone := r.Clone(r.Context())
	clone.Body = io.NopCloser(bytes.NewReader(raw))
	clone.ContentLength = int64(len(raw))
	return clone, nil
}

func (s *Server) registerPasskeys(mux *http.ServeMux, register func(string, Permission, http.HandlerFunc)) {
	if s.Passkeys == nil {
		s.Passkeys = &PasskeyService{store: s.Store, flows: make(map[string]passkeyFlow)}
	}
	p := s.Passkeys
	public := func(pattern string, handler http.HandlerFunc) {
		s.public[pattern] = true
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			peer, err := netip.ParseAddrPort(r.RemoteAddr)
			if err != nil || s.Passwords == nil || !s.Passwords.allow(peer.Addr().Unmap().String()) {
				authError(w, http.StatusTooManyRequests)
				return
			}
			handler(w, r)
		})
	}
	register("GET /api/v2/auth/passkeys", IdentityRead, func(w http.ResponseWriter, r *http.Request) {
		actor, err := sessionPrincipal(r)
		if err != nil {
			respond(w, nil, err)
			return
		}
		out, err := p.list(r.Context(), actor.UserID)
		respond(w, out, err)
	})
	register("DELETE /api/v2/auth/passkeys/{id}", IdentityRead, func(w http.ResponseWriter, r *http.Request) {
		actor, err := sessionPrincipal(r)
		if err != nil {
			respond(w, nil, err)
			return
		}
		respond(w, struct{}{}, p.remove(r.Context(), actor.UserID, r.PathValue("id")))
	})
	register("POST /api/v2/auth/passkeys/register/begin", IdentityRead, func(w http.ResponseWriter, r *http.Request) {
		actor, err := sessionPrincipal(r)
		if err != nil {
			respond(w, nil, err)
			return
		}
		var request struct {
			Name string `json:"name"`
		}
		if !decode(r, w, &request) {
			return
		}
		request.Name = strings.TrimSpace(request.Name)
		if len(request.Name) < 1 || len(request.Name) > 64 {
			respond(w, nil, ErrInvalid)
			return
		}
		wa, origin, rpID, err := s.passkeyRequest(r)
		if err != nil {
			respond(w, nil, err)
			return
		}
		user, err := p.user(r.Context(), actor.UserID, rpID)
		if err != nil {
			respond(w, nil, err)
			return
		}
		creation, session, err := wa.BeginRegistration(user,
			webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
				ResidentKey:      protocol.ResidentKeyRequirementRequired,
				UserVerification: protocol.VerificationRequired,
			}))
		if err != nil {
			respond(w, nil, err)
			return
		}
		id, err := p.put(passkeyFlow{session: *session, origin: origin, rpID: rpID,
			owner: actor.UserID, sessionID: actor.CredentialID, name: request.Name})
		respond(w, passkeyStart{id, creation}, err)
	})
	register("POST /api/v2/auth/passkeys/register/finish", IdentityRead, func(w http.ResponseWriter, r *http.Request) {
		actor, err := sessionPrincipal(r)
		if err != nil {
			respond(w, nil, err)
			return
		}
		var request passkeyFinish
		if !decodePasskey(r, w, &request) {
			return
		}
		wa, origin, rpID, err := s.passkeyRequest(r)
		if err != nil {
			respond(w, nil, err)
			return
		}
		flow, err := p.take(request.FlowID, origin, rpID)
		if err != nil {
			respond(w, nil, err)
			return
		}
		if flow.owner != actor.UserID || flow.sessionID != actor.CredentialID {
			respond(w, nil, ErrForbidden)
			return
		}
		user, err := p.user(r.Context(), actor.UserID, rpID)
		if err != nil {
			respond(w, nil, err)
			return
		}
		signed, err := passkeyResponse(r, request.Credential)
		if err != nil {
			respond(w, nil, err)
			return
		}
		credential, err := wa.FinishRegistration(user, flow.session, signed)
		if err != nil {
			respond(w, nil, ErrUnauthorized)
			return
		}
		data, err := json.Marshal(credential)
		if err != nil {
			respond(w, nil, err)
			return
		}
		tx, err := p.store.db.BeginTx(r.Context(), nil)
		if err != nil {
			respond(w, nil, err)
			return
		}
		defer func() { _ = tx.Rollback() }()
		var count int
		err = tx.QueryRowContext(r.Context(), `SELECT count(*) FROM management_passkeys WHERE user_id=?`, actor.UserID).Scan(&count)
		if err != nil {
			respond(w, nil, err)
			return
		}
		if count >= maxPasskeys {
			respond(w, nil, ErrConflict)
			return
		}
		var existing int
		err = tx.QueryRowContext(r.Context(), `SELECT count(*) FROM management_users u
            JOIN management_credentials c ON c.user_id=u.id
            WHERE u.id=? AND u.disabled=0 AND u.credential IS NOT NULL AND
            c.id=? AND c.kind='session' AND c.revoked=0 AND c.generation=u.generation AND c.expires_at>?`,
			actor.UserID, actor.CredentialID, time.Now().Unix()).Scan(&existing)
		if err != nil || existing != 1 {
			respond(w, nil, ErrUnauthorized)
			return
		}
		_, err = tx.ExecContext(r.Context(), `INSERT INTO management_passkeys
            (credential_id,user_id,rp_id,data,name,created_at,last_used_at)
            VALUES(?,?,?,?,?,?,0)`, credential.ID, actor.UserID, rpID, data, flow.name, time.Now().Unix())
		if err != nil {
			respond(w, nil, ErrConflict)
			return
		}
		if err = recordEvent(r.Context(), tx, "passkey.added", actor.UserID, actor.UserID); err != nil {
			respond(w, nil, err)
			return
		}
		respond(w, struct{}{}, tx.Commit())
	})
	public("POST /api/v2/auth/passkeys/login/begin", func(w http.ResponseWriter, r *http.Request) {
		wa, origin, rpID, err := s.passkeyRequest(r)
		if err != nil {
			respond(w, nil, err)
			return
		}
		options, session, err := wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
		if err != nil {
			respond(w, nil, err)
			return
		}
		id, err := p.put(passkeyFlow{session: *session, origin: origin, rpID: rpID})
		respond(w, passkeyStart{id, options}, err)
	})
	public("POST /api/v2/auth/passkeys/login/finish", func(w http.ResponseWriter, r *http.Request) {
		var request passkeyFinish
		if !decodePasskey(r, w, &request) {
			return
		}
		wa, origin, rpID, err := s.passkeyRequest(r)
		if err != nil {
			respond(w, nil, err)
			return
		}
		flow, err := p.take(request.FlowID, origin, rpID)
		if err != nil || flow.owner != "" {
			respond(w, nil, ErrUnauthorized)
			return
		}
		signed, err := passkeyResponse(r, request.Credential)
		if err != nil {
			respond(w, nil, err)
			return
		}
		var owner string
		var previous []byte
		user, credential, err := wa.FinishPasskeyLogin(func(rawID, handle []byte) (webauthn.User, error) {
			u, old, lookupErr := p.userForCredential(r.Context(), rpID, rawID, handle)
			if lookupErr == nil {
				owner, previous = u.id, old
			}
			return u, lookupErr
		}, flow.session, signed)
		if err != nil || user == nil || credential == nil || owner == "" {
			p.store.audit(r.Context(), "passkey.login_failed", "", "")
			respond(w, nil, ErrUnauthorized)
			return
		}
		updated, err := json.Marshal(credential)
		if err != nil {
			respond(w, nil, err)
			return
		}
		tx, err := p.store.db.BeginTx(r.Context(), nil)
		if err != nil {
			respond(w, nil, err)
			return
		}
		defer func() { _ = tx.Rollback() }()
		result, err := tx.ExecContext(r.Context(), `UPDATE management_passkeys SET data=?,last_used_at=?
            WHERE credential_id=? AND user_id=? AND rp_id=? AND data=?`,
			updated, time.Now().Unix(), credential.ID, owner, rpID, previous)
		if err != nil {
			respond(w, nil, err)
			return
		}
		if n, _ := result.RowsAffected(); n != 1 {
			respond(w, nil, ErrUnauthorized)
			return
		}
		var active int
		err = tx.QueryRowContext(r.Context(), `SELECT count(*) FROM management_users
            WHERE id=? AND disabled=0 AND credential IS NOT NULL`, owner).Scan(&active)
		if err != nil || active != 1 {
			respond(w, nil, ErrUnauthorized)
			return
		}
		issued, err := issueCredential(sessionContext(r, "passkey"), tx, owner, "session", nil, time.Now().Add(8*time.Hour).Unix())
		if err != nil {
			respond(w, nil, err)
			return
		}
		if err = recordEvent(r.Context(), tx, "passkey.login_succeeded", owner, owner); err != nil {
			respond(w, nil, err)
			return
		}
		if err = tx.Commit(); err != nil {
			respond(w, nil, err)
			return
		}
		setSessionCookie(w, r, issued)
		respond(w, issued, nil)
	})
}

func decodePasskey(r *http.Request, w http.ResponseWriter, out *passkeyFinish) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, (128<<10)+1))
	if err != nil || len(body) > 128<<10 || json.Unmarshal(body, out) != nil || len(out.FlowID) != 43 {
		authError(w, http.StatusBadRequest)
		return false
	}
	return true
}
