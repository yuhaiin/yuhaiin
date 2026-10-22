package auth

import (
	"context"
	"database/sql"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

type sessionInfoKey struct{}
type sessionInfo struct{ UserAgent, RemoteAddr, Method string }

func sessionContext(r *http.Request, method string) context.Context {
	peer, _ := netip.ParseAddrPort(r.RemoteAddr)
	// Forwarded headers are untrusted. Store only the actual socket peer.
	return context.WithValue(r.Context(), sessionInfoKey{}, sessionInfo{
		UserAgent:  strings.ToValidUTF8(r.UserAgent()[:min(len(r.UserAgent()), 512)], ""),
		RemoteAddr: peer.Addr().Unmap().String(), Method: method,
	})
}

func saveSessionInfo(ctx context.Context, tx *sql.Tx, id string, info sessionInfo) error {
	if info.Method == "" {
		info.Method = "password"
	}
	_, err := tx.ExecContext(ctx, `UPDATE management_credentials SET user_agent=?,remote_addr=?,last_seen=?,auth_method=? WHERE id=?`, info.UserAgent, info.RemoteAddr, time.Now().Unix(), info.Method, id)
	return err
}

type Session struct {
	ID         string `json:"id"`
	CreatedAt  int64  `json:"createdAt"`
	ExpiresAt  int64  `json:"expiresAt"`
	LastSeen   int64  `json:"lastSeen"`
	UserAgent  string `json:"userAgent"`
	RemoteAddr string `json:"remoteAddr"`
	AuthMethod string `json:"authMethod"`
	Current    bool   `json:"current"`
}

func (s *Store) Sessions(ctx context.Context, p Principal) ([]Session, error) {
	if p.CredentialType != "session" {
		return nil, ErrForbidden
	}
	rows, err := s.db.QueryContext(ctx, `SELECT c.id,c.created_at,c.expires_at,c.last_seen,c.user_agent,c.remote_addr,c.auth_method
        FROM management_credentials c JOIN management_users u ON u.id=c.user_id
        WHERE c.user_id=? AND c.kind='session' AND c.revoked=0 AND c.generation=u.generation AND u.disabled=0
        AND (c.expires_at=0 OR c.expires_at>?) ORDER BY c.created_at DESC,c.id`, p.UserID, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Session{}
	for rows.Next() {
		var session Session
		if err := rows.Scan(&session.ID, &session.CreatedAt, &session.ExpiresAt, &session.LastSeen, &session.UserAgent, &session.RemoteAddr, &session.AuthMethod); err != nil {
			return nil, err
		}
		session.Current = session.ID == p.CredentialID
		out = append(out, session)
	}
	return out, rows.Err()
}

func (s *Store) RevokeSession(ctx context.Context, p Principal, id string) error {
	if p.CredentialType != "session" {
		return ErrForbidden
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `UPDATE management_credentials SET revoked=1 WHERE id=? AND user_id=? AND kind='session' AND revoked=0`, id, p.UserID)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return sql.ErrNoRows
	}
	if err := recordEvent(ctx, tx, "session.revoked", p.UserID, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Server) registerSessions(register func(string, Permission, http.HandlerFunc)) {
	register("GET /api/v2/auth/sessions", IdentityRead, func(w http.ResponseWriter, r *http.Request) {
		p, _ := FromContext(r.Context())
		out, err := s.Store.Sessions(r.Context(), p)
		respond(w, out, err)
	})
	register("DELETE /api/v2/auth/sessions/{id}", IdentityRead, func(w http.ResponseWriter, r *http.Request) {
		p, _ := FromContext(r.Context())
		respond(w, struct{}{}, s.Store.RevokeSession(r.Context(), p, r.PathValue("id")))
	})
}
