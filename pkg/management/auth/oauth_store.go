package auth

import (
	"context"
	"database/sql"
	"net/url"
	"strings"
	"time"
)

type OAuthProvider struct {
	Provider         string `json:"provider"`
	ClientID         string `json:"clientId"`
	ClientSecret     string `json:"clientSecret,omitempty"`
	RedirectURL      string `json:"redirectUrl"`
	SecretConfigured bool   `json:"secretConfigured"`
}

func validProvider(provider string) bool { return provider == "github" || provider == "google" }

func (s *Store) oauthProvider(ctx context.Context, provider string) (OAuthProvider, error) {
	out := OAuthProvider{Provider: provider}
	err := s.db.QueryRowContext(ctx, `SELECT client_id,client_secret,redirect_url FROM management_oauth_providers WHERE provider=?`, provider).Scan(&out.ClientID, &out.ClientSecret, &out.RedirectURL)
	return out, err
}

func (s *Store) OAuthProviders(ctx context.Context) ([]OAuthProvider, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT provider,client_id,redirect_url FROM management_oauth_providers ORDER BY provider`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OAuthProvider{}
	for rows.Next() {
		var p OAuthProvider
		if err := rows.Scan(&p.Provider, &p.ClientID, &p.RedirectURL); err != nil {
			return nil, err
		}
		p.SecretConfigured = true
		out = append(out, p)
	}
	return out, rows.Err()
}

func validOAuthCallback(provider, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/api/v2/auth/oauth/"+provider+"/callback" {
		return false
	}
	return u.Scheme == "https" || u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
}

func (s *Store) SaveOAuthProvider(ctx context.Context, actor string, p OAuthProvider) error {
	if !validProvider(p.Provider) || len(p.ClientID) > 512 || len(p.ClientSecret) > 2048 || len(p.RedirectURL) > 2048 || p.ClientID == "" || !validOAuthCallback(p.Provider, p.RedirectURL) {
		return ErrInvalid
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if p.ClientSecret == "" {
		if err := tx.QueryRowContext(ctx, `SELECT client_secret FROM management_oauth_providers WHERE provider=?`, p.Provider).Scan(&p.ClientSecret); err != nil {
			return ErrInvalid
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO management_oauth_providers(provider,client_id,client_secret,redirect_url) VALUES(?,?,?,?) ON CONFLICT(provider) DO UPDATE SET client_id=excluded.client_id,client_secret=excluded.client_secret,redirect_url=excluded.redirect_url`, p.Provider, p.ClientID, p.ClientSecret, p.RedirectURL); err != nil {
		return err
	}
	if err := recordEvent(ctx, tx, "oauth.provider_updated", actor, p.Provider); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteOAuthProvider(ctx context.Context, actor, provider string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM management_oauth_providers WHERE provider=?`, provider); err != nil {
		return err
	}
	if err := recordEvent(ctx, tx, "oauth.provider_disabled", actor, provider); err != nil {
		return err
	}
	return tx.Commit()
}

type OAuthLink struct {
	Provider    string `json:"provider"`
	Subject     string `json:"subject"`
	DisplayName string `json:"displayName"`
	CreatedAt   int64  `json:"createdAt"`
}

func (s *Store) OAuthLinks(ctx context.Context, owner string) ([]OAuthLink, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT provider,subject,display_name,created_at FROM management_oauth_links WHERE user_id=? ORDER BY provider`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OAuthLink{}
	for rows.Next() {
		var link OAuthLink
		if err := rows.Scan(&link.Provider, &link.Subject, &link.DisplayName, &link.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, link)
	}
	return out, rows.Err()
}

// Linking and sign-in revalidate the initiating session/account inside the same
// transaction as the write, including reset/disable/unlink races.
func (s *Store) completeOAuth(ctx context.Context, flow oauthFlow, link OAuthLink, actor Principal) (*IssuedCredential, error) {
	if !validProvider(link.Provider) || link.Subject == "" || len(link.Subject) > 255 {
		return nil, ErrUnauthorized
	}
	link.DisplayName = strings.ToValidUTF8(link.DisplayName[:min(len(link.DisplayName), 255)], "")
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var owner string
	if flow.Owner != "" {
		if actor.CredentialType != "session" || actor.CredentialID != flow.CredentialID || actor.UserID != flow.Owner {
			return nil, ErrForbidden
		}
		err = tx.QueryRowContext(ctx, `SELECT u.id FROM management_users u JOIN management_credentials c ON c.user_id=u.id WHERE c.id=? AND c.kind='session' AND c.revoked=0 AND c.generation=u.generation AND c.expires_at>? AND u.credential IS NOT NULL AND u.disabled=0`, flow.CredentialID, time.Now().Unix()).Scan(&owner)
		if err != nil {
			return nil, ErrUnauthorized
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM management_oauth_links WHERE (provider=? AND subject=?) OR (user_id=? AND provider=?)`, link.Provider, link.Subject, owner, link.Provider).Scan(&count); err != nil {
			return nil, err
		}
		if count != 0 {
			return nil, ErrConflict
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO management_oauth_links(provider,subject,user_id,display_name,created_at) VALUES(?,?,?,?,?)`, link.Provider, link.Subject, owner, link.DisplayName, time.Now().Unix()); err != nil {
			return nil, err
		}
		if err := recordEvent(ctx, tx, "oauth.linked", owner, link.Provider); err != nil {
			return nil, err
		}
		return nil, tx.Commit()
	}
	err = tx.QueryRowContext(ctx, `SELECT u.id FROM management_oauth_links l JOIN management_users u ON u.id=l.user_id WHERE l.provider=? AND l.subject=? AND u.disabled=0 AND u.credential IS NOT NULL`, link.Provider, link.Subject).Scan(&owner)
	if err != nil {
		return nil, ErrUnauthorized
	}
	issued, err := issueCredential(ctx, tx, owner, "session", nil, time.Now().Add(8*time.Hour).Unix())
	if err != nil {
		return nil, err
	}
	if err := recordEvent(ctx, tx, "oauth.login_succeeded", owner, link.Provider); err != nil {
		return nil, err
	}
	return &issued, tx.Commit()
}

func (s *Store) UnlinkOAuth(ctx context.Context, p Principal, provider string) error {
	if p.CredentialType != "session" {
		return ErrForbidden
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `DELETE FROM management_oauth_links WHERE user_id=? AND provider=?`, p.UserID, provider)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return sql.ErrNoRows
	}
	// Provider-created sessions stop immediately when its binding is removed.
	if _, err := tx.ExecContext(ctx, `UPDATE management_credentials SET revoked=1 WHERE user_id=? AND kind='session' AND auth_method=?`, p.UserID, provider); err != nil {
		return err
	}
	if err := recordEvent(ctx, tx, "oauth.unlinked", p.UserID, provider); err != nil {
		return err
	}
	return tx.Commit()
}
