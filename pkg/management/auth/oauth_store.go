package auth

import (
	"context"
	"database/sql"
	"errors"
	"github.com/Asutorufa/yuhaiin/pkg/security/configchange"
	"net/url"
	"strings"
	"time"
	"uuid"
)

type OAuthProvider struct {
	Issuer           string `json:"issuer,omitempty"`
	Name             string `json:"name,omitempty"`
	Enabled          *bool  `json:"enabled"`
	Revision         uint64 `json:"revision"`
	ClearSecret      bool   `json:"clearSecret,omitzero"`
	Provider         string `json:"provider"`
	ClientID         string `json:"clientId"`
	ClientSecret     string `json:"clientSecret,omitempty" secret:"true"`
	RedirectURL      string `json:"redirectUrl"`
	SecretConfigured bool   `json:"secretConfigured"`
}

func validProvider(provider string) bool {
	if provider == "github" || provider == "google" {
		return true
	}
	id, ok := strings.CutPrefix(provider, "oidc-")
	if !ok || len(id) != 36 {
		return false
	}
	parsed, err := uuid.Parse(id)
	return err == nil && parsed.String() == id
}
func (p OAuthProvider) isOIDC() bool { return strings.HasPrefix(p.Provider, "oidc-") }
func oauthIssuer(p OAuthProvider) string {
	switch p.Provider {
	case "google":
		return "https://accounts.google.com"
	case "github":
		return "https://github.com"
	default:
		return p.Issuer
	}
}
func (p OAuthProvider) enabled() bool { return p.Enabled == nil || *p.Enabled }
func publicOAuthProvider(p OAuthProvider) OAuthProvider {
	p.SecretConfigured = p.ClientSecret != ""
	p.ClientSecret = ""
	p.ClearSecret = false
	return p
}

func readOAuthProvider(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, provider string) (OAuthProvider, error) {
	out := OAuthProvider{Provider: provider}
	var enabled bool
	err := q.QueryRowContext(ctx, `SELECT client_id,client_secret,redirect_url,issuer,name,enabled,revision FROM management_oauth_providers WHERE provider=?`, provider).Scan(&out.ClientID, &out.ClientSecret, &out.RedirectURL, &out.Issuer, &out.Name, &enabled, &out.Revision)
	out.Enabled = new(enabled)
	out.SecretConfigured = out.ClientSecret != ""
	return out, err
}

func (s *Store) oauthProvider(ctx context.Context, provider string) (OAuthProvider, error) {
	return readOAuthProvider(ctx, s.db, provider)
}

func (s *Store) OAuthProviders(ctx context.Context) ([]OAuthProvider, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT provider,client_id,redirect_url,issuer,name,enabled,revision,length(client_secret)>0 FROM management_oauth_providers ORDER BY provider`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OAuthProvider{}
	for rows.Next() {
		var p OAuthProvider
		var enabled bool
		if err := rows.Scan(&p.Provider, &p.ClientID, &p.RedirectURL, &p.Issuer, &p.Name, &enabled, &p.Revision, &p.SecretConfigured); err != nil {
			return nil, err
		}
		p.Enabled = new(enabled)
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
	if !validOAuthProviderConfiguration(p) {
		return ErrInvalid
	}

	tx, err := configchange.Begin(ctx, s.db, "oidc-provider")
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	previous, err := readOAuthProvider(ctx, tx, p.Provider)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	exists := err == nil
	if p.isOIDC() && (p.Revision != previous.Revision || exists && p.Issuer != previous.Issuer) {
		return ErrConflict
	}
	if p.Revision > (1<<53)-2 {
		return ErrConflict
	}
	if !exists {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM management_oauth_providers`).Scan(&count); err != nil {
			return err
		}
		if count >= 32 {
			return ErrConflict
		}
	}
	providedSecret := p.ClientSecret != "" || p.ClearSecret
	if p.ClearSecret {
		p.ClientSecret = ""
	}
	if p.ClientSecret == "" && !p.ClearSecret {
		p.ClientSecret = previous.ClientSecret
	}
	if !p.isOIDC() && p.ClientSecret == "" {
		return ErrInvalid
	}
	actorPrincipal, authenticated := FromContext(ctx)
	if authenticated {
		actorPrincipal, err = freshRoleActor(ctx, tx, actorPrincipal)
		if err != nil || actorPrincipal.UserID != actor || !actorPrincipal.Allows(SecurityWrite) || providedSecret && !actorPrincipal.Allows(SecretsManage) {
			return ErrForbidden
		}
	}
	var lastRevision uint64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT revision FROM management_oauth_revisions WHERE provider=?),0)`, p.Provider).Scan(&lastRevision); err != nil {
		return err
	}
	if lastRevision >= (1<<53)-1 {
		return ErrConflict
	}
	p.Revision = max(previous.Revision, lastRevision) + 1
	if _, err := tx.ExecContext(ctx, `INSERT INTO management_oauth_revisions(provider,revision) VALUES(?,?) ON CONFLICT(provider) DO UPDATE SET revision=excluded.revision`, p.Provider, p.Revision); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO management_oauth_providers(provider,client_id,client_secret,redirect_url,issuer,name,enabled,revision) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(provider) DO UPDATE SET client_id=excluded.client_id,client_secret=excluded.client_secret,redirect_url=excluded.redirect_url,issuer=excluded.issuer,name=excluded.name,enabled=excluded.enabled,revision=excluded.revision`, p.Provider, p.ClientID, p.ClientSecret, p.RedirectURL, p.Issuer, p.Name, p.enabled(), p.Revision); err != nil {
		return ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `UPDATE management_credentials SET revoked=1 WHERE kind='session' AND auth_method=?`, p.Provider); err != nil {
		return err
	}
	publicAfter := struct {
		OAuthProvider
		ClientSecretChanged bool `json:"clientSecretChanged"`
	}{OAuthProvider: publicOAuthProvider(p), ClientSecretChanged: p.ClientSecret != previous.ClientSecret}
	ctx, err = roleAuditContext(ctx, publicOAuthProvider(previous), publicAfter)
	if err != nil {
		return err
	}

	if err := recordEvent(ctx, tx, "oauth.provider_updated", actor, p.Provider); err != nil {
		return err
	}
	var historyBefore *OAuthProvider
	if exists {
		historyBefore = &previous
	}
	historyAfter := p
	historyAfter.ClearSecret = false
	historyAfter.SecretConfigured = p.ClientSecret != ""
	var publicBefore any
	if exists {
		publicBefore = publicOAuthProvider(previous)
	}
	if err := configchange.RecordValues(ctx, s.db, tx, "oidc-provider", p.Provider, p.Revision, historyBefore, historyAfter, publicBefore, publicAfter); err != nil {
		return err
	}
	return configchange.Commit(ctx, tx)
}

func (s *Store) DeleteOAuthProvider(ctx context.Context, actor, provider string) error {
	tx, err := configchange.Begin(ctx, s.db, "oidc-provider")
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if actorPrincipal, authenticated := FromContext(ctx); authenticated {
		current, err := freshRoleActor(ctx, tx, actorPrincipal)
		if err != nil || current.UserID != actor || !current.Allows(SecurityWrite) {
			return ErrForbidden
		}
	}
	previous, err := readOAuthProvider(ctx, tx, provider)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE management_credentials SET revoked=1 WHERE kind='session' AND auth_method=?`, provider); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM management_oauth_providers WHERE provider=?`, provider); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM management_oauth_links WHERE provider=?`, provider); err != nil {
		return err
	}
	if err := recordEvent(ctx, tx, "oauth.provider_disabled", actor, provider); err != nil {
		return err
	}
	if err := configchange.RecordValues(ctx, s.db, tx, "oidc-provider", provider, previous.Revision+1, previous, nil, publicOAuthProvider(previous), nil); err != nil {
		return err
	}
	return configchange.Commit(ctx, tx)
}

type OAuthLink struct {
	Issuer      string `json:"issuer,omitempty"`
	Provider    string `json:"provider"`
	Subject     string `json:"subject"`
	DisplayName string `json:"displayName"`
	CreatedAt   int64  `json:"createdAt"`
}

func (s *Store) OAuthLinks(ctx context.Context, owner string) ([]OAuthLink, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT provider,subject,display_name,created_at,issuer FROM management_oauth_links WHERE user_id=? ORDER BY provider`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OAuthLink{}
	for rows.Next() {
		var link OAuthLink
		if err := rows.Scan(&link.Provider, &link.Subject, &link.DisplayName, &link.CreatedAt, &link.Issuer); err != nil {
			return nil, err
		}
		out = append(out, link)
	}
	return out, rows.Err()
}

// Linking and sign-in revalidate the initiating session/account inside the same
// transaction as the write, including reset/disable/unlink races.
func (s *Store) completeOAuth(ctx context.Context, flow oauthFlow, link OAuthLink, actor Principal) (*IssuedCredential, error) {
	if link.Issuer == "" && !strings.HasPrefix(link.Provider, "oidc-") {
		link.Issuer = oauthIssuer(OAuthProvider{Provider: link.Provider})
	}
	if !validProvider(link.Provider) || link.Subject == "" || len(link.Subject) > 255 {
		return nil, ErrUnauthorized
	}
	link.DisplayName = strings.ToValidUTF8(link.DisplayName[:min(len(link.DisplayName), 255)], "")
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if flow.Provider.Provider != "" {
		current, err := readOAuthProvider(ctx, tx, flow.Provider.Provider)
		if err != nil || !current.enabled() || current.Revision != flow.Provider.Revision || current.Issuer != flow.Provider.Issuer || link.Provider != current.Provider || link.Issuer != oauthIssuer(current) {
			return nil, ErrUnauthorized
		}
	} else if strings.HasPrefix(link.Provider, "oidc-") {
		return nil, ErrUnauthorized
	}
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
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM management_oauth_links WHERE (issuer=? AND subject=?) OR (user_id=? AND provider=?)`, link.Issuer, link.Subject, owner, link.Provider).Scan(&count); err != nil {
			return nil, err
		}
		if count != 0 {
			return nil, ErrConflict
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO management_oauth_links(provider,subject,user_id,display_name,created_at,issuer) VALUES(?,?,?,?,?,?)`, link.Provider, link.Subject, owner, link.DisplayName, time.Now().Unix(), link.Issuer); err != nil {
			return nil, err
		}
		if err := recordEvent(ctx, tx, "oauth.linked", owner, link.Provider); err != nil {
			return nil, err
		}
		return nil, tx.Commit()
	}
	err = tx.QueryRowContext(ctx, `SELECT u.id FROM management_oauth_links l JOIN management_users u ON u.id=l.user_id WHERE l.provider=? AND l.subject=? AND l.issuer=? AND u.disabled=0 AND u.credential IS NOT NULL`, link.Provider, link.Subject, link.Issuer).Scan(&owner)
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
	p, err = freshRoleActor(ctx, tx, p)
	if err != nil || !p.Allows(IdentityRead) {
		return ErrForbidden
	}
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
