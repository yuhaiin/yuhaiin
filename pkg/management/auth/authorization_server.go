package auth

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
	"uuid"

	"github.com/Asutorufa/yuhaiin/pkg/management/oauth"
	permission "github.com/Asutorufa/yuhaiin/pkg/management/permission"
)

// AuthorizationServer is Yuhaiin's OAuth 2.1 Authorization Server. It is a
// management identity feature, not part of any single resource server: the
// management HTTP API, MCP and future resources are entries of one Registry,
// and every token is an ordinary management credential bound to one grant,
// one client and exactly one resource.
//
// It is unrelated to the GitHub, Google and OIDC login providers in oauth.go,
// which let Yuhaiin users sign in with an external identity provider. Here
// Yuhaiin is the provider, and those logins are just one way for a user to
// authenticate before giving consent.
type AuthorizationServer struct {
	store     *Store
	resources *oauth.Registry
	limiter   *rateLimiter

	mu      sync.Mutex
	pending map[string]authorizationRequest
}

func newAuthorizationServer(store *Store, resources *oauth.Registry) *AuthorizationServer {
	if resources == nil {
		resources = &oauth.Registry{}
	}
	return &AuthorizationServer{store: store, resources: resources, limiter: newRateLimiter(120, 1200), pending: make(map[string]authorizationRequest)}
}

// Resources returns the protected resource registry.
func (a *AuthorizationServer) Resources() *oauth.Registry { return a.resources }

const (
	credentialOAuth    = "oauth"
	kindOAuthAccess    = "oauth_access"
	kindOAuthRefresh   = "oauth_refresh"
	codeLifetime       = 5 * time.Minute
	requestLifetime    = 10 * time.Minute
	maxPendingRequests = 256
	maxDynamicClients  = 512
	maxClients         = 1024
	maxGrantsPerUser   = 128
	// Rotated refresh tokens are retained for reuse detection. The most recent
	// ones per grant are enough: a token older than that is simply unknown.
	retainedRotations = 32
)

// OAuthServerSettings is the operator-facing configuration. The issuer is the
// externally reachable origin, set explicitly by an administrator; it is never
// derived from request headers.
type OAuthServerSettings struct {
	Enabled             bool     `json:"enabled"`
	Issuer              string   `json:"issuer"`
	DynamicRegistration bool     `json:"dynamicRegistration"`
	DisabledResources   []string `json:"disabledResources"`
	AccessTokenTTL      int64    `json:"accessTokenTtl"`
	RefreshTokenTTL     int64    `json:"refreshTokenTtl"`
	GrantTTL            int64    `json:"grantTtl"`
	Revision            uint64   `json:"revision"`
}

func (s OAuthServerSettings) active() bool { return s.Enabled && s.Issuer != "" }

func (s OAuthServerSettings) resourceEnabled(id string) bool {
	return s.active() && !slices.Contains(s.DisabledResources, id)
}

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readOAuthServerSettings(ctx context.Context, q queryer) (OAuthServerSettings, error) {
	var s OAuthServerSettings
	var disabled string
	err := q.QueryRowContext(ctx, `SELECT enabled,issuer,dynamic_registration,disabled_resources,access_token_ttl,refresh_token_ttl,grant_ttl,revision FROM management_oauth_server WHERE id=1`).
		Scan(&s.Enabled, &s.Issuer, &s.DynamicRegistration, &disabled, &s.AccessTokenTTL, &s.RefreshTokenTTL, &s.GrantTTL, &s.Revision)
	if err != nil {
		return OAuthServerSettings{}, err
	}
	if err := json.Unmarshal([]byte(disabled), &s.DisabledResources); err != nil {
		return OAuthServerSettings{}, err
	}
	if s.DisabledResources == nil {
		s.DisabledResources = []string{}
	}
	return s, nil
}

// Settings returns the current Authorization Server configuration.
func (a *AuthorizationServer) Settings(ctx context.Context) (OAuthServerSettings, error) {
	return readOAuthServerSettings(ctx, a.store.db)
}

// SaveSettings validates and stores the configuration. Disabling the server,
// changing the issuer or disabling a resource takes effect on the next request:
// tokens are validated against the current settings every time.
func (a *AuthorizationServer) SaveSettings(ctx context.Context, actor Principal, next OAuthServerSettings) (OAuthServerSettings, error) {
	if next.Issuer != "" {
		issuer, err := oauth.NormalizeIssuer(next.Issuer)
		if err != nil {
			return OAuthServerSettings{}, ErrInvalid
		}
		next.Issuer = issuer
	}
	if next.Enabled && next.Issuer == "" ||
		next.AccessTokenTTL < 300 || next.AccessTokenTTL > 3600 ||
		next.GrantTTL < 86400 || next.GrantTTL > 365*86400 ||
		next.RefreshTokenTTL < 3600 || next.RefreshTokenTTL > next.GrantTTL {
		return OAuthServerSettings{}, ErrInvalid
	}
	next.DisabledResources = slices.Compact(slices.Sorted(slices.Values(next.DisabledResources)))
	for _, id := range next.DisabledResources {
		if _, ok := a.resources.ByID(id); !ok {
			return OAuthServerSettings{}, ErrInvalid
		}
	}
	encoded, err := json.Marshal(next.DisabledResources)
	if err != nil {
		return OAuthServerSettings{}, err
	}
	tx, err := a.store.db.BeginTx(ctx, nil)
	if err != nil {
		return OAuthServerSettings{}, err
	}
	defer func() { _ = tx.Rollback() }()
	current, err := readOAuthServerSettings(ctx, tx)
	if err != nil {
		return OAuthServerSettings{}, err
	}
	if next.Revision != current.Revision {
		return OAuthServerSettings{}, ErrConflict
	}
	changes, _ := json.Marshal(struct {
		Before OAuthServerSettings `json:"before"`
		After  OAuthServerSettings `json:"after"`
	}{current, next})
	if _, err := tx.ExecContext(ctx, `UPDATE management_oauth_server SET enabled=?,issuer=?,dynamic_registration=?,disabled_resources=?,access_token_ttl=?,refresh_token_ttl=?,grant_ttl=?,revision=revision+1 WHERE id=1`,
		next.Enabled, next.Issuer, next.DynamicRegistration, string(encoded), next.AccessTokenTTL, next.RefreshTokenTTL, next.GrantTTL); err != nil {
		return OAuthServerSettings{}, err
	}
	if err := recordOAuthEvent(ctx, tx, "oauth.settings.updated", actor.UserID, "authorization-server", oauthDetails{Changes: string(changes)}); err != nil {
		return OAuthServerSettings{}, err
	}
	if err := tx.Commit(); err != nil {
		return OAuthServerSettings{}, err
	}
	return a.Settings(ctx)
}

// OAuthClient is a registered OAuth client. Client secrets are shown once at
// creation and stored only as a SHA-256 verifier.
type OAuthClient struct {
	ID                      string       `json:"id"`
	Name                    string       `json:"name"`
	Type                    string       `json:"type"`
	Registration            string       `json:"registration"`
	RedirectURIs            []string     `json:"redirectUris"`
	TokenEndpointAuthMethod string       `json:"tokenEndpointAuthMethod"`
	GrantTypes              []string     `json:"grantTypes"`
	Scopes                  []Permission `json:"scopes"`
	Resources               []string     `json:"resources"`
	ClientURI               string       `json:"clientUri"`
	CreatedBy               string       `json:"createdBy"`
	CreatedAt               int64        `json:"createdAt"`
	UpdatedAt               int64        `json:"updatedAt"`
	Disabled                bool         `json:"disabled"`
	ActiveGrants            int          `json:"activeGrants"`
}

// IssuedOAuthClient carries a newly generated client secret exactly once.
type IssuedOAuthClient struct {
	OAuthClient
	Secret string `json:"secret,omitempty"`
}

// OAuthClientRequest creates or updates a pre-registered client.
type OAuthClientRequest struct {
	Name                    string       `json:"name"`
	Type                    string       `json:"type"`
	RedirectURIs            []string     `json:"redirectUris"`
	TokenEndpointAuthMethod string       `json:"tokenEndpointAuthMethod"`
	Scopes                  []Permission `json:"scopes"`
	Resources               []string     `json:"resources"`
	ClientURI               string       `json:"clientUri"`
	Disabled                bool         `json:"disabled"`
}

const clientColumns = `c.id,c.name,c.client_type,c.registration,c.redirect_uris,c.token_endpoint_auth_method,c.grant_types,c.scopes,c.resources,c.client_uri,c.created_by,c.created_at,c.updated_at,c.disabled,
	(SELECT count(*) FROM management_oauth_grants g WHERE g.client_id=c.id AND g.revoked=0 AND g.expires_at>unixepoch())`

func scanClient(row scanner) (OAuthClient, error) {
	var c OAuthClient
	var redirects, grants, scopes, resources string
	if err := row.Scan(&c.ID, &c.Name, &c.Type, &c.Registration, &redirects, &c.TokenEndpointAuthMethod, &grants, &scopes, &resources, &c.ClientURI, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt, &c.Disabled, &c.ActiveGrants); err != nil {
		return OAuthClient{}, err
	}
	for _, field := range []struct {
		raw string
		out any
	}{{redirects, &c.RedirectURIs}, {grants, &c.GrantTypes}, {scopes, &c.Scopes}, {resources, &c.Resources}} {
		if err := json.Unmarshal([]byte(field.raw), field.out); err != nil {
			return OAuthClient{}, err
		}
	}
	return c, nil
}

// Clients lists every registered client.
func (a *AuthorizationServer) Clients(ctx context.Context) ([]OAuthClient, error) {
	rows, err := a.store.db.QueryContext(ctx, `SELECT `+clientColumns+` FROM management_oauth_clients c ORDER BY c.created_at,c.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OAuthClient{}
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (a *AuthorizationServer) client(ctx context.Context, q queryer, id string) (OAuthClient, error) {
	return scanClient(q.QueryRowContext(ctx, `SELECT `+clientColumns+` FROM management_oauth_clients c WHERE c.id=?`, id))
}

func validClientName(name string) bool {
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 100 {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// normalizeClient validates client metadata against the resource registry.
func (a *AuthorizationServer) normalizeClient(c *OAuthClient) error {
	c.Name = strings.TrimSpace(c.Name)
	if !validClientName(c.Name) || len(c.ClientURI) > 2048 {
		return oauth.InvalidClientMetadata("client name is required and must be short plain text")
	}
	if c.ClientURI != "" {
		if err := oauth.ValidateRedirectURI(c.ClientURI, false); err != nil || !strings.HasPrefix(c.ClientURI, "https://") {
			return oauth.InvalidClientMetadata("client URI must be an https URL")
		}
	}
	switch c.Type {
	case "public":
		if c.TokenEndpointAuthMethod == "" {
			c.TokenEndpointAuthMethod = "none"
		}
		if c.TokenEndpointAuthMethod != "none" {
			return oauth.InvalidClientMetadata("public clients use token endpoint authentication method none")
		}
	case "confidential":
		if c.TokenEndpointAuthMethod == "" {
			c.TokenEndpointAuthMethod = "client_secret_basic"
		}
		if c.TokenEndpointAuthMethod != "client_secret_basic" && c.TokenEndpointAuthMethod != "client_secret_post" {
			return oauth.InvalidClientMetadata("confidential clients use client_secret_basic or client_secret_post")
		}
	default:
		return oauth.InvalidClientMetadata("client type must be public or confidential")
	}
	if len(c.RedirectURIs) == 0 || len(c.RedirectURIs) > 16 {
		return oauth.InvalidRedirectURI("between one and sixteen redirect URIs are required")
	}
	for _, uri := range c.RedirectURIs {
		if err := oauth.ValidateRedirectURI(uri, c.Type == "public"); err != nil {
			return err
		}
	}
	c.RedirectURIs = slices.Compact(slices.Clone(c.RedirectURIs))
	if len(c.Resources) == 0 {
		for _, r := range a.resources.All() {
			c.Resources = append(c.Resources, r.ID)
		}
	}
	var available []Permission
	for _, id := range c.Resources {
		r, ok := a.resources.ByID(id)
		if !ok {
			return oauth.InvalidClientMetadata("unknown resource " + id)
		}
		available = append(available, r.Scopes...)
	}
	c.Resources = slices.Compact(slices.Sorted(slices.Values(c.Resources)))
	if len(c.Scopes) == 0 {
		c.Scopes = oauth.Intersect(permission.DelegableValues(), available)
	}
	for _, scope := range c.Scopes {
		if !permission.Delegable(scope) || !slices.Contains(available, scope) {
			return oauth.InvalidScope("scope " + string(scope) + " is not offered by the client's resources")
		}
	}
	c.Scopes = oauth.Intersect(permission.DelegableValues(), c.Scopes)
	c.GrantTypes = slices.Clone(oauth.GrantTypes)
	return nil
}

func insertClient(ctx context.Context, tx *sql.Tx, c OAuthClient, secret string) error {
	encode := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	var hash []byte
	if secret != "" {
		hash = oauth.Hash(secret)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO management_oauth_clients(id,name,client_type,registration,redirect_uris,token_endpoint_auth_method,secret_hash,grant_types,scopes,resources,client_uri,created_by,created_at,updated_at,disabled) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.ID, c.Name, c.Type, c.Registration, encode(c.RedirectURIs), c.TokenEndpointAuthMethod, hash, encode(c.GrantTypes), encode(c.Scopes), encode(c.Resources), c.ClientURI, c.CreatedBy, c.CreatedAt, c.UpdatedAt, c.Disabled)
	return err
}

// CreateClient pre-registers a client. A confidential client's secret is
// returned once and never again.
func (a *AuthorizationServer) CreateClient(ctx context.Context, actor Principal, request OAuthClientRequest) (IssuedOAuthClient, error) {
	now := time.Now().Unix()
	c := OAuthClient{ID: oauth.NewClientID(), Name: request.Name, Type: request.Type, Registration: "manual", RedirectURIs: request.RedirectURIs, TokenEndpointAuthMethod: request.TokenEndpointAuthMethod, Scopes: request.Scopes, Resources: request.Resources, ClientURI: request.ClientURI, CreatedBy: actor.UserID, CreatedAt: now, UpdatedAt: now, Disabled: request.Disabled}
	return a.registerClient(ctx, actor.UserID, c)
}

func (a *AuthorizationServer) registerClient(ctx context.Context, actor string, c OAuthClient) (IssuedOAuthClient, error) {
	if err := a.normalizeClient(&c); err != nil {
		return IssuedOAuthClient{}, err
	}
	secret := ""
	if c.Type == "confidential" {
		secret = oauth.NewSecret(oauth.ClientSecretPrefix)
	}
	tx, err := a.store.db.BeginTx(ctx, nil)
	if err != nil {
		return IssuedOAuthClient{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if c.Registration == "dynamic" {
		// Abandoned dynamic registrations without any grant are reclaimed.
		if _, err := tx.ExecContext(ctx, `DELETE FROM management_oauth_clients WHERE registration='dynamic' AND created_at<? AND NOT EXISTS(SELECT 1 FROM management_oauth_grants g WHERE g.client_id=management_oauth_clients.id)`, time.Now().Add(-24*time.Hour).Unix()); err != nil {
			return IssuedOAuthClient{}, err
		}
		var dynamic int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM management_oauth_clients WHERE registration='dynamic'`).Scan(&dynamic); err != nil {
			return IssuedOAuthClient{}, err
		}
		if dynamic >= maxDynamicClients {
			return IssuedOAuthClient{}, ErrConflict
		}
	}
	var total int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM management_oauth_clients`).Scan(&total); err != nil {
		return IssuedOAuthClient{}, err
	}
	if total >= maxClients {
		return IssuedOAuthClient{}, ErrConflict
	}
	if err := insertClient(ctx, tx, c, secret); err != nil {
		return IssuedOAuthClient{}, err
	}
	if err := recordOAuthEvent(ctx, tx, "oauth.client.created", actor, c.ID, oauthDetails{ClientID: c.ID}); err != nil {
		return IssuedOAuthClient{}, err
	}
	if err := tx.Commit(); err != nil {
		return IssuedOAuthClient{}, err
	}
	return IssuedOAuthClient{OAuthClient: c, Secret: secret}, nil
}

// UpdateClient changes a client's metadata. The type and secret are fixed at
// registration. Disabling a client invalidates its tokens immediately, because
// validation joins the client row; re-enabling restores nothing that was
// revoked in the meantime.
func (a *AuthorizationServer) UpdateClient(ctx context.Context, actor Principal, id string, request OAuthClientRequest) (OAuthClient, error) {
	tx, err := a.store.db.BeginTx(ctx, nil)
	if err != nil {
		return OAuthClient{}, err
	}
	defer func() { _ = tx.Rollback() }()
	c, err := a.client(ctx, tx, id)
	if err != nil {
		return OAuthClient{}, err
	}
	before := c
	c.Name, c.RedirectURIs, c.Scopes, c.Resources, c.ClientURI, c.Disabled = request.Name, request.RedirectURIs, request.Scopes, request.Resources, request.ClientURI, request.Disabled
	if request.TokenEndpointAuthMethod != "" {
		c.TokenEndpointAuthMethod = request.TokenEndpointAuthMethod
	}
	if request.Type != "" && request.Type != c.Type {
		return OAuthClient{}, oauth.InvalidClientMetadata("the client type cannot change")
	}
	if err := a.normalizeClient(&c); err != nil {
		return OAuthClient{}, err
	}
	c.UpdatedAt = time.Now().Unix()
	encode := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	if _, err := tx.ExecContext(ctx, `UPDATE management_oauth_clients SET name=?,redirect_uris=?,token_endpoint_auth_method=?,scopes=?,resources=?,client_uri=?,disabled=?,updated_at=? WHERE id=?`,
		c.Name, encode(c.RedirectURIs), c.TokenEndpointAuthMethod, encode(c.Scopes), encode(c.Resources), c.ClientURI, c.Disabled, c.UpdatedAt, id); err != nil {
		return OAuthClient{}, err
	}
	// Narrowing a client's scopes or resources revokes grants beyond them.
	if _, err := tx.ExecContext(ctx, `UPDATE management_oauth_grants SET revoked=1,revoked_reason='client_changed' WHERE client_id=? AND revoked=0 AND (
		EXISTS(SELECT 1 FROM json_each(management_oauth_grants.scopes) s WHERE s.value NOT IN (SELECT value FROM json_each(?))))`, id, encode(c.Scopes)); err != nil {
		return OAuthClient{}, err
	}
	changes, _ := json.Marshal(struct {
		Before OAuthClient `json:"before"`
		After  OAuthClient `json:"after"`
	}{before, c})
	event := "oauth.client.updated"
	if c.Disabled && !before.Disabled {
		event = "oauth.client.disabled"
	}
	if err := recordOAuthEvent(ctx, tx, event, actor.UserID, id, oauthDetails{ClientID: id, Changes: string(changes)}); err != nil {
		return OAuthClient{}, err
	}
	if err := tx.Commit(); err != nil {
		return OAuthClient{}, err
	}
	return a.client(ctx, a.store.db, id)
}

// DeleteClient removes a client and, by cascade, all of its grants and tokens.
func (a *AuthorizationServer) DeleteClient(ctx context.Context, actor Principal, id string) error {
	tx, err := a.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `DELETE FROM management_oauth_clients WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return sql.ErrNoRows
	}
	if err := recordOAuthEvent(ctx, tx, "oauth.client.deleted", actor.UserID, id, oauthDetails{ClientID: id}); err != nil {
		return err
	}
	return tx.Commit()
}

// OAuthGrant is one user's authorization of one client for one resource.
type OAuthGrant struct {
	ID            string       `json:"id"`
	ClientID      string       `json:"clientId"`
	ClientName    string       `json:"clientName"`
	ClientType    string       `json:"clientType"`
	Registration  string       `json:"registration"`
	UserID        string       `json:"userId"`
	UserLogin     string       `json:"userLogin"`
	Resource      string       `json:"resource"`
	ResourceID    string       `json:"resourceId"`
	Scopes        []Permission `json:"scopes"`
	CreatedAt     int64        `json:"createdAt"`
	ExpiresAt     int64        `json:"expiresAt"`
	LastUsedAt    int64        `json:"lastUsedAt"`
	Revoked       bool         `json:"revoked"`
	RevokedReason string       `json:"revokedReason"`
	ActiveTokens  int          `json:"activeTokens"`
}

// Grants lists grants, optionally only those of one user.
func (a *AuthorizationServer) Grants(ctx context.Context, owner string) ([]OAuthGrant, error) {
	settings, err := a.Settings(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := a.store.db.QueryContext(ctx, `SELECT g.id,g.client_id,c.name,c.client_type,c.registration,g.user_id,u.login,g.resource,g.scopes,g.created_at,g.expires_at,g.last_used_at,g.revoked,g.revoked_reason,
		(SELECT count(*) FROM management_credentials k WHERE k.grant_id=g.id AND k.revoked=0 AND k.expires_at>unixepoch())
		FROM management_oauth_grants g JOIN management_oauth_clients c ON c.id=g.client_id JOIN management_users u ON u.id=g.user_id
		WHERE (?='' OR g.user_id=?) ORDER BY g.created_at DESC,g.id LIMIT 1000`, owner, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OAuthGrant{}
	for rows.Next() {
		var g OAuthGrant
		var scopes string
		if err := rows.Scan(&g.ID, &g.ClientID, &g.ClientName, &g.ClientType, &g.Registration, &g.UserID, &g.UserLogin, &g.Resource, &scopes, &g.CreatedAt, &g.ExpiresAt, &g.LastUsedAt, &g.Revoked, &g.RevokedReason, &g.ActiveTokens); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(scopes), &g.Scopes); err != nil {
			return nil, err
		}
		if settings.Issuer != "" {
			if r, ok := a.resources.ForURI(settings.Issuer, g.Resource); ok {
				g.ResourceID = r.ID
			}
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// RevokeGrant revokes a grant and every token it issued. Users revoke their own
// grants; revoking another user's grant requires security:write.
func (a *AuthorizationServer) RevokeGrant(ctx context.Context, actor Principal, id string) error {
	tx, err := a.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var owner, client, resource string
	if err := tx.QueryRowContext(ctx, `SELECT user_id,client_id,resource FROM management_oauth_grants WHERE id=?`, id).Scan(&owner, &client, &resource); err != nil {
		return err
	}
	if owner != actor.UserID && !actor.Allows(SecurityWrite) {
		return ErrForbidden
	}
	reason := "user_revoked"
	if owner != actor.UserID {
		reason = "administrator_revoked"
	}
	if err := revokeGrant(ctx, tx, id, reason); err != nil {
		return err
	}
	if err := recordOAuthEvent(ctx, tx, "oauth.grant.revoked", actor.UserID, id, oauthDetails{ClientID: client, Resource: resource, GrantID: id, Reason: reason}); err != nil {
		return err
	}
	return tx.Commit()
}

func revokeGrant(ctx context.Context, tx *sql.Tx, id, reason string) error {
	if _, err := tx.ExecContext(ctx, `UPDATE management_oauth_grants SET revoked=1,revoked_reason=CASE WHEN revoked=0 THEN ? ELSE revoked_reason END WHERE id=?`, reason, id); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE management_credentials SET revoked=1 WHERE grant_id=?`, id)
	return err
}

// revokeExceedingGrants revokes the OAuth grants of owner whose scopes are no
// longer all held by the owner. It runs inside every transaction that changes a
// user's role, custom roles or status, so lost permissions cannot come back
// through an old grant, and its tokens are invalid immediately.
func revokeExceedingGrants(ctx context.Context, tx *sql.Tx, owner string) error {
	var role string
	var disabled bool
	if err := tx.QueryRowContext(ctx, `SELECT role,disabled FROM management_users WHERE id=?`, owner).Scan(&role, &disabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,client_id,resource,scopes FROM management_oauth_grants WHERE user_id=? AND revoked=0`, owner)
	if err != nil {
		return err
	}
	type grant struct{ id, client, resource, scopes string }
	var grants []grant
	for rows.Next() {
		var g grant
		if err := rows.Scan(&g.id, &g.client, &g.resource, &g.scopes); err != nil {
			rows.Close()
			return err
		}
		grants = append(grants, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(grants) == 0 {
		return err
	}
	var effective []Permission
	if !disabled {
		if effective, err = effectivePermissions(ctx, tx, owner, role); err != nil {
			return err
		}
	}
	for _, g := range grants {
		var scopes []Permission
		if err := json.Unmarshal([]byte(g.scopes), &scopes); err != nil {
			return err
		}
		if !disabled && oauth.Subset(scopes, effective) {
			continue
		}
		reason := "permissions_changed"
		if disabled {
			reason = "user_disabled"
		}
		if err := revokeGrant(ctx, tx, g.id, reason); err != nil {
			return err
		}
		if err := recordOAuthEvent(ctx, tx, "oauth.grant.revoked", "", g.id, oauthDetails{ClientID: g.client, Resource: g.resource, GrantID: g.id, Reason: reason}); err != nil {
			return err
		}
	}
	return nil
}

// roleHolders lists the users with an active OAuth grant that hold a custom role.
func roleHolders(ctx context.Context, tx *sql.Tx, role string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT g.user_id FROM management_oauth_grants g JOIN management_user_roles r ON r.user_id=g.user_id WHERE r.role_id=? AND g.revoked=0`, role)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		users = append(users, id)
	}
	return users, rows.Err()
}

// revokeExceedingGrantsForRole applies revokeExceedingGrants to every user
// assigned a custom role.
func revokeExceedingGrantsForRole(ctx context.Context, tx *sql.Tx, role string) error {
	users, err := roleHolders(ctx, tx, role)
	if err != nil {
		return err
	}
	for _, id := range users {
		if err := revokeExceedingGrants(ctx, tx, id); err != nil {
			return err
		}
	}
	return nil
}

// OAuthToken is the administrator view of an OAuth credential. The secret is
// never stored and never shown again after issuance.
type OAuthToken struct {
	ID        string       `json:"id"`
	GrantID   string       `json:"grantId"`
	Kind      string       `json:"kind"`
	Prefix    string       `json:"prefix"`
	Scopes    []Permission `json:"scopes"`
	CreatedAt int64        `json:"createdAt"`
	ExpiresAt int64        `json:"expiresAt"`
	LastSeen  int64        `json:"lastSeen"`
	Revoked   bool         `json:"revoked"`
}

// Tokens lists the credentials of one grant.
func (a *AuthorizationServer) Tokens(ctx context.Context, actor Principal, grant string) ([]OAuthToken, error) {
	var owner string
	if err := a.store.db.QueryRowContext(ctx, `SELECT user_id FROM management_oauth_grants WHERE id=?`, grant).Scan(&owner); err != nil {
		return nil, err
	}
	if owner != actor.UserID && !actor.Allows(SecurityRead) {
		return nil, ErrForbidden
	}
	rows, err := a.store.db.QueryContext(ctx, `SELECT id,grant_id,kind,prefix,scopes,created_at,expires_at,last_seen,revoked FROM management_credentials WHERE grant_id=? ORDER BY created_at DESC,id LIMIT 200`, grant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OAuthToken{}
	for rows.Next() {
		var t OAuthToken
		var scopes string
		if err := rows.Scan(&t.ID, &t.GrantID, &t.Kind, &t.Prefix, &scopes, &t.CreatedAt, &t.ExpiresAt, &t.LastSeen, &t.Revoked); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(scopes), &t.Scopes); err != nil {
			return nil, err
		}
		t.Kind = strings.TrimPrefix(t.Kind, "oauth_")
		out = append(out, t)
	}
	return out, rows.Err()
}

// Authenticate validates an OAuth access token presented to resource. It is the
// single token validator for every resource server. All checks run against the
// database on every call, so revocation, disabling and permission changes take
// effect immediately; there is deliberately no validation cache.
//
// The returned Principal holds the intersection of the user's current
// effective permissions, the token's granted scopes and the resource's scopes.
func (a *AuthorizationServer) Authenticate(ctx context.Context, token string, resource oauth.Resource) (Principal, error) {
	if !oauth.WellFormedSecret(token, oauth.AccessTokenPrefix) {
		return Principal{}, ErrUnauthorized
	}
	settings, err := a.Settings(ctx)
	if err != nil || !settings.resourceEnabled(resource.ID) {
		return Principal{}, ErrUnauthorized
	}
	tx, err := a.store.db.BeginTx(ctx, nil)
	if err != nil {
		return Principal{}, ErrUnauthorized
	}
	defer func() { _ = tx.Rollback() }()
	var (
		p                                    Principal
		role, scopes, grantResource          string
		clientScopes, clientResources        string
		credRevoked, grantRevoked, clientOff bool
		userDisabled, enrolled               bool
		credExpires, grantExpires, lastSeen  int64
		credGeneration, grantGeneration, gen int64
	)
	err = tx.QueryRowContext(ctx, `SELECT c.id,c.user_id,c.scopes,c.revoked,c.expires_at,c.generation,c.last_seen,
		g.id,g.client_id,g.resource,g.revoked,g.expires_at,g.generation,cl.disabled,cl.scopes,cl.resources,
		u.role,u.disabled,u.credential IS NOT NULL,u.generation
		FROM management_credentials c JOIN management_oauth_grants g ON g.id=c.grant_id
		JOIN management_oauth_clients cl ON cl.id=g.client_id JOIN management_users u ON u.id=c.user_id
		WHERE c.verifier=? AND c.kind='oauth_access'`, oauth.Hash(token)).
		Scan(&p.CredentialID, &p.UserID, &scopes, &credRevoked, &credExpires, &credGeneration, &lastSeen,
			&p.GrantID, &p.ClientID, &grantResource, &grantRevoked, &grantExpires, &grantGeneration, &clientOff, &clientScopes, &clientResources,
			&role, &userDisabled, &enrolled, &gen)
	if err != nil {
		return Principal{}, ErrUnauthorized
	}
	now := time.Now().Unix()
	reason := ""
	switch {
	case credRevoked:
		reason = "token_revoked"
	case credExpires <= now:
		reason = "token_expired"
	case grantRevoked:
		reason = "grant_revoked"
	case grantExpires <= now:
		reason = "grant_expired"
	case clientOff:
		reason = "client_disabled"
	case userDisabled || !enrolled:
		reason = "user_disabled"
	case credGeneration != gen || grantGeneration != gen:
		reason = "credential_generation_changed"
	case grantResource != resource.URI(settings.Issuer):
		reason = "audience_mismatch"
	}
	var allowedScopes []Permission
	var allowedResources []string
	if reason == "" && (json.Unmarshal([]byte(clientScopes), &allowedScopes) != nil || json.Unmarshal([]byte(clientResources), &allowedResources) != nil || !slices.Contains(allowedResources, resource.ID)) {
		reason = "client_resource_withdrawn"
	}
	p.CredentialType, p.AuthMethod, p.Resource = credentialOAuth, credentialOAuth, grantResource
	if reason != "" {
		_ = tx.Rollback()
		a.store.audit(withAuditReason(WithPrincipal(ctx, p), reason), "oauth.authentication.failed", p.UserID, p.ClientID)
		return Principal{}, ErrUnauthorized
	}
	effective, err := effectivePermissions(ctx, tx, p.UserID, role)
	if err != nil {
		return Principal{}, ErrUnauthorized
	}
	var granted []Permission
	if json.Unmarshal([]byte(scopes), &granted) != nil {
		return Principal{}, ErrUnauthorized
	}
	if err := tx.Commit(); err != nil {
		return Principal{}, ErrUnauthorized
	}
	p.Permissions = oauth.Intersect(granted, effective, resource.Scopes, allowedScopes)
	if lastSeen < now-60 {
		_, _ = a.store.db.ExecContext(ctx, `UPDATE management_credentials SET last_seen=? WHERE id=? AND last_seen<?`, now, p.CredentialID, now-60)
		_, _ = a.store.db.ExecContext(ctx, `UPDATE management_oauth_grants SET last_used_at=? WHERE id=? AND last_used_at<?`, now, p.GrantID, now-60)
	}
	return p, nil
}

// oauthDetails is the structured, secret-free part of an OAuth audit event.
type oauthDetails struct {
	ClientID     string   `json:"clientId,omitempty"`
	Resource     string   `json:"resource,omitempty"`
	GrantID      string   `json:"grantId,omitempty"`
	CredentialID string   `json:"credentialId,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
	Reason       string   `json:"-"`
	Changes      string   `json:"-"`
}

func withAuditReason(ctx context.Context, reason string) context.Context {
	info, _ := ctx.Value(auditKey{}).(auditInfo)
	info.reason = reason
	return context.WithValue(ctx, auditKey{}, info)
}

// recordOAuthEvent writes an OAuth event through the shared security audit.
// Token values, client secrets, codes and PKCE verifiers never reach it.
func recordOAuthEvent(ctx context.Context, tx *sql.Tx, event, actor, subject string, details oauthDetails) error {
	info, _ := ctx.Value(auditKey{}).(auditInfo)
	if details.Reason != "" {
		info.reason = details.Reason
	}
	encoded, _ := json.Marshal(struct {
		OAuth   oauthDetails `json:"oauth"`
		Changes string       `json:"changes,omitempty"`
	}{details, details.Changes})
	info.changes = string(encoded)
	return recordEvent(context.WithValue(ctx, auditKey{}, info), tx, event, actor, subject)
}

func newGrantID() string { return "grant-" + uuid.New().String() }
