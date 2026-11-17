package auth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"uuid"

	"github.com/Asutorufa/yuhaiin/pkg/management/oauth"
	permission "github.com/Asutorufa/yuhaiin/pkg/management/permission"
)

// authorizationRequest is a validated authorization request waiting for the
// user's decision. Like external login flows, pending requests are bounded,
// short-lived, single-use and lost on restart.
type authorizationRequest struct {
	ID               string
	Client           OAuthClient
	RedirectURI      string
	RedirectRequired bool
	State            string
	Challenge        string
	Resource         oauth.Resource
	ResourceURI      string
	Scopes           []Permission
	Issuer           string
	Expires          time.Time
}

// redirectError is an authorization error that may be returned to the client
// through its validated redirect URI.
type redirectError struct {
	err         *oauth.Error
	redirectURI string
	state       string
	issuer      string
}

func (e *redirectError) Error() string { return e.err.Error() }

func (e *redirectError) location() string {
	return authorizationResponse(e.redirectURI, e.issuer, url.Values{"error": {e.err.Code}, "error_description": {e.err.Description}}, e.state)
}

func authorizationResponse(redirect, issuer string, values url.Values, state string) string {
	u, _ := url.Parse(redirect)
	query := u.Query()
	maps.Copy(query, values)
	if state != "" {
		query.Set("state", state)
	}
	query.Set("iss", issuer) // RFC 9207 mix-up protection
	u.RawQuery = query.Encode()
	return u.String()
}

func singleValues(values url.Values, names ...string) error {
	for _, name := range names {
		if len(values[name]) > 1 {
			return oauth.InvalidRequest("parameter " + name + " is repeated")
		}
	}
	return nil
}

// StartAuthorization validates an authorization request (RFC 6749 4.1.1 with
// OAuth 2.1 and RFC 8707 rules). Errors that occur before the client and its
// redirect URI are verified are returned as plain *oauth.Error and must never
// redirect; later errors are *redirectError.
func (a *AuthorizationServer) StartAuthorization(ctx context.Context, values url.Values) (authorizationRequest, error) {
	settings, err := a.Settings(ctx)
	if err != nil || !settings.active() {
		return authorizationRequest{}, oauth.InvalidRequest("the authorization server is disabled")
	}
	if err := singleValues(values, "response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method", "resource"); err != nil {
		return authorizationRequest{}, err
	}
	client, err := a.client(ctx, a.store.db, values.Get("client_id"))
	if err != nil || client.Disabled {
		return authorizationRequest{}, oauth.InvalidClient("unknown or disabled client")
	}
	redirect, required := values.Get("redirect_uri"), true
	if redirect == "" {
		if len(client.RedirectURIs) != 1 {
			return authorizationRequest{}, oauth.InvalidRequest("redirect_uri is required")
		}
		redirect, required = client.RedirectURIs[0], false
	}
	if !slices.ContainsFunc(client.RedirectURIs, func(registered string) bool { return oauth.MatchRedirectURI(registered, redirect) }) {
		return authorizationRequest{}, oauth.InvalidRequest("redirect_uri is not registered for this client")
	}
	state := values.Get("state")
	if len(state) > 1024 {
		return authorizationRequest{}, oauth.InvalidRequest("state is too long")
	}
	fail := func(err *oauth.Error) (authorizationRequest, error) {
		return authorizationRequest{}, &redirectError{err: err, redirectURI: redirect, state: state, issuer: settings.Issuer}
	}
	if values.Get("response_type") != "code" {
		return fail(&oauth.Error{Code: "unsupported_response_type", Description: "only the authorization code flow is supported"})
	}
	if !slices.Contains(client.GrantTypes, "authorization_code") {
		return fail(oauth.UnauthorizedClient("client may not use the authorization code grant"))
	}
	if values.Get("code_challenge_method") != "S256" || !oauth.ValidCodeChallenge(values.Get("code_challenge")) {
		return fail(oauth.InvalidRequest("PKCE with code_challenge_method S256 is required"))
	}
	var resource oauth.Resource
	resourceURI := values.Get("resource")
	if resourceURI == "" {
		if len(client.Resources) != 1 {
			return fail(oauth.InvalidTarget("the resource parameter is required"))
		}
		resource, _ = a.resources.ByID(client.Resources[0])
	} else {
		var ok bool
		if resource, ok = a.resources.ForURI(settings.Issuer, resourceURI); !ok {
			return fail(oauth.InvalidTarget("unknown resource"))
		}
	}
	if resource.ID == "" || !slices.Contains(client.Resources, resource.ID) || !settings.resourceEnabled(resource.ID) {
		return fail(oauth.InvalidTarget("the client may not access this resource"))
	}
	scopes, err := oauth.ParseScope(values.Get("scope"))
	if err != nil {
		return fail(err.(*oauth.Error))
	}
	offered := oauth.Intersect(resource.Scopes, client.Scopes)
	if len(scopes) == 0 {
		scopes = offered
	}
	if !oauth.Subset(scopes, offered) {
		return fail(oauth.InvalidScope("a requested scope is not available to this client and resource"))
	}
	if resource.Required != "" && !slices.Contains(scopes, resource.Required) {
		scopes = append([]Permission{resource.Required}, scopes...)
	}
	request := authorizationRequest{ID: oauth.NewSecret(""), Client: client, RedirectURI: redirect, RedirectRequired: required, State: state, Challenge: values.Get("code_challenge"), Resource: resource, ResourceURI: resource.URI(settings.Issuer), Scopes: scopes, Issuer: settings.Issuer, Expires: time.Now().Add(requestLifetime)}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.prunePendingLocked()
	if len(a.pending) >= maxPendingRequests {
		return fail(&oauth.Error{Code: "temporarily_unavailable", Description: "too many pending authorization requests"})
	}
	a.pending[request.ID] = request
	return request, nil
}

func (a *AuthorizationServer) prunePendingLocked() {
	for id, request := range a.pending {
		if time.Now().After(request.Expires) {
			delete(a.pending, id)
		}
	}
}

func (a *AuthorizationServer) pendingRequest(id string, consume bool) (authorizationRequest, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.prunePendingLocked()
	request, ok := a.pending[id]
	if !ok || id == "" {
		return authorizationRequest{}, sql.ErrNoRows
	}
	if consume {
		delete(a.pending, id)
	}
	return request, nil
}

// ConsentScope describes one requested scope on the consent page.
type ConsentScope struct {
	ID          Permission `json:"id"`
	Category    string     `json:"category"`
	Description string     `json:"description"`
	Access      string     `json:"access"`
	Required    bool       `json:"required"`
	Available   bool       `json:"available"`
	Previously  bool       `json:"previouslyGranted"`
}

// AuthorizationDetails is what the consent page shows.
type AuthorizationDetails struct {
	ID             string         `json:"id"`
	ClientID       string         `json:"clientId"`
	ClientName     string         `json:"clientName"`
	ClientType     string         `json:"clientType"`
	ClientURI      string         `json:"clientUri"`
	Registration   string         `json:"registration"`
	RedirectOrigin string         `json:"redirectOrigin"`
	RedirectURI    string         `json:"redirectUri"`
	Resource       string         `json:"resource"`
	ResourceID     string         `json:"resourceId"`
	ResourceName   string         `json:"resourceName"`
	Scopes         []ConsentScope `json:"scopes"`
	ExpiresAt      int64          `json:"expiresAt"`
	AccessTokenTTL int64          `json:"accessTokenTtl"`
	GrantTTL       int64          `json:"grantTtl"`
	ExistingGrant  bool           `json:"existingGrant"`
}

func scopeAccess(p Permission) string {
	switch {
	case strings.HasSuffix(string(p), ":read"):
		return "read"
	case p == permission.MCPConnect:
		return "connect"
	default:
		return "write"
	}
}

// Authorization returns the consent details of a pending request for actor.
func (a *AuthorizationServer) Authorization(ctx context.Context, actor Principal, id string) (AuthorizationDetails, error) {
	request, err := a.pendingRequest(id, false)
	if err != nil {
		return AuthorizationDetails{}, err
	}
	settings, err := a.Settings(ctx)
	if err != nil {
		return AuthorizationDetails{}, err
	}
	var role string
	if err := a.store.db.QueryRowContext(ctx, `SELECT role FROM management_users WHERE id=? AND disabled=0`, actor.UserID).Scan(&role); err != nil {
		return AuthorizationDetails{}, ErrForbidden
	}
	effective, err := effectivePermissions(ctx, a.store.db, actor.UserID, role)
	if err != nil {
		return AuthorizationDetails{}, err
	}
	previous := map[Permission]bool{}
	existing := false
	rows, err := a.store.db.QueryContext(ctx, `SELECT scopes FROM management_oauth_grants WHERE user_id=? AND client_id=? AND resource=? AND revoked=0 AND expires_at>unixepoch()`, actor.UserID, request.Client.ID, request.ResourceURI)
	if err != nil {
		return AuthorizationDetails{}, err
	}
	for rows.Next() {
		var encoded string
		var scopes []Permission
		if rows.Scan(&encoded) == nil && json.Unmarshal([]byte(encoded), &scopes) == nil {
			existing = true
			for _, s := range scopes {
				previous[s] = true
			}
		}
	}
	rows.Close()
	out := AuthorizationDetails{ID: request.ID, ClientID: request.Client.ID, ClientName: request.Client.Name, ClientType: request.Client.Type, ClientURI: request.Client.ClientURI, Registration: request.Client.Registration,
		RedirectOrigin: oauth.RedirectOrigin(request.RedirectURI), RedirectURI: request.RedirectURI, Resource: request.ResourceURI, ResourceID: request.Resource.ID, ResourceName: request.Resource.Name,
		ExpiresAt: request.Expires.Unix(), AccessTokenTTL: settings.AccessTokenTTL, GrantTTL: settings.GrantTTL, ExistingGrant: existing}
	for _, scope := range request.Scopes {
		definition, _ := permission.Lookup(scope)
		out.Scopes = append(out.Scopes, ConsentScope{ID: scope, Category: definition.Category, Description: definition.Description, Access: scopeAccess(scope), Required: scope == request.Resource.Required, Available: slices.Contains(effective, scope), Previously: previous[scope]})
	}
	return out, nil
}

// Decide approves or denies a pending request and returns the client redirect.
// Approval issues a single-use authorization code bound to the client, the
// exact redirect URI, the PKCE challenge, the resource and the scopes the user
// selected, which never exceed the user's current permissions.
func (a *AuthorizationServer) Decide(ctx context.Context, actor Principal, id string, approve bool, selected []Permission) (string, error) {
	request, err := a.pendingRequest(id, true)
	if err != nil {
		return "", err
	}
	details := oauthDetails{ClientID: request.Client.ID, Resource: request.ResourceURI}
	if !approve {
		if err := a.audit(ctx, "oauth.authorization.denied", actor.UserID, request.Client.ID, details); err != nil {
			return "", err
		}
		return authorizationResponse(request.RedirectURI, request.Issuer, url.Values{"error": {"access_denied"}, "error_description": {"the user denied the request"}}, request.State), nil
	}
	tx, err := a.store.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	var role string
	var generation int64
	if err := tx.QueryRowContext(ctx, `SELECT role,generation FROM management_users WHERE id=? AND disabled=0 AND credential IS NOT NULL`, actor.UserID).Scan(&role, &generation); err != nil {
		return "", ErrForbidden
	}
	effective, err := effectivePermissions(ctx, tx, actor.UserID, role)
	if err != nil {
		return "", err
	}
	if !oauth.Subset(selected, request.Scopes) {
		return "", ErrInvalid
	}
	granted := oauth.Intersect(request.Scopes, selected, effective)
	if len(granted) == 0 || request.Resource.Required != "" && !slices.Contains(granted, request.Resource.Required) {
		return "", ErrForbidden
	}
	code := oauth.NewSecret(oauth.AuthorizationCodePrefix)
	scopes, _ := json.Marshal(granted)
	// Expired codes are removed whenever a new one is issued.
	if _, err := tx.ExecContext(ctx, `DELETE FROM management_oauth_codes WHERE expires_at<=?`, time.Now().Unix()); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO management_oauth_codes(verifier,client_id,user_id,redirect_uri,redirect_uri_required,code_challenge,resource,scopes,generation,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		oauth.Hash(code), request.Client.ID, actor.UserID, request.RedirectURI, request.RedirectRequired, request.Challenge, request.ResourceURI, string(scopes), generation, time.Now().Add(codeLifetime).Unix()); err != nil {
		return "", err
	}
	details.Scopes = scopeStrings(granted)
	if err := recordOAuthEvent(ctx, tx, "oauth.authorization.approved", actor.UserID, request.Client.ID, details); err != nil {
		return "", err
	}
	if err := recordOAuthEvent(ctx, tx, "oauth.code.issued", actor.UserID, request.Client.ID, details); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return authorizationResponse(request.RedirectURI, request.Issuer, url.Values{"code": {code}}, request.State), nil
}

func scopeStrings(scopes []Permission) []string {
	out := make([]string, len(scopes))
	for i, s := range scopes {
		out[i] = string(s)
	}
	return out
}

func (a *AuthorizationServer) audit(ctx context.Context, event, actor, subject string, details oauthDetails) error {
	tx, err := a.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := recordOAuthEvent(ctx, tx, event, actor, subject, details); err != nil {
		return err
	}
	return tx.Commit()
}

// TokenResponse is the RFC 6749 section 5.1 response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
}

// authenticateClient implements client authentication at the token and
// revocation endpoints. Exactly one method is accepted per request and it must
// be the method registered for the client.
func (a *AuthorizationServer) authenticateClient(ctx context.Context, r *http.Request, form url.Values) (OAuthClient, error) {
	id, secret, method := form.Get("client_id"), "", "none"
	if user, clientSecret, ok := basicAuth(r); ok {
		if form.Has("client_secret") || id != "" && id != user {
			return OAuthClient{}, oauth.InvalidRequest("use exactly one client authentication method")
		}
		id, secret, method = user, clientSecret, "client_secret_basic"
	} else if r.Header.Get("Authorization") != "" {
		return OAuthClient{}, oauth.InvalidClient("unsupported client authentication")
	} else if form.Has("client_secret") {
		secret, method = form.Get("client_secret"), "client_secret_post"
	}
	if id == "" {
		return OAuthClient{}, oauth.InvalidClient("client authentication is required")
	}
	var hash []byte
	client, err := a.client(ctx, a.store.db, id)
	if err == nil {
		err = a.store.db.QueryRowContext(ctx, `SELECT secret_hash FROM management_oauth_clients WHERE id=?`, id).Scan(&hash)
	}
	if err != nil || client.Disabled || client.TokenEndpointAuthMethod != method {
		return OAuthClient{}, oauth.InvalidClient("client authentication failed")
	}
	if method != "none" && (!oauth.WellFormedSecret(secret, oauth.ClientSecretPrefix) || subtle.ConstantTimeCompare(oauth.Hash(secret), hash) != 1) {
		return OAuthClient{}, oauth.InvalidClient("client authentication failed")
	}
	return client, nil
}

// basicAuth decodes RFC 6749 section 2.3.1 credentials, which are
// form-urlencoded before base64 encoding.
func basicAuth(r *http.Request) (string, string, bool) {
	scheme, encoded, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", false
	}
	user, clientSecret, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return "", "", false
	}
	user, err1 := url.QueryUnescape(user)
	clientSecret, err2 := url.QueryUnescape(clientSecret)
	return user, clientSecret, ok && err1 == nil && err2 == nil
}

// Token implements the token endpoint for every supported grant type.
func (a *AuthorizationServer) Token(ctx context.Context, r *http.Request, form url.Values) (TokenResponse, error) {
	settings, err := a.Settings(ctx)
	if err != nil || !settings.active() {
		return TokenResponse{}, oauth.InvalidRequest("the authorization server is disabled")
	}
	if err := singleValues(form, "grant_type", "code", "redirect_uri", "code_verifier", "refresh_token", "scope", "resource", "client_id", "client_secret"); err != nil {
		return TokenResponse{}, err
	}
	client, err := a.authenticateClient(ctx, r, form)
	if err != nil {
		_ = a.audit(withAuditReason(ctx, "client_authentication_failed"), "oauth.authentication.failed", "", form.Get("client_id"), oauthDetails{ClientID: form.Get("client_id")})
		return TokenResponse{}, err
	}
	grant, ok := tokenGrants[form.Get("grant_type")]
	if !ok {
		return TokenResponse{}, oauth.UnsupportedGrantType("supported grant types are authorization_code and refresh_token")
	}
	if !slices.Contains(client.GrantTypes, form.Get("grant_type")) {
		return TokenResponse{}, oauth.UnauthorizedClient("the client may not use this grant type")
	}
	return grant(a, ctx, settings, client, form)
}

// tokenGrants maps grant_type values to their handlers. A new grant type, such
// as client_credentials for a dedicated service identity, is added here and
// advertised in oauth.GrantTypes; nothing else in the server changes.
var tokenGrants = map[string]func(*AuthorizationServer, context.Context, OAuthServerSettings, OAuthClient, url.Values) (TokenResponse, error){
	"authorization_code": (*AuthorizationServer).exchangeCode,
	"refresh_token":      (*AuthorizationServer).refresh,
}

func (a *AuthorizationServer) exchangeCode(ctx context.Context, settings OAuthServerSettings, client OAuthClient, form url.Values) (TokenResponse, error) {
	code := form.Get("code")
	if !oauth.WellFormedSecret(code, oauth.AuthorizationCodePrefix) {
		return TokenResponse{}, oauth.InvalidGrant("invalid authorization code")
	}
	tx, err := a.store.db.BeginTx(ctx, nil)
	if err != nil {
		return TokenResponse{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var (
		codeClient, owner, redirect, challenge, resourceURI, encoded string
		required                                                     bool
		generation, expires, consumed                                int64
		previousGrant                                                sql.NullString
	)
	verifier := oauth.Hash(code)
	err = tx.QueryRowContext(ctx, `SELECT client_id,user_id,redirect_uri,redirect_uri_required,code_challenge,resource,scopes,generation,expires_at,consumed_at,grant_id FROM management_oauth_codes WHERE verifier=?`, verifier).
		Scan(&codeClient, &owner, &redirect, &required, &challenge, &resourceURI, &encoded, &generation, &expires, &consumed, &previousGrant)
	if err != nil {
		return TokenResponse{}, oauth.InvalidGrant("invalid authorization code")
	}
	details := oauthDetails{ClientID: codeClient, Resource: resourceURI}
	if consumed != 0 {
		// RFC 6749 section 10.5: a replayed code revokes what it issued.
		if previousGrant.Valid {
			details.GrantID = previousGrant.String
			if err := revokeGrant(ctx, tx, previousGrant.String, "authorization_code_reuse"); err != nil {
				return TokenResponse{}, err
			}
			if err := recordOAuthEvent(ctx, tx, "oauth.grant.revoked", "", previousGrant.String, oauthDetails{ClientID: codeClient, Resource: resourceURI, GrantID: previousGrant.String, Reason: "authorization_code_reuse"}); err != nil {
				return TokenResponse{}, err
			}
		}
		details.Reason = "authorization_code_reuse"
		if err := recordOAuthEvent(ctx, tx, "oauth.authentication.failed", owner, codeClient, details); err != nil {
			return TokenResponse{}, err
		}
		if err := tx.Commit(); err != nil {
			return TokenResponse{}, err
		}
		return TokenResponse{}, oauth.InvalidGrant("authorization code was already used")
	}
	now := time.Now().Unix()
	switch {
	case codeClient != client.ID:
		return TokenResponse{}, oauth.InvalidGrant("authorization code was issued to another client")
	case expires <= now:
		return TokenResponse{}, oauth.InvalidGrant("authorization code expired")
	case form.Has("redirect_uri") && form.Get("redirect_uri") != redirect, required && form.Get("redirect_uri") != redirect:
		return TokenResponse{}, oauth.InvalidGrant("redirect_uri does not match the authorization request")
	case !oauth.VerifyPKCE(form.Get("code_verifier"), challenge):
		return TokenResponse{}, oauth.InvalidGrant("PKCE verification failed")
	}
	if form.Has("resource") {
		if canonical, err := oauth.CanonicalResource(form.Get("resource")); err != nil || canonical != resourceURI {
			return TokenResponse{}, oauth.InvalidTarget("resource does not match the authorization request")
		}
	}
	resource, ok := a.resources.ForURI(settings.Issuer, resourceURI)
	if !ok || !settings.resourceEnabled(resource.ID) || !slices.Contains(client.Resources, resource.ID) {
		return TokenResponse{}, oauth.InvalidTarget("the resource is no longer available")
	}
	// The conditional update is the single-use guarantee: of two concurrent
	// exchanges of one code, exactly one consumes it.
	result, err := tx.ExecContext(ctx, `UPDATE management_oauth_codes SET consumed_at=? WHERE verifier=? AND consumed_at=0`, now, verifier)
	if err != nil {
		return TokenResponse{}, err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return TokenResponse{}, oauth.InvalidGrant("authorization code was already used")
	}
	var role string
	var current int64
	if err := tx.QueryRowContext(ctx, `SELECT role,generation FROM management_users WHERE id=? AND disabled=0 AND credential IS NOT NULL`, owner).Scan(&role, &current); err != nil || current != generation {
		return TokenResponse{}, oauth.InvalidGrant("the authorizing user is no longer active")
	}
	effective, err := effectivePermissions(ctx, tx, owner, role)
	if err != nil {
		return TokenResponse{}, err
	}
	var approved []Permission
	if err := json.Unmarshal([]byte(encoded), &approved); err != nil {
		return TokenResponse{}, err
	}
	scopes := oauth.Intersect(approved, effective, resource.Scopes, client.Scopes)
	if len(scopes) == 0 {
		return TokenResponse{}, oauth.InvalidGrant("the user no longer holds the approved permissions")
	}
	var grants int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM management_oauth_grants WHERE user_id=? AND revoked=0 AND expires_at>?`, owner, now).Scan(&grants); err != nil {
		return TokenResponse{}, err
	}
	if grants >= maxGrantsPerUser {
		return TokenResponse{}, oauth.InvalidGrant("too many active authorizations for this user")
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM management_oauth_grants WHERE user_id=? AND (revoked=1 OR expires_at<=?) AND created_at<?`, owner, now, now-30*86400); err != nil {
		return TokenResponse{}, err
	}
	grant := newGrantID()
	encodedScopes, _ := json.Marshal(scopes)
	if _, err := tx.ExecContext(ctx, `INSERT INTO management_oauth_grants(id,client_id,user_id,resource,scopes,generation,created_at,expires_at,last_used_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		grant, client.ID, owner, resourceURI, string(encodedScopes), generation, now, now+settings.GrantTTL, now); err != nil {
		return TokenResponse{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE management_oauth_codes SET grant_id=? WHERE verifier=?`, grant, verifier); err != nil {
		return TokenResponse{}, err
	}
	details.GrantID, details.Scopes = grant, scopeStrings(scopes)
	if err := recordOAuthEvent(ctx, tx, "oauth.code.consumed", owner, client.ID, details); err != nil {
		return TokenResponse{}, err
	}
	response, err := issueOAuthTokens(ctx, tx, settings, owner, grant, generation, scopes, now+settings.GrantTTL, now)
	if err != nil {
		return TokenResponse{}, err
	}
	if err := recordOAuthEvent(ctx, tx, "oauth.token.issued", owner, client.ID, details); err != nil {
		return TokenResponse{}, err
	}
	return response, tx.Commit()
}

func issueOAuthTokens(ctx context.Context, tx *sql.Tx, settings OAuthServerSettings, owner, grant string, generation int64, scopes []Permission, grantExpiry, now int64) (TokenResponse, error) {
	access := oauth.NewSecret(oauth.AccessTokenPrefix)
	refresh := oauth.NewSecret(oauth.RefreshTokenPrefix)
	encoded, _ := json.Marshal(scopes)
	insert := func(secret, kind string, expiry int64) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO management_credentials(id,user_id,kind,verifier,prefix,scopes,generation,created_at,expires_at,auth_method,grant_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			uuid.New().String(), owner, kind, oauth.Hash(secret), secret[:12], string(encoded), generation, now, expiry, credentialOAuth, grant)
		return err
	}
	if err := insert(access, kindOAuthAccess, now+settings.AccessTokenTTL); err != nil {
		return TokenResponse{}, err
	}
	if err := insert(refresh, kindOAuthRefresh, min(now+settings.RefreshTokenTTL, grantExpiry)); err != nil {
		return TokenResponse{}, err
	}
	return TokenResponse{AccessToken: access, TokenType: "Bearer", ExpiresIn: settings.AccessTokenTTL, RefreshToken: refresh, Scope: oauth.FormatScope(scopes)}, nil
}

func (a *AuthorizationServer) refresh(ctx context.Context, settings OAuthServerSettings, client OAuthClient, form url.Values) (TokenResponse, error) {
	token := form.Get("refresh_token")
	if !oauth.WellFormedSecret(token, oauth.RefreshTokenPrefix) {
		return TokenResponse{}, oauth.InvalidGrant("invalid refresh token")
	}
	tx, err := a.store.db.BeginTx(ctx, nil)
	if err != nil {
		return TokenResponse{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var (
		id, owner, grant, grantClient, resourceURI, grantScopes, role string
		revoked, grantRevoked, userDisabled, enrolled                 bool
		expires, grantExpires, generation, grantGeneration, current   int64
	)
	err = tx.QueryRowContext(ctx, `SELECT c.id,c.user_id,c.revoked,c.expires_at,c.generation,g.id,g.client_id,g.resource,g.scopes,g.revoked,g.expires_at,g.generation,u.role,u.disabled,u.credential IS NOT NULL,u.generation
		FROM management_credentials c JOIN management_oauth_grants g ON g.id=c.grant_id JOIN management_users u ON u.id=c.user_id
		WHERE c.verifier=? AND c.kind='oauth_refresh'`, oauth.Hash(token)).
		Scan(&id, &owner, &revoked, &expires, &generation, &grant, &grantClient, &resourceURI, &grantScopes, &grantRevoked, &grantExpires, &grantGeneration, &role, &userDisabled, &enrolled, &current)
	if err != nil {
		return TokenResponse{}, oauth.InvalidGrant("invalid refresh token")
	}
	details := oauthDetails{ClientID: grantClient, Resource: resourceURI, GrantID: grant, CredentialID: id}
	if grantClient != client.ID {
		return TokenResponse{}, oauth.InvalidGrant("refresh token was issued to another client")
	}
	if revoked && !grantRevoked {
		// A rotated refresh token was presented again: the token family may be
		// stolen. Revoke the whole grant, including the newest tokens.
		if err := revokeGrant(ctx, tx, grant, "refresh_token_reuse"); err != nil {
			return TokenResponse{}, err
		}
		details.Reason = "refresh_token_reuse"
		if err := recordOAuthEvent(ctx, tx, "oauth.refresh.reuse_detected", owner, client.ID, details); err != nil {
			return TokenResponse{}, err
		}
		if err := recordOAuthEvent(ctx, tx, "oauth.grant.revoked", "", grant, details); err != nil {
			return TokenResponse{}, err
		}
		if err := tx.Commit(); err != nil {
			return TokenResponse{}, err
		}
		return TokenResponse{}, oauth.InvalidGrant("refresh token was already used")
	}
	now := time.Now().Unix()
	if revoked || grantRevoked || expires <= now || grantExpires <= now || userDisabled || !enrolled || generation != current || grantGeneration != current {
		return TokenResponse{}, oauth.InvalidGrant("refresh token is no longer valid")
	}
	resource, ok := a.resources.ForURI(settings.Issuer, resourceURI)
	if !ok || !settings.resourceEnabled(resource.ID) || !slices.Contains(client.Resources, resource.ID) {
		return TokenResponse{}, oauth.InvalidTarget("the resource is no longer available")
	}
	if form.Has("resource") {
		if canonical, err := oauth.CanonicalResource(form.Get("resource")); err != nil || canonical != resourceURI {
			return TokenResponse{}, oauth.InvalidTarget("a refresh token cannot change its resource")
		}
	}
	var scopes []Permission
	if err := json.Unmarshal([]byte(grantScopes), &scopes); err != nil {
		return TokenResponse{}, err
	}
	if form.Has("scope") {
		requested, err := oauth.ParseScope(form.Get("scope"))
		if err != nil {
			return TokenResponse{}, err
		}
		if !oauth.Subset(requested, scopes) {
			return TokenResponse{}, oauth.InvalidScope("a refresh cannot add scopes")
		}
		scopes = requested
	}
	// Permissions are evaluated again: a refresh never restores access the
	// user has lost since consent.
	effective, err := effectivePermissions(ctx, tx, owner, role)
	if err != nil {
		return TokenResponse{}, err
	}
	scopes = oauth.Intersect(scopes, effective, resource.Scopes, client.Scopes)
	if len(scopes) == 0 {
		return TokenResponse{}, oauth.InvalidGrant("the user no longer holds the granted permissions")
	}
	result, err := tx.ExecContext(ctx, `UPDATE management_credentials SET revoked=1 WHERE id=? AND revoked=0`, id)
	if err != nil {
		return TokenResponse{}, err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return TokenResponse{}, oauth.InvalidGrant("refresh token was already used")
	}
	// Bound the token family: expired tokens go, and only the most recent
	// rotated refresh tokens are kept for reuse detection.
	if _, err := tx.ExecContext(ctx, `DELETE FROM management_credentials WHERE grant_id=? AND expires_at<=?`, grant, now); err != nil {
		return TokenResponse{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM management_credentials WHERE grant_id=? AND kind='oauth_refresh' AND revoked=1 AND id NOT IN (SELECT id FROM management_credentials WHERE grant_id=? AND kind='oauth_refresh' AND revoked=1 ORDER BY created_at DESC LIMIT ?)`, grant, grant, retainedRotations); err != nil {
		return TokenResponse{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE management_oauth_grants SET last_used_at=? WHERE id=?`, now, grant); err != nil {
		return TokenResponse{}, err
	}
	response, err := issueOAuthTokens(ctx, tx, settings, owner, grant, current, scopes, grantExpires, now)
	if err != nil {
		return TokenResponse{}, err
	}
	details.Scopes = scopeStrings(scopes)
	if err := recordOAuthEvent(ctx, tx, "oauth.token.refreshed", owner, client.ID, details); err != nil {
		return TokenResponse{}, err
	}
	return response, tx.Commit()
}

// Revoke implements RFC 7009. Revoking a refresh token revokes its grant and
// therefore every access token of that grant; revoking an access token
// revokes only that token. Unknown tokens and tokens of other clients are
// ignored, as the RFC requires.
func (a *AuthorizationServer) Revoke(ctx context.Context, r *http.Request, form url.Values) error {
	settings, err := a.Settings(ctx)
	if err != nil || !settings.active() {
		return oauth.InvalidRequest("the authorization server is disabled")
	}
	if err := singleValues(form, "token", "token_type_hint", "client_id", "client_secret"); err != nil {
		return err
	}
	client, err := a.authenticateClient(ctx, r, form)
	if err != nil {
		return err
	}
	token := form.Get("token")
	if token == "" {
		return oauth.InvalidRequest("token is required")
	}
	kind := ""
	switch {
	case oauth.WellFormedSecret(token, oauth.AccessTokenPrefix):
		kind = kindOAuthAccess
	case oauth.WellFormedSecret(token, oauth.RefreshTokenPrefix):
		kind = kindOAuthRefresh
	default:
		return nil
	}
	tx, err := a.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var id, owner, grant, resource string
	err = tx.QueryRowContext(ctx, `SELECT c.id,c.user_id,g.id,g.resource FROM management_credentials c JOIN management_oauth_grants g ON g.id=c.grant_id WHERE c.verifier=? AND c.kind=? AND g.client_id=?`, oauth.Hash(token), kind, client.ID).Scan(&id, &owner, &grant, &resource)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	details := oauthDetails{ClientID: client.ID, Resource: resource, GrantID: grant, CredentialID: id}
	if kind == kindOAuthRefresh {
		if err := revokeGrant(ctx, tx, grant, "client_revoked"); err != nil {
			return err
		}
		if err := recordOAuthEvent(ctx, tx, "oauth.grant.revoked", owner, grant, oauthDetails{ClientID: client.ID, Resource: resource, GrantID: grant, Reason: "client_revoked"}); err != nil {
			return err
		}
	} else if _, err := tx.ExecContext(ctx, `UPDATE management_credentials SET revoked=1 WHERE id=?`, id); err != nil {
		return err
	}
	if err := recordOAuthEvent(ctx, tx, "oauth.token.revoked", owner, client.ID, details); err != nil {
		return err
	}
	return tx.Commit()
}

// ClientRegistration is the RFC 7591 client metadata subset Yuhaiin accepts.
type ClientRegistration struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
}

// ClientRegistrationResponse is the RFC 7591 section 3.2.1 response.
type ClientRegistrationResponse struct {
	ClientRegistration
	ClientID              string `json:"client_id"`
	ClientSecret          string `json:"client_secret,omitempty"`
	ClientIDIssuedAt      int64  `json:"client_id_issued_at"`
	ClientSecretExpiresAt *int64 `json:"client_secret_expires_at,omitempty"`
}

// Register implements open dynamic client registration (RFC 7591), which MCP
// clients use to obtain a client ID. Registered clients still need the
// explicit consent of a signed-in user before they receive any token, and
// unused registrations expire.
func (a *AuthorizationServer) Register(ctx context.Context, request ClientRegistration) (ClientRegistrationResponse, error) {
	settings, err := a.Settings(ctx)
	if err != nil || !settings.active() || !settings.DynamicRegistration {
		return ClientRegistrationResponse{}, &oauth.Error{Status: http.StatusForbidden, Code: "access_denied", Description: "dynamic client registration is disabled"}
	}
	for _, grant := range request.GrantTypes {
		if !slices.Contains(oauth.GrantTypes, grant) {
			return ClientRegistrationResponse{}, oauth.InvalidClientMetadata("unsupported grant type " + grant)
		}
	}
	for _, response := range request.ResponseTypes {
		if response != "code" {
			return ClientRegistrationResponse{}, oauth.InvalidClientMetadata("only the code response type is supported")
		}
	}
	scopes, err := oauth.ParseScope(request.Scope)
	if err != nil {
		return ClientRegistrationResponse{}, oauth.InvalidClientMetadata("unknown scope")
	}
	if request.ClientName == "" {
		request.ClientName = "Unnamed application"
	}
	clientType := "public"
	if request.TokenEndpointAuthMethod == "" {
		request.TokenEndpointAuthMethod = "client_secret_basic"
		if len(request.RedirectURIs) > 0 {
			request.TokenEndpointAuthMethod = "none"
		}
	}
	if request.TokenEndpointAuthMethod != "none" {
		clientType = "confidential"
	}
	now := time.Now().Unix()
	issued, err := a.registerClient(ctx, "", OAuthClient{ID: oauth.NewClientID(), Name: request.ClientName, Type: clientType, Registration: "dynamic", RedirectURIs: request.RedirectURIs, TokenEndpointAuthMethod: request.TokenEndpointAuthMethod, Scopes: scopes, ClientURI: request.ClientURI, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		if oauthErr, ok := errors.AsType[*oauth.Error](err); ok {
			if oauthErr.Code == "invalid_scope" {
				return ClientRegistrationResponse{}, oauth.InvalidClientMetadata(oauthErr.Description)
			}
			return ClientRegistrationResponse{}, err
		}
		if errors.Is(err, ErrConflict) {
			return ClientRegistrationResponse{}, &oauth.Error{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable", Description: "too many registered clients"}
		}
		return ClientRegistrationResponse{}, err
	}
	out := ClientRegistrationResponse{ClientID: issued.ID, ClientSecret: issued.Secret, ClientIDIssuedAt: now}
	out.RedirectURIs, out.ClientName, out.ClientURI, out.TokenEndpointAuthMethod = issued.RedirectURIs, issued.Name, issued.ClientURI, issued.TokenEndpointAuthMethod
	out.GrantTypes, out.ResponseTypes, out.Scope = issued.GrantTypes, []string{"code"}, oauth.FormatScope(issued.Scopes)
	if issued.Secret != "" {
		never := int64(0)
		out.ClientSecretExpiresAt = &never
	}
	return out, nil
}

// rateLimiter bounds unauthenticated OAuth endpoints per peer and globally.
type rateLimiter struct {
	mu       sync.Mutex
	perPeer  int
	global   int
	start    time.Time
	total    int
	counters map[string]int
}

func newRateLimiter(perPeer, global int) *rateLimiter {
	return &rateLimiter{perPeer: perPeer, global: global, counters: make(map[string]int)}
}

func (l *rateLimiter) allow(peer string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now := time.Now(); now.Sub(l.start) >= time.Minute {
		l.start, l.total, l.counters = now, 0, make(map[string]int)
	}
	if l.total >= l.global || l.counters[peer] >= l.perPeer {
		return false
	}
	l.total++
	l.counters[peer]++
	return true
}
