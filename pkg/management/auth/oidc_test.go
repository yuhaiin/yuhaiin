package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	jose "github.com/go-jose/go-jose/v4"
)

type testOIDC struct {
	public                  bool
	discoveries             int
	t                       *testing.T
	server                  *httptest.Server
	mu                      sync.Mutex
	key                     ed25519.PrivateKey
	keyID, nonce, challenge string
	mutate                  func(map[string]any)
	jwks                    int
}

func newTestOIDC(t *testing.T) *testOIDC {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	provider := &testOIDC{t: t, key: key, keyID: "first"}
	provider.server = httptest.NewTLSServer(http.HandlerFunc(provider.serve))
	t.Cleanup(provider.server.Close)
	return provider
}
func (p *testOIDC) serve(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	var response any
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		p.discoveries++
		response = map[string]any{"issuer": p.server.URL, "authorization_endpoint": p.server.URL + "/authorize", "token_endpoint": p.server.URL + "/token", "jwks_uri": p.server.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"EdDSA"}, "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}}
	case "/jwks":
		p.jwks++
		response = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: p.key.Public(), KeyID: p.keyID, Algorithm: "EdDSA", Use: "sig"}}}
	case "/token":
		if err := r.ParseForm(); err != nil {
			p.t.Error(err)
			w.WriteHeader(400)
			return
		}
		client, proof, ok := r.BasicAuth()
		if !ok {
			client, proof = r.Form.Get("client_id"), r.Form.Get("client_secret")
		}
		digest := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		expectedProof := "private-client-secret"
		if p.public {
			expectedProof = ""
		}
		if client != "enterprise-client" || proof != expectedProof || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "authorization-code" || base64.RawURLEncoding.EncodeToString(digest[:]) != p.challenge {
			p.t.Error("invalid client authentication or PKCE exchange")
			w.WriteHeader(400)
			return
		}
		now := time.Now().Unix()
		claims := map[string]any{"iss": p.server.URL, "sub": "stable-subject", "aud": "enterprise-client", "nonce": p.nonce, "iat": now, "exp": now + 300, "name": "Display Name", "email": "admin@example.test", "email_verified": true, "roles": []string{"admin"}}
		if p.mutate != nil {
			p.mutate(claims)
		}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: p.key}, (&jose.SignerOptions{}).WithHeader("kid", p.keyID).WithType("JWT"))
		if err != nil {
			p.t.Error(err)
			return
		}
		encoded, err := json.Marshal(claims)
		if err != nil {
			p.t.Error(err)
			return
		}
		signed, err := signer.Sign(encoded)
		if err != nil {
			p.t.Error(err)
			return
		}
		jwt, err := signed.CompactSerialize()
		if err != nil {
			p.t.Error(err)
			return
		}
		response = map[string]any{"access_token": "private-provider-access-token", "id_token": jwt, "token_type": "Bearer", "expires_in": 300}
	default:
		w.WriteHeader(404)
		return
	}
	data, err := json.Marshal(response)
	if err != nil {
		p.t.Error(err)
		return
	}
	_, _ = w.Write(data)
}
func (p *testOIDC) configure(t *testing.T, s *Store, actor User) OAuthProvider {
	t.Helper()
	id := "oidc-" + uuid.New().String()
	config := OAuthProvider{Provider: id, Name: "Enterprise SSO", Issuer: p.server.URL, ClientID: "enterprise-client", ClientSecret: "private-client-secret", RedirectURL: "https://controller.example/api/v2/auth/oauth/" + id + "/callback"}
	if err := s.SaveOAuthProvider(t.Context(), actor.ID, config); err != nil {
		t.Fatal(err)
	}
	actual, err := s.oauthProvider(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	return actual
}
func (p *testOIDC) start(t *testing.T, o *OAuthService, config OAuthProvider, actor Principal) (OAuthStart, oauthFlow) {
	t.Helper()
	start, err := o.startContext(t.Context(), config, "https://ui.example", actor)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := url.Parse(start.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	if authorization.Scheme != "https" || authorization.Query().Get("nonce") == "" || authorization.Query().Get("code_challenge_method") != "S256" || authorization.Query().Get("response_type") != "code" || authorization.Query().Get("state") != start.State {
		t.Fatal("missing OIDC nonce, state or PKCE")
	}
	p.mu.Lock()
	p.nonce = authorization.Query().Get("nonce")
	p.challenge = authorization.Query().Get("code_challenge")
	p.mu.Unlock()
	flow, err := o.claim(config.Provider, start.State)
	if err != nil {
		t.Fatal(err)
	}
	return start, flow
}

func TestOIDCExplicitBindingAndLocalPermissions(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	user := testUser(t, s, "reader", ReadOnly)
	provider := newTestOIDC(t)
	config := provider.configure(t, s, admin)
	o := newOAuthService()
	o.client = provider.server.Client()
	// An email/role claim cannot automatically link or create a local account.
	_, flow := provider.start(t, o, config, Principal{})
	identity, err := o.identity(t.Context(), flow, "authorization-code")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.completeOAuth(t.Context(), flow, identity, Principal{}); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("unbound identity signed in using email or role claims", err)
	}
	local := testSession(t, s, user)
	actor, err := s.Authenticate(t.Context(), local.Secret, "session")
	if err != nil {
		t.Fatal(err)
	}
	start, flow := provider.start(t, o, config, actor)
	completion, err := o.callback(t.Context(), start.State, flow, "authorization-code")
	if err != nil {
		t.Fatal(err)
	}
	finished, err := o.finish(config.Provider, start.State, start.Secret, completion, "https://ui.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.completeOAuth(t.Context(), finished, finished.Identity, actor); err != nil {
		t.Fatal(err)
	}
	if _, err := o.finish(config.Provider, start.State, start.Secret, completion, "https://ui.example"); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("completion proof replayed", err)
	}
	_, flow = provider.start(t, o, config, Principal{})
	identity, err = o.identity(t.Context(), flow, "authorization-code")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := s.completeOAuth(context.WithValue(t.Context(), sessionInfoKey{}, sessionInfo{Method: config.Provider}), flow, identity, Principal{})
	if err != nil || issued == nil {
		t.Fatal("explicitly linked sign-in failed", err)
	}
	principal, err := s.Authenticate(t.Context(), issued.Secret, "session")
	if err != nil || principal.UserID != user.ID || principal.Allows(UsersManage) {
		t.Fatal("OIDC claims changed local permissions", err)
	}
	if err := s.UnlinkOAuth(t.Context(), actor, config.Provider); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(t.Context(), issued.Secret, "session"); err == nil {
		t.Fatal("unlink retained an OIDC session")
	}
	if _, err := s.Authenticate(t.Context(), local.Secret, "session"); err != nil {
		t.Fatal("OIDC unlink revoked password recovery session", err)
	}
}

func TestOIDCTokenValidationRejectsMixupAndReplayInputs(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	provider := newTestOIDC(t)
	config := provider.configure(t, s, admin)
	o := newOAuthService()
	o.client = provider.server.Client()
	tests := map[string]func(map[string]any){
		"nonce":                      func(c map[string]any) { c["nonce"] = "another-flow" },
		"issuer":                     func(c map[string]any) { c["iss"] = "https://another-issuer.test" },
		"audience":                   func(c map[string]any) { c["aud"] = "another-client" },
		"expired":                    func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() },
		"future-issued":              func(c map[string]any) { c["iat"] = time.Now().Add(5 * time.Minute).Unix() },
		"old-issued":                 func(c map[string]any) { c["iat"] = time.Now().Add(-10 * time.Minute).Unix() },
		"missing-issued":             func(c map[string]any) { delete(c, "iat") },
		"future-nbf":                 func(c map[string]any) { c["nbf"] = time.Now().Add(2 * time.Minute).Unix() },
		"azp":                        func(c map[string]any) { c["azp"] = "another-client" },
		"multi-audience-without-azp": func(c map[string]any) { c["aud"] = []string{"enterprise-client", "other"} },
		"at-hash":                    func(c map[string]any) { c["at_hash"] = "invalid-hash" },
		"missing-subject":            func(c map[string]any) { delete(c, "sub") },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			_, flow := provider.start(t, o, config, Principal{})
			provider.mu.Lock()
			provider.mutate = mutate
			provider.mu.Unlock()
			if _, err := o.identity(t.Context(), flow, "authorization-code"); !errors.Is(err, ErrUnauthorized) {
				t.Fatal("invalid ID token accepted", err)
			}
		})
	}
	provider.mu.Lock()
	provider.mutate = func(c map[string]any) {
		c["aud"] = []string{"enterprise-client", "other"}
		c["azp"] = "enterprise-client"
	}
	provider.mu.Unlock()
	_, flow := provider.start(t, o, config, Principal{})
	if _, err := o.identity(t.Context(), flow, "authorization-code"); err != nil {
		t.Fatal("valid authorized party rejected", err)
	}
}

func TestOIDCConfigurationRevisionRevokesSessionsAndPendingCompletions(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	provider := newTestOIDC(t)
	config := provider.configure(t, s, admin)
	o := newOAuthService()
	o.client = provider.server.Client()
	_, flow := provider.start(t, o, config, Principal{})
	identity, err := o.identity(t.Context(), flow, "authorization-code")
	if err != nil {
		t.Fatal(err)
	}
	local := testSession(t, s, admin)
	oidcSession := testSession(t, s, admin)
	if _, err := s.db.ExecContext(t.Context(), `UPDATE management_credentials SET auth_method=? WHERE id=?`, config.Provider, oidcSession.ID); err != nil {
		t.Fatal(err)
	}
	config.Name = "Renamed enterprise"
	config.ClientSecret = ""
	if err := s.SaveOAuthProvider(t.Context(), admin.ID, config); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(t.Context(), oidcSession.Secret, "session"); err == nil {
		t.Fatal("provider reconfiguration retained its active session")
	}
	if _, err := s.Authenticate(t.Context(), local.Secret, "session"); err != nil {
		t.Fatal("provider change revoked local session", err)
	}
	if _, err := s.completeOAuth(t.Context(), flow, identity, Principal{}); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("retired provider configuration completed a login", err)
	}
	if err := s.SaveOAuthProvider(t.Context(), admin.ID, config); !errors.Is(err, ErrConflict) {
		t.Fatal("stale provider revision overwrote configuration", err)
	}
	stored, err := s.oauthProvider(t.Context(), config.Provider)
	if err != nil || stored.ClientSecret != "private-client-secret" {
		t.Fatal("provider update lost write-only secret", err)
	}
	stored.Issuer = "https://different-issuer.test"
	if err := s.SaveOAuthProvider(t.Context(), admin.ID, stored); !errors.Is(err, ErrConflict) {
		t.Fatal("immutable provider issuer changed", err)
	}
	public, err := s.OAuthProviders(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(public)
	if strings.Contains(string(encoded), "private-client-secret") {
		t.Fatal("provider settings returned a reusable client secret")
	}
}

func TestOIDCSigningKeysRotateAndUnknownSignaturesFail(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	provider := newTestOIDC(t)
	config := provider.configure(t, s, admin)
	o := newOAuthService()
	o.client = provider.server.Client()
	_, flow := provider.start(t, o, config, Principal{})
	if _, err := o.identity(t.Context(), flow, "authorization-code"); err != nil {
		t.Fatal(err)
	}
	provider.mu.Lock()
	firstFetches := provider.jwks
	provider.mu.Unlock()
	_, next, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	provider.mu.Lock()
	provider.key = next
	provider.keyID = "rotated"
	provider.mu.Unlock()
	_, flow = provider.start(t, o, config, Principal{})
	if _, err := o.identity(t.Context(), flow, "authorization-code"); err != nil {
		t.Fatal("rotated JWKS key rejected", err)
	}
	provider.mu.Lock()
	if provider.jwks <= firstFetches {
		t.Error("key rotation did not refresh JWKS")
	}
	provider.mu.Unlock()
	// Serve a token signed by an untrusted key while retaining the trusted JWKS.
	trustedClient := o.client
	o.client = &http.Client{Transport: oauthTransport(func(r *http.Request) (*http.Response, error) {
		response, err := trustedClient.Transport.RoundTrip(r)
		if err != nil || r.URL.Path != "/token" {
			return response, err
		}
		defer response.Body.Close()
		var token map[string]any
		if err := json.UnmarshalRead(response.Body, &token); err != nil {
			return nil, err
		}
		raw := token["id_token"].(string)
		parts := strings.Split(raw, ".")
		parts[2] = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		token["id_token"] = strings.Join(parts, ".")
		encoded, err := json.Marshal(token)
		if err != nil {
			return nil, err
		}
		response.Body = io.NopCloser(strings.NewReader(string(encoded)))
		return response, nil
	})}
	_, flow = provider.start(t, o, config, Principal{})
	if _, err := o.identity(t.Context(), flow, "authorization-code"); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("untrusted ID token signature accepted", err)
	}
}

func TestOIDCProviderUnavailablePreservesLocalAuthentication(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	provider := newTestOIDC(t)
	config := provider.configure(t, s, admin)
	o := newOAuthService()
	o.client = provider.server.Client()
	local := testSession(t, s, admin)
	provider.server.Close()
	if _, err := o.startContext(t.Context(), config, "https://ui.example", Principal{}); err == nil {
		t.Fatal("unavailable IdP unexpectedly discovered")
	}
	if _, err := s.Authenticate(t.Context(), local.Secret, "session"); err != nil {
		t.Fatal("external outage blocked local session", err)
	}
	// Explicit offline recovery remains independent from OIDC discovery/config.
	if _, err := s.ResetEnrollment(t.Context(), admin.ID, admin.ID); err != nil {
		t.Fatal("external outage blocked local recovery", err)
	}
}

func TestOIDCSecretsAndAuditFailurePreserveProviderConfiguration(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	provider := newTestOIDC(t)
	config := provider.configure(t, s, admin)
	local := testSession(t, s, admin)
	actor := Principal{UserID: admin.ID, CredentialID: local.ID, CredentialType: "session", Permissions: []Permission{SecurityRead, SecurityWrite}}
	ctx := WithPrincipal(t.Context(), actor)
	config.ClientSecret = "another-private-secret"
	if err := s.SaveOAuthProvider(ctx, admin.ID, config); !errors.Is(err, ErrForbidden) {
		t.Fatal("security writer replaced a secret without secret authority", err)
	}
	config.ClientSecret = "private-client-secret"
	if err := s.SaveOAuthProvider(ctx, admin.ID, config); !errors.Is(err, ErrForbidden) {
		t.Fatal("client secret equality disclosed a matching guess", err)
	}
	config.ClientSecret = ""
	config.Name = "Updated label"
	if err := s.SaveOAuthProvider(ctx, admin.ID, config); err != nil {
		t.Fatal("write-only preservation required secret read/manage", err)
	}
	current, err := s.oauthProvider(t.Context(), config.Provider)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(t.Context(), `CREATE TRIGGER fail_oidc_audit BEFORE INSERT ON management_security_events BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	next := current
	next.Name = "Must not commit"
	if err := s.SaveOAuthProvider(t.Context(), admin.ID, next); err == nil {
		t.Fatal("provider change succeeded without durable audit")
	}
	unchanged, err := s.oauthProvider(t.Context(), config.Provider)
	if err != nil || unchanged.Revision != current.Revision || unchanged.Name != current.Name || unchanged.ClientSecret != "private-client-secret" {
		t.Fatal("failed provider audit changed configuration", err)
	}
}

func TestOIDCDiscoveryRejectsIssuerMismatchAndInsecureEndpoints(t *testing.T) {
	provider := newTestOIDC(t)
	id := "oidc-" + uuid.New().String()
	config := OAuthProvider{Provider: id, Name: "Enterprise", Issuer: provider.server.URL, ClientID: "enterprise-client", RedirectURL: "https://controller.test/api/v2/auth/oauth/" + id + "/callback"}
	base := provider.server.Client()
	for _, field := range []string{"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"} {
		t.Run(field, func(t *testing.T) {
			o := newOAuthService()
			o.client = &http.Client{Transport: oauthTransport(func(r *http.Request) (*http.Response, error) {
				response, err := base.Transport.RoundTrip(r)
				if err != nil {
					return nil, err
				}
				defer response.Body.Close()
				var document map[string]any
				if err := json.UnmarshalRead(response.Body, &document); err != nil {
					return nil, err
				}
				document[field] = "http://insecure-or-wrong.test/endpoint"
				data, err := json.Marshal(document)
				if err != nil {
					return nil, err
				}
				response.Body = io.NopCloser(strings.NewReader(string(data)))
				return response, nil
			})}
			if _, err := o.discoverOIDC(t.Context(), config); err == nil {
				t.Fatal("invalid discovery endpoint accepted")
			}
		})
	}
	config.RedirectURL = "http://localhost/api/v2/auth/oauth/" + id + "/callback"
	if validOIDCConfiguration(config) {
		t.Fatal("generic OIDC accepted a non-HTTPS callback")
	}
}

func TestOIDCProviderHTTPConfigurationAndPublicDiscovery(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	local := testSession(t, s, admin)
	provider := newTestOIDC(t)
	server := &Server{Store: s, AcceptOrigin: func(origin string, _ *http.Request) bool { return origin == "https://ui.example" }}
	mux := http.NewServeMux()
	server.Register(mux)
	server.OAuth.client = provider.server.Client()
	gate := server.Wrap(mux)
	request := func(method, path string, body any, authenticated bool) *httptest.ResponseRecorder {
		t.Helper()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(method, "https://controller.example/api/v2/auth"+path, strings.NewReader(string(encoded)))
		r.Header.Set("Origin", "https://ui.example")
		if authenticated {
			r.Header.Set("Authorization", "Session "+local.Secret)
		}
		w := httptest.NewRecorder()
		gate.ServeHTTP(w, r)
		return w
	}
	config := OAuthProvider{Name: "Enterprise SSO", Issuer: provider.server.URL, ClientID: "enterprise-client", ClientSecret: "private-client-secret", RedirectURL: "https://controller.example"}
	w := request("POST", "/oidc/settings", config, true)
	var saved OAuthProvider
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &saved) != nil || !saved.isOIDC() || saved.Revision != 1 || saved.ClientSecret != "" || !saved.SecretConfigured || !validOAuthCallback(saved.Provider, saved.RedirectURL) {
		t.Fatalf("provider creation failed: %d %s", w.Code, w.Body.String())
	}
	w = request("GET", "/oauth/providers?details=1", nil, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Enterprise SSO") || strings.Contains(w.Body.String(), "private-client-secret") {
		t.Fatal("unsafe public provider metadata", w.Code)
	}
	w = request("GET", "/oauth/settings/"+saved.Provider+"/status", nil, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"ready":true`) {
		t.Fatal("discovery status unavailable", w.Code)
	}
	saved.Enabled = new(false)
	if w = request("PUT", "/oauth/settings/"+saved.Provider, saved, true); w.Code != 200 {
		t.Fatal("provider disable failed", w.Code)
	}
	if w = request("GET", "/oauth/providers", nil, false); w.Code != 200 || strings.Contains(w.Body.String(), saved.Provider) {
		t.Fatal("disabled provider advertised for login", w.Code)
	}
	if w = request("POST", "/oauth/"+saved.Provider+"/start", nil, false); w.Code == 200 {
		t.Fatal("disabled provider started login")
	}
}

func TestOIDCIssuerSubjectBindingCannotBypassLegacyGoogleOwnership(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	first := testUser(t, s, "first", ReadOnly)
	second := testUser(t, s, "second", ReadOnly)
	firstSession := testSession(t, s, first)
	firstActor, err := s.Authenticate(t.Context(), firstSession.Secret, "session")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.completeOAuth(t.Context(), oauthFlow{Owner: first.ID, CredentialID: firstSession.ID}, OAuthLink{Provider: "google", Subject: "same-subject"}, firstActor); err != nil {
		t.Fatal(err)
	}
	id := "oidc-" + uuid.New().String()
	config := OAuthProvider{Provider: id, Name: "Generic Google", Issuer: "https://accounts.google.com", ClientID: "client", RedirectURL: "https://controller.test/api/v2/auth/oauth/" + id + "/callback"}
	if err := s.SaveOAuthProvider(t.Context(), admin.ID, config); err != nil {
		t.Fatal(err)
	}
	config, err = s.oauthProvider(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	secondSession := testSession(t, s, second)
	secondActor, err := s.Authenticate(t.Context(), secondSession.Secret, "session")
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.completeOAuth(t.Context(), oauthFlow{Provider: config, Owner: second.ID, CredentialID: secondSession.ID}, OAuthLink{Provider: id, Issuer: config.Issuer, Subject: "same-subject"}, secondActor)
	if !errors.Is(err, ErrConflict) {
		t.Fatal("same issuer/subject linked through a second provider namespace", err)
	}
}

func TestOIDCPublicClientUsesPKCEWithoutStoredClientSecret(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	provider := newTestOIDC(t)
	config := provider.configure(t, s, admin)
	config.ClearSecret = true
	if err := s.SaveOAuthProvider(t.Context(), admin.ID, config); err != nil {
		t.Fatal(err)
	}
	config, err := s.oauthProvider(t.Context(), config.Provider)
	if err != nil || config.ClientSecret != "" {
		t.Fatal("client secret was not cleared", err)
	}
	provider.mu.Lock()
	provider.public = true
	provider.mu.Unlock()
	o := newOAuthService()
	o.client = provider.server.Client()
	_, flow := provider.start(t, o, config, Principal{})
	if _, err := o.identity(t.Context(), flow, "authorization-code"); err != nil {
		t.Fatal("public-client PKCE exchange failed", err)
	}
}

func TestOIDCConcurrentStartsCoalesceDiscovery(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	provider := newTestOIDC(t)
	config := provider.configure(t, s, admin)
	o := newOAuthService()
	o.client = provider.server.Client()
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if _, err := o.startContext(t.Context(), config, "https://ui.example", Principal{}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.discoveries != 1 {
		t.Fatal("concurrent starts repeated discovery", provider.discoveries)
	}
}
