package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type oauthTransport func(*http.Request) (*http.Response, error)

func (f oauthTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testSession(t *testing.T, s *Store, u User) IssuedCredential {
	t.Helper()
	tx, err := s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	out, err := issueCredential(t.Context(), tx, u.ID, "session", nil, time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestOAuthBrowserFlow(t *testing.T) {
	for _, provider := range []string{"github", "google"} {
		t.Run(provider, func(t *testing.T) {
			s := testStore(t)
			admin := testUser(t, s, "admin", Admin)
			reader := testUser(t, s, "reader", ReadOnly)
			browser := testSession(t, s, reader)
			p, err := s.Authenticate(t.Context(), browser.Secret, "session")
			if err != nil {
				t.Fatal(err)
			}
			config := OAuthProvider{Provider: provider, ClientID: "client", ClientSecret: "private-client-secret", RedirectURL: "https://controller.example/api/v2/auth/oauth/" + provider + "/callback"}
			if err := s.SaveOAuthProvider(t.Context(), admin.ID, config); err != nil {
				t.Fatal(err)
			}
			server := &Server{Store: s, AcceptOrigin: func(origin string, _ *http.Request) bool { return origin == "https://ui.example" }}
			mux := http.NewServeMux()
			server.Register(mux)
			gate := server.Wrap(mux)
			do := func(method, path, auth, origin, body string) *httptest.ResponseRecorder {
				t.Helper()
				r := httptest.NewRequest(method, "https://controller.example/api/v2/auth"+path, strings.NewReader(body))
				r.Header.Set("Authorization", auth)
				r.Header.Set("Origin", origin)
				r.Header.Set("User-Agent", "Test browser")
				r.Header.Set("X-Forwarded-For", "203.0.113.99")
				r.RemoteAddr = "192.0.2.1:1000"
				w := httptest.NewRecorder()
				gate.ServeHTTP(w, r)
				return w
			}
			var pkce string
			server.OAuth.client = &http.Client{Transport: oauthTransport(func(r *http.Request) (*http.Response, error) {
				body := `{"access_token":"provider-access-secret","token_type":"Bearer"}`
				if r.Method == http.MethodPost {
					if err := r.ParseForm(); err != nil {
						t.Fatal(err)
					}
					if r.Form.Get("code_verifier") != pkce || r.Form.Get("redirect_uri") != config.RedirectURL || r.Form.Get("client_secret") != config.ClientSecret || r.Form.Get("code") != "authorization-code" {
						t.Fatalf("incorrect token exchange: %v", r.Form)
					}
				} else {
					if r.Header.Get("Authorization") != "Bearer provider-access-secret" {
						t.Fatal("missing access token")
					}
					if provider == "github" {
						body = `{"id":123456789,"login":"renamable"}`
					} else {
						body = `{"sub":"google-stable-id","name":"Display Name"}`
					}
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			begin := func(link bool) OAuthStart {
				t.Helper()
				action := "start"
				auth := ""
				if link {
					action = "link"
					auth = "Session " + browser.Secret
				}
				w := do("POST", "/oauth/"+provider+"/"+action, auth, "https://ui.example", "{}")
				if w.Code != 200 {
					t.Fatalf("start: %d %s", w.Code, w.Body.String())
				}
				var out OAuthStart
				if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
					t.Fatal(err)
				}
				server.OAuth.mu.Lock()
				pkce = server.OAuth.flows[out.State].PKCE
				server.OAuth.mu.Unlock()
				u, err := url.Parse(out.AuthorizationURL)
				if err != nil {
					t.Fatal(err)
				}
				hash := sha256.Sum256([]byte(pkce))
				if u.Query().Get("code_challenge") != base64.RawURLEncoding.EncodeToString(hash[:]) || u.Query().Get("code_challenge_method") != "S256" || u.Query().Get("state") != out.State {
					t.Fatal("missing PKCE/state")
				}
				return out
			}
			callback := func(start OAuthStart) string {
				t.Helper()
				w := do("GET", "/oauth/"+provider+"/callback?state="+start.State+"&code=authorization-code", "", "", "")
				if w.Code != 200 || !strings.Contains(w.Body.String(), "https://ui.example") || strings.Contains(w.Body.String(), "provider-access-secret") || strings.Contains(w.Body.String(), start.Secret) || w.Header().Get("Content-Security-Policy") == "" {
					t.Fatalf("unsafe callback: %d %s", w.Code, w.Body.String())
				}
				server.OAuth.mu.Lock()
				proof := server.OAuth.flows[start.State].Completion
				server.OAuth.mu.Unlock()
				if proof == "" || !strings.Contains(w.Body.String(), proof) {
					t.Fatalf("missing completion proof: %s", w.Body.String())
				}
				if w := do("GET", "/oauth/"+provider+"/callback?state="+start.State+"&code=authorization-code", "", "", ""); w.Code != 401 {
					t.Fatal("callback replay accepted")
				}
				return proof
			}
			finish := func(start OAuthStart, proof, auth string) *httptest.ResponseRecorder {
				body, _ := json.Marshal(map[string]string{"state": start.State, "secret": start.Secret, "completion": proof})
				return do("POST", "/oauth/"+provider+"/complete", auth, "https://ui.example", string(body))
			}
			start := begin(true)
			proof := callback(start)
			if w := finish(start, "wrong-proof", "Session "+browser.Secret); w.Code != 401 {
				t.Fatal("wrong completion proof accepted")
			}
			if w := finish(start, proof, "Session "+browser.Secret); w.Code != 200 {
				t.Fatalf("link: %d %s", w.Code, w.Body.String())
			}
			if w := finish(start, proof, "Session "+browser.Secret); w.Code != 401 {
				t.Fatal("completion replay accepted")
			}
			links, err := s.OAuthLinks(t.Context(), reader.ID)
			if err != nil || len(links) != 1 {
				t.Fatalf("links=%v err=%v", links, err)
			}
			start = begin(false)
			proof = callback(start)
			w := finish(start, proof, "")
			if w.Code != 200 {
				t.Fatalf("login: %d %s", w.Code, w.Body.String())
			}
			var issued IssuedCredential
			if err := json.Unmarshal(w.Body.Bytes(), &issued); err != nil {
				t.Fatal(err)
			}
			loggedIn, err := s.Authenticate(t.Context(), issued.Secret, "session")
			if err != nil || loggedIn.UserID != reader.ID || loggedIn.Allows(UsersManage) || loggedIn.CredentialID != issued.ID {
				t.Fatalf("OAuth permission/identity mismatch: %+v %v", loggedIn, err)
			}
			sessions, err := s.Sessions(t.Context(), loggedIn)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, session := range sessions {
				if session.ID == issued.ID {
					found = true
					if !session.Current || session.AuthMethod != provider || session.UserAgent != "Test browser" || session.RemoteAddr != "192.0.2.1" || session.LastSeen == 0 {
						t.Fatalf("session metadata: %+v", session)
					}
				}
			}
			if !found {
				t.Fatal("OAuth session absent")
			}
			if err := s.UnlinkOAuth(t.Context(), p, provider); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Authenticate(t.Context(), issued.Secret, "session"); !errors.Is(err, ErrUnauthorized) {
				t.Fatal("unlinked provider session survived")
			}
			start = begin(false)
			proof = callback(start)
			if w := finish(start, proof, ""); w.Code != 401 {
				t.Fatal("unbound OAuth created/logged in a local user")
			}
		})
	}
}

func TestOAuthBindingLifecycleAndConfiguration(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	u := testUser(t, s, "reader", ReadOnly)
	other := testUser(t, s, "other", ReadOnly)
	issued := testSession(t, s, u)
	actor, err := s.Authenticate(t.Context(), issued.Secret, "session")
	if err != nil {
		t.Fatal(err)
	}
	f := oauthFlow{Owner: u.ID, CredentialID: issued.ID}
	link := OAuthLink{Provider: "github", Subject: "42", DisplayName: "name"}
	if _, err := s.completeOAuth(t.Context(), f, link, principal(other)); !errors.Is(err, ErrForbidden) {
		t.Fatal("cross-user link accepted")
	}
	if _, err := s.completeOAuth(t.Context(), f, link, actor); err != nil {
		t.Fatal(err)
	}
	if _, err := s.completeOAuth(t.Context(), f, link, actor); !errors.Is(err, ErrConflict) {
		t.Fatal("duplicate binding accepted")
	}
	otherSession := testSession(t, s, other)
	otherActor, err := s.Authenticate(t.Context(), otherSession.Secret, "session")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.completeOAuth(t.Context(), oauthFlow{Owner: other.ID, CredentialID: otherSession.ID}, link, otherActor); !errors.Is(err, ErrConflict) {
		t.Fatal("same identity bound to two users")
	}
	if _, err := s.ResetEnrollment(t.Context(), admin.ID, u.ID); err != nil {
		t.Fatal(err)
	}
	links, err := s.OAuthLinks(t.Context(), u.ID)
	if err != nil || len(links) != 0 {
		t.Fatal("reset retained OAuth bindings")
	}
	if _, err := s.completeOAuth(t.Context(), f, OAuthLink{Provider: "google", Subject: "subject"}, actor); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("reset session completed binding")
	}
	config := OAuthProvider{Provider: "github", ClientID: "client", ClientSecret: "keep-secret", RedirectURL: "https://controller.example/api/v2/auth/oauth/github/callback"}
	if err := s.SaveOAuthProvider(t.Context(), admin.ID, config); err != nil {
		t.Fatal(err)
	}
	config.ClientSecret = ""
	config.ClientID = "updated"
	if err := s.SaveOAuthProvider(t.Context(), admin.ID, config); err != nil {
		t.Fatal(err)
	}
	stored, err := s.oauthProvider(t.Context(), "github")
	if err != nil || stored.ClientSecret != "keep-secret" {
		t.Fatal("blank secret did not preserve existing")
	}
	public, err := s.OAuthProviders(t.Context())
	if err != nil || len(public) != 1 || public[0].ClientSecret != "" || !public[0].SecretConfigured {
		t.Fatal("settings leaked secret")
	}
	for _, callback := range []string{"http://public.example/api/v2/auth/oauth/github/callback", "https://controller.example/wrong", "https://controller.example/api/v2/auth/oauth/github/callback?x=1", "https://user:password@controller.example/api/v2/auth/oauth/github/callback"} {
		config.RedirectURL = callback
		if err := s.SaveOAuthProvider(t.Context(), admin.ID, config); !errors.Is(err, ErrInvalid) {
			t.Fatalf("unsafe callback %q accepted", callback)
		}
	}
}

func TestOAuthPendingGrantBoundsAndOrigin(t *testing.T) {
	o := newOAuthService()
	config := OAuthProvider{Provider: "github", ClientID: "client"}
	start, err := o.start(config, "https://ui.example", Principal{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.claim("google", start.State); err == nil {
		t.Fatal("provider mixup accepted")
	}
	o.mu.Lock()
	f := o.flows[start.State]
	f.Completion = "proof"
	o.flows[start.State] = f
	o.mu.Unlock()
	if _, err := o.finish("github", start.State, start.Secret, "proof", "https://evil.example"); err == nil {
		t.Fatal("untrusted completion origin accepted")
	}
	o.invalidate("github")
	if _, err := o.claim("github", start.State); err == nil {
		t.Fatal("disabled provider retained pending flow")
	}
	for range 256 {
		if _, err := o.start(config, "https://ui.example", Principal{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := o.start(config, "https://ui.example", Principal{}); !errors.Is(err, ErrConflict) {
		t.Fatal("unbounded pending grants")
	}
	o.mu.Lock()
	for state, f := range o.flows {
		f.Expires = time.Now().Add(-time.Second)
		o.flows[state] = f
	}
	o.mu.Unlock()
	if _, err := o.start(config, "https://ui.example", Principal{}); err != nil {
		t.Fatal("expired grants not pruned")
	}
}
