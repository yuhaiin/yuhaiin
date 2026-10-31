package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json/v2"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// Pending grants are bounded, short-lived and lost on restart. Provider tokens
// exist only for the userinfo request; they are never persisted or returned.
type oauthFlow struct {
	OIDC                                      *oidcRuntime
	Nonce                                     string
	Started                                   time.Time
	Provider                                  OAuthProvider
	Origin, Secret, PKCE, Owner, CredentialID string
	Expires                                   time.Time
	Claimed                                   bool
	Completion                                string
	Identity                                  OAuthLink
}

type OAuthService struct {
	mu        sync.Mutex
	flows     map[string]oauthFlow
	oidc      map[string]*oidcRuntime
	oidcLoads map[string]*oidcLoad
	oidcSlots chan struct{}
	client    *http.Client
}

func newOAuthService() *OAuthService {
	return &OAuthService{flows: make(map[string]oauthFlow), oidc: make(map[string]*oidcRuntime), oidcLoads: make(map[string]*oidcLoad), oidcSlots: make(chan struct{}, 8), client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func oauthRandom() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func (o *OAuthService) pruneLocked() {
	for id, f := range o.flows {
		if time.Now().After(f.Expires) {
			delete(o.flows, id)
		}
	}
}
func (o *OAuthService) invalidate(provider string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.oidc, provider)
	delete(o.oidcLoads, provider)
	for id, f := range o.flows {
		if f.Provider.Provider == provider {
			delete(o.flows, id)
		}
	}
}

func providerConfig(p OAuthProvider) (oauth2.Config, string) {
	c := oauth2.Config{ClientID: p.ClientID, ClientSecret: p.ClientSecret, RedirectURL: p.RedirectURL}
	if p.Provider == "github" {
		c.Endpoint = oauth2.Endpoint{AuthURL: "https://github.com/login/oauth/authorize", TokenURL: "https://github.com/login/oauth/access_token", AuthStyle: oauth2.AuthStyleInParams}
		c.Scopes = []string{"read:user"}
		return c, "https://api.github.com/user"
	}
	c.Endpoint = oauth2.Endpoint{AuthURL: "https://accounts.google.com/o/oauth2/v2/auth", TokenURL: "https://oauth2.googleapis.com/token", AuthStyle: oauth2.AuthStyleInParams}
	c.Scopes = []string{"openid", "profile"}
	return c, "https://openidconnect.googleapis.com/v1/userinfo"
}

type OAuthStart struct {
	State            string `json:"state"`
	Secret           string `json:"secret"`
	AuthorizationURL string `json:"authorizationUrl"`
	ExpiresAt        int64  `json:"expiresAt"`
}

func (o *OAuthService) start(provider OAuthProvider, origin string, actor Principal) (OAuthStart, error) {
	return o.startContext(context.Background(), provider, origin, actor)
}
func (o *OAuthService) startContext(ctx context.Context, provider OAuthProvider, origin string, actor Principal) (OAuthStart, error) {
	if !provider.enabled() {
		return OAuthStart{}, ErrUnauthorized
	}
	f := oauthFlow{Provider: provider, Origin: origin, Secret: oauthRandom(), PKCE: oauth2.GenerateVerifier(), Expires: time.Now().Add(5 * time.Minute), Started: time.Now(), Owner: actor.UserID, CredentialID: actor.CredentialID}
	if provider.isOIDC() {
		f.Nonce = oauthRandom()
	}
	o.mu.Lock()
	o.pruneLocked()
	if len(o.flows) >= 256 {
		o.mu.Unlock()
		return OAuthStart{}, ErrConflict
	}
	state := oauthRandom()
	o.flows[state] = f
	o.mu.Unlock()
	config, _ := providerConfig(provider)
	options := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(f.PKCE)}
	if provider.isOIDC() {
		runtime, err := o.preparedOIDC(ctx, provider)
		if err != nil {
			o.mu.Lock()
			delete(o.flows, state)
			o.mu.Unlock()
			return OAuthStart{}, err
		}
		f.OIDC = runtime
		config = runtime.config
		options = append(options, oauth2.SetAuthURLParam("nonce", f.Nonce))
		o.mu.Lock()
		if _, exists := o.flows[state]; !exists {
			o.mu.Unlock()
			return OAuthStart{}, ErrUnauthorized
		}
		o.flows[state] = f
		o.mu.Unlock()
	}
	return OAuthStart{state, f.Secret, config.AuthCodeURL(state, options...), f.Expires.Unix()}, nil
}

func (o *OAuthService) claim(provider, state string) (oauthFlow, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.pruneLocked()
	f, ok := o.flows[state]
	if !ok || f.Provider.Provider != provider || f.Claimed {
		return oauthFlow{}, ErrUnauthorized
	}
	f.Claimed = true
	o.flows[state] = f
	return f, nil
}

func (o *OAuthService) identity(ctx context.Context, f oauthFlow, code string) (OAuthLink, error) {
	if f.Provider.isOIDC() {
		return o.oidcIdentity(ctx, f, code)
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, o.client)
	config, endpoint := providerConfig(f.Provider)
	token, err := config.Exchange(ctx, code, oauth2.VerifierOption(f.PKCE))
	if err != nil {
		return OAuthLink{}, ErrUnauthorized
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return OAuthLink{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/json")
	if f.Provider.Provider == "github" {
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	}
	response, err := o.client.Do(req)
	if err != nil {
		return OAuthLink{}, ErrUnauthorized
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return OAuthLink{}, ErrUnauthorized
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return OAuthLink{}, ErrUnauthorized
	}
	link := OAuthLink{Provider: f.Provider.Provider, Issuer: oauthIssuer(f.Provider)}
	if f.Provider.Provider == "github" {
		var user struct {
			ID    int64  `json:"id"`
			Login string `json:"login"`
		}
		if json.Unmarshal(body, &user) != nil || user.ID <= 0 {
			return OAuthLink{}, ErrUnauthorized
		}
		link.Subject = strconv.FormatInt(user.ID, 10)
		link.DisplayName = user.Login
	} else {
		var user struct {
			Sub  string `json:"sub"`
			Name string `json:"name"`
		}
		if json.Unmarshal(body, &user) != nil || user.Sub == "" || len(user.Sub) > 255 {
			return OAuthLink{}, ErrUnauthorized
		}
		link.Subject = user.Sub
		link.DisplayName = user.Name
	}
	return link, nil
}

func (o *OAuthService) callback(ctx context.Context, state string, f oauthFlow, code string) (completion string, err error) {
	defer func() {
		if err != nil {
			o.mu.Lock()
			if current, ok := o.flows[state]; ok && current.Secret == f.Secret && current.Claimed {
				delete(o.flows, state)
			}
			o.mu.Unlock()
		}
	}()
	if code == "" || len(code) > 4096 {
		return "", ErrUnauthorized
	}
	identity, err := o.identity(ctx, f, code)
	if err != nil {
		return "", err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.pruneLocked()
	current, ok := o.flows[state]
	if !ok || current.Secret != f.Secret {
		return "", ErrUnauthorized
	}
	current.Completion = oauthRandom()
	current.Identity = identity
	o.flows[state] = current
	return current.Completion, nil
}

func (o *OAuthService) finish(provider, state, secret, completion, origin string) (oauthFlow, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.pruneLocked()
	f, ok := o.flows[state]
	if !ok || f.Provider.Provider != provider || f.Origin != origin || completion == "" || f.Completion == "" || subtle.ConstantTimeCompare([]byte(f.Secret), []byte(secret)) != 1 || subtle.ConstantTimeCompare([]byte(f.Completion), []byte(completion)) != 1 {
		return oauthFlow{}, ErrUnauthorized
	}
	delete(o.flows, state)
	return f, nil
}

func (s *Server) oauthOrigin(r *http.Request) (string, error) {
	origin := r.Header.Get("Origin")
	if origin == "" || s.AcceptOrigin == nil || !s.AcceptOrigin(origin, r) {
		return "", ErrForbidden
	}
	return origin, nil
}

func sessionPrincipal(r *http.Request) (Principal, error) {
	p, ok := FromContext(r.Context())
	if !ok || p.CredentialType != "session" {
		return Principal{}, ErrForbidden
	}
	return p, nil
}
