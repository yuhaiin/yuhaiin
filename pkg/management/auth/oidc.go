package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type oidcRuntime struct {
	discoveredAt time.Time
	revision     uint64
	config       oauth2.Config
	verifier     *oidc.IDTokenVerifier
}
type oidcLoad struct {
	done    chan struct{}
	runtime *oidcRuntime
	err     error
}

// This transport is used only by identity-provider HTTP operations. It never
// changes proxy forwarding or the local password/recovery path.
type oidcTransport struct{ base http.RoundTripper }

func (t oidcTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if !oidcHTTPSURL(r.URL.String()) {
		return nil, ErrInvalid
	}
	response, err := t.base.RoundTrip(r)
	if err == nil {
		response.Body = &oidcBody{ReadCloser: response.Body, left: 1 << 20}
	}
	return response, err
}

type oidcBody struct {
	io.ReadCloser
	left int64
}

func (b *oidcBody) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, errors.New("identity provider response exceeds limit")
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.ReadCloser.Read(p)
	b.left -= int64(n)
	return n, err
}
func oidcHTTPSURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == ""
}
func (o *OAuthService) oidcClient() *http.Client {
	client := *o.client
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	client.Transport = oidcTransport{base: transport}
	client.Timeout = 15 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &client
}
func (o *OAuthService) discoverOIDC(ctx context.Context, p OAuthProvider) (*oidcRuntime, error) {
	select {
	case o.oidcSlots <- struct{}{}:
		defer func() { <-o.oidcSlots }()
	default:
		return nil, ErrConflict
	}
	if !validProvider(p.Provider) || !p.isOIDC() || !validOIDCConfiguration(p) {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	ctx = oidc.ClientContext(ctx, o.oidcClient())
	provider, err := oidc.NewProvider(ctx, p.Issuer)
	if err != nil {
		return nil, ErrUnauthorized
	}
	var metadata struct {
		JWKS string `json:"jwks_uri"`
	}
	endpoint := provider.Endpoint()
	if provider.Claims(&metadata) != nil || !oidcHTTPSURL(metadata.JWKS) || !oidcHTTPSURL(endpoint.AuthURL) || !oidcHTTPSURL(endpoint.TokenURL) {
		return nil, ErrInvalid
	}
	runtime := &oidcRuntime{discoveredAt: time.Now(), revision: p.Revision, config: oauth2.Config{ClientID: p.ClientID, ClientSecret: p.ClientSecret, RedirectURL: p.RedirectURL, Endpoint: endpoint, Scopes: []string{oidc.ScopeOpenID, "profile"}}}
	// VerifierContext retains only this bounded client; its context is not the
	// initiating request's canceled discovery deadline. JWKS rotation uses the
	// library's cached key set and coalesced refresh.
	runtime.verifier = provider.VerifierContext(oidc.ClientContext(context.Background(), o.oidcClient()), &oidc.Config{ClientID: p.ClientID})
	return runtime, nil
}
func (o *OAuthService) preparedOIDC(ctx context.Context, p OAuthProvider) (*oidcRuntime, error) {
	o.mu.Lock()
	if runtime := o.oidc[p.Provider]; runtime != nil && runtime.revision == p.Revision && time.Since(runtime.discoveredAt) < 15*time.Minute {
		o.mu.Unlock()
		return runtime, nil
	}
	if pending := o.oidcLoads[p.Provider]; pending != nil {
		o.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-pending.done:
		}
		if pending.err != nil {
			return nil, pending.err
		}
		if pending.runtime.revision != p.Revision {
			return nil, ErrConflict
		}
		return pending.runtime, nil
	}
	if len(o.oidcLoads) >= 8 || len(o.oidc) >= 32 && o.oidc[p.Provider] == nil {
		o.mu.Unlock()
		return nil, ErrConflict
	}
	pending := &oidcLoad{done: make(chan struct{})}
	o.oidcLoads[p.Provider] = pending
	o.mu.Unlock()
	runtime, err := o.discoverOIDC(ctx, p)
	o.mu.Lock()
	// Invalidated in-flight discovery cannot repopulate a retired configuration.
	if o.oidcLoads[p.Provider] == pending {
		delete(o.oidcLoads, p.Provider)
		if err == nil {
			o.oidc[p.Provider] = runtime
		}
	} else {
		err = ErrConflict
	}
	pending.runtime, pending.err = runtime, err
	close(pending.done)
	o.mu.Unlock()
	return runtime, err
}
func (o *OAuthService) oidcIdentity(ctx context.Context, f oauthFlow, code string) (OAuthLink, error) {
	if f.OIDC == nil || f.Nonce == "" {
		return OAuthLink{}, ErrUnauthorized
	}
	select {
	case o.oidcSlots <- struct{}{}:
		defer func() { <-o.oidcSlots }()
	default:
		return OAuthLink{}, ErrConflict
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	ctx = oidc.ClientContext(ctx, o.oidcClient())
	token, err := f.OIDC.config.Exchange(ctx, code, oauth2.VerifierOption(f.PKCE))
	if err != nil {
		return OAuthLink{}, ErrUnauthorized
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || len(raw) > 64<<10 {
		return OAuthLink{}, ErrUnauthorized
	}
	identity, err := f.OIDC.verifier.Verify(ctx, raw)
	if err != nil || identity.Issuer != f.Provider.Issuer || identity.Subject == "" || len(identity.Subject) > 255 || subtle.ConstantTimeCompare([]byte(identity.Nonce), []byte(f.Nonce)) != 1 {
		return OAuthLink{}, ErrUnauthorized
	}
	var claims struct {
		AuthorizedParty string `json:"azp"`
		Name            string `json:"name"`
		NotBefore       int64  `json:"nbf"`
	}
	now := time.Now()
	if identity.Claims(&claims) != nil || len(identity.Audience) > 1 && claims.AuthorizedParty != f.Provider.ClientID || claims.AuthorizedParty != "" && claims.AuthorizedParty != f.Provider.ClientID || identity.IssuedAt.IsZero() || identity.IssuedAt.After(now.Add(time.Minute)) || identity.IssuedAt.Before(f.Started.Add(-time.Minute)) || !identity.Expiry.After(identity.IssuedAt) || !identity.Expiry.After(now) || claims.NotBefore > now.Add(time.Minute).Unix() {
		return OAuthLink{}, ErrUnauthorized
	}
	if identity.AccessTokenHash != "" && identity.VerifyAccessToken(token.AccessToken) != nil {
		return OAuthLink{}, ErrUnauthorized
	}
	// No email, directory group or role claim can create/link an account or grant
	// management privileges. Only an explicit local-account binding is accepted.
	return OAuthLink{Provider: f.Provider.Provider, Issuer: identity.Issuer, Subject: identity.Subject, DisplayName: claims.Name}, nil
}
