package auth

import (
	"html/template"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"uuid"
)

// This page sends only a one-use completion proof to the initiating trusted UI.
// A separate POST must also prove possession of the start secret. No session or
// provider access token appears in a URL, page, storage or window message.
var oauthCallbackPage = template.Must(template.New("oauth").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><title>OAuth</title><p>Return to the application to finish signing in. You may close this window.</p><script nonce="{{.Nonce}}">if(window.opener){window.opener.postMessage({type:"yuhaiin-oauth",state:{{.State}},completion:{{.Completion}},failed:{{.Failed}}},{{.Origin}});window.close();}</script></html>`))

func (s *Server) registerOAuth(mux *http.ServeMux, register func(string, Permission, http.HandlerFunc)) {
	if s.OAuth == nil {
		s.OAuth = newOAuthService()
	}
	if s.public == nil {
		s.public = make(map[string]bool)
	}
	public := func(pattern string, handler http.HandlerFunc) {
		s.public[pattern] = true
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			peer, _ := netip.ParseAddrPort(r.RemoteAddr)
			if s.Passwords != nil && !s.Passwords.allow(peer.Addr().Unmap().String()) {
				authError(w, http.StatusTooManyRequests)
				return
			}
			handler(w, r)
		})
	}
	public("GET /api/v2/auth/oauth/providers", func(w http.ResponseWriter, r *http.Request) {
		providers, err := s.Store.OAuthProviders(r.Context())
		out := []string{}
		for _, p := range providers {
			if p.enabled() {
				out = append(out, p.Provider)
			}
		}
		if r.URL.Query().Get("details") == "1" {
			type publicProvider struct {
				Provider string `json:"provider"`
				Name     string `json:"name"`
			}
			details := []publicProvider{}
			for _, p := range providers {
				if p.enabled() {
					details = append(details, publicProvider{p.Provider, p.Name})
				}
			}
			respond(w, details, err)
			return
		}
		respond(w, out, err)
	})
	register("GET /api/v2/auth/oauth/settings", SecurityRead, func(w http.ResponseWriter, r *http.Request) {
		if _, err := sessionPrincipal(r); err != nil {
			respond(w, nil, err)
			return
		}
		out, err := s.Store.OAuthProviders(r.Context())
		respond(w, out, err)
	})
	register("PUT /api/v2/auth/oauth/settings/{provider}", SecurityWrite, func(w http.ResponseWriter, r *http.Request) {
		actor, err := sessionPrincipal(r)
		if err != nil {
			respond(w, nil, err)
			return
		}
		var p OAuthProvider
		if !decode(r, w, &p) {
			return
		}
		p.Provider = r.PathValue("provider")
		if !validOAuthProviderConfiguration(p) {
			respond(w, nil, ErrInvalid)
			return
		}
		if p.isOIDC() && p.enabled() {
			if _, err := s.OAuth.discoverOIDC(r.Context(), p); err != nil {
				respond(w, nil, err)
				return
			}
		}
		err = s.Store.SaveOAuthProvider(r.Context(), actor.UserID, p)
		if err == nil {
			s.OAuth.invalidate(p.Provider)
		}
		respond(w, struct{}{}, err)
	})
	register("DELETE /api/v2/auth/oauth/settings/{provider}", SecurityWrite, func(w http.ResponseWriter, r *http.Request) {
		actor, err := sessionPrincipal(r)
		if err != nil {
			respond(w, nil, err)
			return
		}
		err = s.Store.DeleteOAuthProvider(r.Context(), actor.UserID, r.PathValue("provider"))
		if err == nil {
			s.OAuth.invalidate(r.PathValue("provider"))
		}
		respond(w, struct{}{}, err)
	})
	register("POST /api/v2/auth/oidc/settings", SecurityWrite, func(w http.ResponseWriter, r *http.Request) {
		actor, err := sessionPrincipal(r)
		if err != nil {
			respond(w, nil, err)
			return
		}
		var p OAuthProvider
		if !decode(r, w, &p) {
			return
		}
		if p.Provider == "" {
			p.Provider = "oidc-" + uuid.New().String()
			if callback, err := url.Parse(p.RedirectURL); err == nil && (callback.Path == "" || callback.Path == "/") {
				callback.Path = "/api/v2/auth/oauth/" + p.Provider + "/callback"
				p.RedirectURL = callback.String()
			}
		}
		p.RedirectURL = strings.ReplaceAll(p.RedirectURL, "{provider}", p.Provider)
		if !p.isOIDC() || !validProvider(p.Provider) {
			respond(w, nil, ErrInvalid)
			return
		}
		p.Revision = 0
		if !validOAuthProviderConfiguration(p) {
			respond(w, nil, ErrInvalid)
			return
		}
		if p.enabled() {
			if _, err := s.OAuth.discoverOIDC(r.Context(), p); err != nil {
				respond(w, nil, err)
				return
			}
		}
		err = s.Store.SaveOAuthProvider(r.Context(), actor.UserID, p)
		s.OAuth.invalidate(p.Provider)
		if err != nil {
			respond(w, nil, err)
			return
		}
		saved, err := s.Store.oauthProvider(r.Context(), p.Provider)
		respond(w, publicOAuthProvider(saved), err)
	})
	register("GET /api/v2/auth/oauth/settings/{provider}/status", SecurityRead, func(w http.ResponseWriter, r *http.Request) {
		p, err := s.Store.oauthProvider(r.Context(), r.PathValue("provider"))
		if err != nil {
			respond(w, nil, err)
			return
		}
		ready := p.enabled()
		if ready && p.isOIDC() {
			_, err = s.OAuth.discoverOIDC(r.Context(), p)
			ready = err == nil
		}
		respond(w, struct {
			Enabled  bool   `json:"enabled"`
			Ready    bool   `json:"ready"`
			Revision uint64 `json:"revision"`
		}{p.enabled(), ready, p.Revision}, nil)
	})
	start := func(link bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			origin, err := s.oauthOrigin(r)
			if err != nil {
				authError(w, http.StatusForbidden)
				return
			}
			var actor Principal
			if link {
				actor, err = sessionPrincipal(r)
				if err != nil {
					respond(w, nil, err)
					return
				}
			}
			p, err := s.Store.oauthProvider(r.Context(), r.PathValue("provider"))
			if err != nil {
				authError(w, http.StatusBadRequest)
				return
			}
			out, err := s.OAuth.startContext(r.Context(), p, origin, actor)
			respond(w, out, err)
		}
	}
	public("POST /api/v2/auth/oauth/{provider}/start", start(false))
	register("POST /api/v2/auth/oauth/{provider}/link", IdentityRead, start(true))
	public("GET /api/v2/auth/oauth/{provider}/callback", func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get("state")
		f, err := s.OAuth.claim(r.PathValue("provider"), state)
		if err != nil {
			respond(w, nil, err)
			return
		}
		completion := ""
		if r.URL.Query().Get("error") == "" {
			completion, err = s.OAuth.callback(r.Context(), state, f, r.URL.Query().Get("code"))
		}
		nonce := oauthRandom()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_ = oauthCallbackPage.Execute(w, struct {
			Nonce, State, Completion, Origin string
			Failed                           bool
		}{nonce, state, completion, f.Origin, err != nil || completion == ""})
	})
	public("POST /api/v2/auth/oauth/{provider}/complete", func(w http.ResponseWriter, r *http.Request) {
		origin, err := s.oauthOrigin(r)
		if err != nil {
			authError(w, http.StatusForbidden)
			return
		}
		var request struct {
			State      string `json:"state"`
			Secret     string `json:"secret"`
			Completion string `json:"completion"`
		}
		if !decode(r, w, &request) {
			return
		}
		f, err := s.OAuth.finish(r.PathValue("provider"), request.State, request.Secret, request.Completion, origin)
		if err != nil {
			respond(w, nil, err)
			return
		}
		var actor Principal
		if f.Owner != "" {
			secret, kind := credentials(r)
			actor, err = s.Store.Authenticate(r.Context(), secret, kind)
			if err != nil {
				respond(w, nil, err)
				return
			}
		}
		out, err := s.Store.completeOAuth(sessionContext(r, f.Provider.Provider), f, f.Identity, actor)
		if err == nil && out != nil {
			setSessionCookie(w, r, *out)
		}
		respond(w, out, err)
	})
	register("GET /api/v2/auth/oauth/links", IdentityRead, func(w http.ResponseWriter, r *http.Request) {
		actor, err := sessionPrincipal(r)
		if err != nil {
			respond(w, nil, err)
			return
		}
		out, err := s.Store.OAuthLinks(r.Context(), actor.UserID)
		respond(w, out, err)
	})
	register("DELETE /api/v2/auth/oauth/links/{provider}", IdentityRead, func(w http.ResponseWriter, r *http.Request) {
		actor, err := sessionPrincipal(r)
		if err != nil {
			respond(w, nil, err)
			return
		}
		respond(w, struct{}{}, s.Store.UnlinkOAuth(r.Context(), actor, r.PathValue("provider")))
	})
}
