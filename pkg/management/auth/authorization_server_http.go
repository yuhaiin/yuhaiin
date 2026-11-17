package auth

import (
	"context"
	"errors"
	"html/template"
	"mime"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"encoding/json/v2"

	"github.com/Asutorufa/yuhaiin/pkg/management/oauth"
	permission "github.com/Asutorufa/yuhaiin/pkg/management/permission"
)

// Endpoints of the OAuth 2.1 Authorization Server. They sit outside /api/ so a
// browser following an authorization link never reaches the management API
// namespace, and every one of them still passes through Server.Wrap.
const (
	oauthMetadataPath     = "/.well-known/oauth-authorization-server"
	oauthAuthorizePath    = "/oauth/authorize"
	oauthTokenPath        = "/oauth/token"
	oauthRevokePath       = "/oauth/revoke"
	oauthRegisterPath     = "/oauth/register"
	oauthConsentRoute     = "/#/oauth/consent/"
	oauthServerAPI        = "/api/v2/auth/oauth-server"
	resourceMetadataRoot  = "/.well-known/oauth-protected-resource"
	maxOAuthFormBytes     = 64 << 10
	maxOAuthRegisterBytes = 64 << 10
)

// openCORSPath reports the endpoints that clients running on any web origin
// may call. None of them reads cookies or other ambient credentials, so they
// are answered without Access-Control-Allow-Credentials.
func openCORSPath(path string) bool {
	return path == oauthMetadataPath || path == oauthTokenPath || path == oauthRevokePath || path == oauthRegisterPath ||
		path == resourceMetadataRoot || strings.HasPrefix(path, resourceMetadataRoot+"/")
}

var oauthErrorPage = template.Must(template.New("oauth-error").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorization failed</title><style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:15vh auto;padding:0 16px;color:#222}code{word-break:break-all}</style><h1>Authorization failed</h1><p>The application sent an authorization request that Yuhaiin cannot accept, so you were not redirected back to it.</p><p><code>{{.Code}}</code>: {{.Description}}</p></html>`))

func writeAuthorizeError(w http.ResponseWriter, err error) {
	var oauthErr *oauth.Error
	if !errors.As(err, &oauthErr) {
		oauthErr = oauth.ServerError("")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(http.StatusBadRequest)
	_ = oauthErrorPage.Execute(w, oauthErr)
}

func peerAddress(r *http.Request) string {
	peer, _ := netip.ParseAddrPort(r.RemoteAddr)
	return peer.Addr().Unmap().String()
}

// oauthForm reads an application/x-www-form-urlencoded body. Query parameters
// are never accepted at the token and revocation endpoints.
func oauthForm(w http.ResponseWriter, r *http.Request) (map[string][]string, error) {
	media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if media != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" {
		return nil, oauth.InvalidRequest("send parameters as an application/x-www-form-urlencoded body")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxOAuthFormBytes)
	if err := r.ParseForm(); err != nil {
		return nil, oauth.InvalidRequest("malformed request body")
	}
	return r.PostForm, nil
}

func (s *Server) registerAuthorizationServer(mux *http.ServeMux, register func(string, Permission, http.HandlerFunc)) {
	a := s.Authorization
	if a == nil {
		return
	}
	public := func(pattern string, limited bool, handler http.HandlerFunc) {
		s.public[pattern] = true
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			settings, err := a.Settings(r.Context())
			if err != nil || !settings.active() {
				authError(w, http.StatusNotFound)
				return
			}
			if limited && !a.limiter.allow(peerAddress(r)) {
				oauth.WriteJSON(w, http.StatusTooManyRequests, &oauth.Error{Code: "temporarily_unavailable", Description: "too many requests"})
				return
			}
			handler(w, r)
		})
	}
	public("GET "+oauthMetadataPath, false, func(w http.ResponseWriter, r *http.Request) {
		settings, _ := a.Settings(r.Context())
		issuer := settings.Issuer
		metadata := oauth.AuthorizationServerMetadata{Issuer: issuer, AuthorizationEndpoint: issuer + oauthAuthorizePath, TokenEndpoint: issuer + oauthTokenPath, RevocationEndpoint: issuer + oauthRevokePath,
			ScopesSupported: []string{}, ResponseTypesSupported: []string{"code"}, ResponseModesSupported: []string{"query"}, GrantTypesSupported: oauth.GrantTypes,
			TokenEndpointAuthMethodsSupported: oauth.AuthMethods, RevocationEndpointAuthMethodsSupported: oauth.AuthMethods, CodeChallengeMethodsSupported: []string{"S256"}, AuthorizationResponseIssParameterSupported: true}
		if settings.DynamicRegistration {
			metadata.RegistrationEndpoint = issuer + oauthRegisterPath
		}
		for _, scope := range a.activeScopes(settings) {
			metadata.ScopesSupported = append(metadata.ScopesSupported, string(scope))
		}
		oauth.WriteJSON(w, http.StatusOK, metadata)
	})
	for _, resource := range a.resources.All() {
		public("GET "+resource.MetadataPath(), false, func(w http.ResponseWriter, r *http.Request) {
			settings, _ := a.Settings(r.Context())
			if !settings.resourceEnabled(resource.ID) {
				authError(w, http.StatusNotFound)
				return
			}
			oauth.WriteJSON(w, http.StatusOK, oauth.ResourceMetadata(settings.Issuer, resource))
		})
	}
	public("GET "+oauthAuthorizePath, true, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		request, err := a.StartAuthorization(r.Context(), r.URL.Query())
		var redirect *redirectError
		switch {
		case errors.As(err, &redirect):
			_ = a.audit(withAuditReason(r.Context(), redirect.err.Code), "oauth.authorization.failed", "", r.URL.Query().Get("client_id"), oauthDetails{ClientID: r.URL.Query().Get("client_id")})
			http.Redirect(w, r, redirect.location(), http.StatusSeeOther)
		case err != nil:
			writeAuthorizeError(w, err)
		default:
			_ = a.audit(r.Context(), "oauth.authorization.started", "", request.Client.ID, oauthDetails{ClientID: request.Client.ID, Resource: request.ResourceURI, Scopes: scopeStrings(request.Scopes)})
			http.Redirect(w, r, request.Issuer+oauthConsentRoute+request.ID, http.StatusSeeOther)
		}
	})
	public("POST "+oauthTokenPath, true, func(w http.ResponseWriter, r *http.Request) {
		form, err := oauthForm(w, r)
		if err != nil {
			oauth.WriteError(w, err)
			return
		}
		response, err := a.Token(r.Context(), r, form)
		if err != nil {
			oauth.WriteError(w, err)
			return
		}
		oauth.WriteJSON(w, http.StatusOK, response)
	})
	public("POST "+oauthRevokePath, true, func(w http.ResponseWriter, r *http.Request) {
		form, err := oauthForm(w, r)
		if err == nil {
			err = a.Revoke(r.Context(), r, form)
		}
		if err != nil {
			oauth.WriteError(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	public("POST "+oauthRegisterPath, true, func(w http.ResponseWriter, r *http.Request) {
		media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		var request ClientRegistration
		r.Body = http.MaxBytesReader(w, r.Body, maxOAuthRegisterBytes)
		if media != "application/json" || json.UnmarshalRead(r.Body, &request) != nil {
			oauth.WriteError(w, oauth.InvalidClientMetadata("send client metadata as a JSON object"))
			return
		}
		response, err := a.Register(r.Context(), request)
		if err != nil {
			oauth.WriteError(w, err)
			return
		}
		oauth.WriteJSON(w, http.StatusCreated, response)
	})

	session := func(handler func(http.ResponseWriter, *http.Request, Principal)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			p, err := sessionPrincipal(r)
			if err != nil {
				respond(w, nil, err)
				return
			}
			handler(w, r, p)
		}
	}
	register("GET "+oauthServerAPI+"/settings", SecurityRead, session(func(w http.ResponseWriter, r *http.Request, _ Principal) {
		out, err := a.overview(r.Context())
		respond(w, out, err)
	}))
	register("PUT "+oauthServerAPI+"/settings", SecurityWrite, session(func(w http.ResponseWriter, r *http.Request, p Principal) {
		var request OAuthServerSettings
		if !decode(r, w, &request) {
			return
		}
		out, err := a.SaveSettings(r.Context(), p, request)
		respond(w, out, err)
	}))
	register("GET "+oauthServerAPI+"/clients", SecurityRead, session(func(w http.ResponseWriter, r *http.Request, _ Principal) {
		out, err := a.Clients(r.Context())
		respond(w, out, err)
	}))
	register("POST "+oauthServerAPI+"/clients", SecurityWrite, session(func(w http.ResponseWriter, r *http.Request, p Principal) {
		var request OAuthClientRequest
		if !decode(r, w, &request) {
			return
		}
		out, err := a.CreateClient(r.Context(), p, request)
		respondOAuth(w, out, err)
	}))
	register("PUT "+oauthServerAPI+"/clients/{id}", SecurityWrite, session(func(w http.ResponseWriter, r *http.Request, p Principal) {
		var request OAuthClientRequest
		if !decode(r, w, &request) {
			return
		}
		out, err := a.UpdateClient(r.Context(), p, r.PathValue("id"), request)
		respondOAuth(w, out, err)
	}))
	register("DELETE "+oauthServerAPI+"/clients/{id}", SecurityWrite, session(func(w http.ResponseWriter, r *http.Request, p Principal) {
		respond(w, struct{}{}, a.DeleteClient(r.Context(), p, r.PathValue("id")))
	}))
	register("GET "+oauthServerAPI+"/grants", IdentityRead, session(func(w http.ResponseWriter, r *http.Request, p Principal) {
		owner := p.UserID
		if r.URL.Query().Get("scope") == "all" {
			if !p.Allows(SecurityRead) {
				authError(w, http.StatusForbidden)
				return
			}
			owner = ""
		}
		out, err := a.Grants(r.Context(), owner)
		respond(w, out, err)
	}))
	register("DELETE "+oauthServerAPI+"/grants/{id}", IdentityRead, session(func(w http.ResponseWriter, r *http.Request, p Principal) {
		respond(w, struct{}{}, a.RevokeGrant(r.Context(), p, r.PathValue("id")))
	}))
	register("GET "+oauthServerAPI+"/grants/{id}/tokens", IdentityRead, session(func(w http.ResponseWriter, r *http.Request, p Principal) {
		out, err := a.Tokens(r.Context(), p, r.PathValue("id"))
		respond(w, out, err)
	}))
	register("GET "+oauthServerAPI+"/authorizations/{id}", IdentityRead, session(func(w http.ResponseWriter, r *http.Request, p Principal) {
		out, err := a.Authorization(r.Context(), p, r.PathValue("id"))
		respond(w, out, err)
	}))
	register("POST "+oauthServerAPI+"/authorizations/{id}", IdentityRead, session(func(w http.ResponseWriter, r *http.Request, p Principal) {
		var request struct {
			Approve bool         `json:"approve"`
			Scopes  []Permission `json:"scopes"`
		}
		if !decode(r, w, &request) {
			return
		}
		redirect, err := a.Decide(r.Context(), p, r.PathValue("id"), request.Approve, request.Scopes)
		respond(w, struct {
			RedirectURI string `json:"redirectUri"`
		}{redirect}, err)
	}))
}

// respondOAuth maps OAuth metadata validation errors to 400 with a reason.
func respondOAuth(w http.ResponseWriter, value any, err error) {
	if oauthErr, ok := errors.AsType[*oauth.Error](err); ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.MarshalWrite(w, map[string]string{"error": oauthErr.Code, "message": oauthErr.Description})
		return
	}
	respond(w, value, err)
}

// ResourceOverview describes one protected resource for administrators.
type ResourceOverview struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	URI         string       `json:"uri"`
	MetadataURL string       `json:"metadataUrl"`
	Scopes      []Permission `json:"scopes"`
	Required    Permission   `json:"required,omitempty"`
	Enabled     bool         `json:"enabled"`
	Legacy      bool         `json:"legacyCredentials"`
}

// OAuthServerOverview is the administrator view of the Authorization Server.
type OAuthServerOverview struct {
	Settings              OAuthServerSettings `json:"settings"`
	MetadataURL           string              `json:"metadataUrl,omitempty"`
	AuthorizationEndpoint string              `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint         string              `json:"tokenEndpoint,omitempty"`
	RevocationEndpoint    string              `json:"revocationEndpoint,omitempty"`
	RegistrationEndpoint  string              `json:"registrationEndpoint,omitempty"`
	Resources             []ResourceOverview  `json:"resources"`
}

func (a *AuthorizationServer) overview(ctx context.Context) (OAuthServerOverview, error) {
	settings, err := a.Settings(ctx)
	if err != nil {
		return OAuthServerOverview{}, err
	}
	out := OAuthServerOverview{Settings: settings, Resources: []ResourceOverview{}}
	issuer := settings.Issuer
	if issuer != "" {
		out.MetadataURL, out.AuthorizationEndpoint, out.TokenEndpoint, out.RevocationEndpoint = issuer+oauthMetadataPath, issuer+oauthAuthorizePath, issuer+oauthTokenPath, issuer+oauthRevokePath
		if settings.DynamicRegistration {
			out.RegistrationEndpoint = issuer + oauthRegisterPath
		}
	}
	for _, r := range a.resources.All() {
		item := ResourceOverview{ID: r.ID, Name: r.Name, Scopes: r.Scopes, Required: r.Required, Enabled: settings.resourceEnabled(r.ID), Legacy: r.LegacyCredentials}
		if issuer != "" {
			item.URI, item.MetadataURL = r.URI(issuer), r.MetadataURL(issuer)
		}
		out.Resources = append(out.Resources, item)
	}
	return out, nil
}

func (a *AuthorizationServer) activeScopes(settings OAuthServerSettings) []Permission {
	var out []Permission
	for _, p := range permission.DelegableValues() {
		for _, r := range a.resources.All() {
			if settings.resourceEnabled(r.ID) && slices.Contains(r.Scopes, p) {
				out = append(out, p)
				break
			}
		}
	}
	return out
}
