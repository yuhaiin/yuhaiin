package auth

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/httpapi"
	permission "github.com/Asutorufa/yuhaiin/pkg/management/permission"
)

// Server wraps the application's actual ServeMux, including metrics, profiling,
// streaming and future registrations. No protected handler can bypass this gate
// by registering outside the v2 RPC adapter.
type Server struct {
	Resources    *ResourcePolicies
	Access       *AccessPolicies
	OAuth        *OAuthService
	Proxy        *ProxyCredentials
	Usage        httpapi.UserUsage
	Upstream     *UpstreamCredentials
	Store        *Store
	Permissions  map[string]Permission
	AcceptOrigin func(string, *http.Request) bool
	Passwords    *PasswordService
	public       map[string]bool
}

func secureManagementChannel(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	return err == nil && peer.Addr().Unmap().IsLoopback()
}

func credentials(r *http.Request) (string, string) {
	// Never permit URL credentials, even alongside a valid header.
	if r.URL.Query().Has("token") {
		return "", ""
	}
	if r.Header.Get("Authorization") == "" {
		cookie, err := r.Cookie(sessionCookieName(r))
		if err == nil {
			return cookie.Value, "session"
		}
		return "", ""
	}
	scheme, secret, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok {
		return "", ""
	}
	switch {
	case strings.EqualFold(scheme, "Bearer"):
		return secret, "token"
	case strings.EqualFold(scheme, "Session"):
		return secret, "session"
	default:
		return "", ""
	}
}

func (s *Server) Wrap(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := mux.Handler(r)
		// Only static assets are public; reserved management namespaces cannot
		// become static fallbacks when a route is missing or uses a wrong verb.
		if pattern == "GET /" && !strings.HasPrefix(r.URL.Path, "/api/") &&
			!strings.HasPrefix(r.URL.Path, "/debug/") && r.URL.Path != "/metrics" {
			mux.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if !secureManagementChannel(r) {
			authError(w, http.StatusForbidden)
			return
		}
		origin := r.Header.Get("Origin")
		if origin != "" && (s.AcceptOrigin == nil || !s.AcceptOrigin(origin, r)) {
			authError(w, http.StatusForbidden)
			return
		}
		if origin != "" {
			w.Header().Add("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		r = r.WithContext(withAuditRequest(r, pattern))
		if s.public[pattern] {
			mux.ServeHTTP(w, r)
			return
		}
		secret, kind := credentials(r)
		p, err := s.Store.Authenticate(r.Context(), secret, kind)
		if err != nil {
			authError(w, http.StatusUnauthorized)
			return
		}
		// Cookie mutations require a validated Origin. Header-authenticated CLI
		// clients retain their existing originless contract.
		if r.Header.Get("Authorization") == "" && origin == "" && r.Method != http.MethodGet && r.Method != http.MethodHead {
			authError(w, http.StatusForbidden)
			return
		}
		permission := s.Permissions[pattern]
		r = r.WithContext(WithPrincipal(r.Context(), p))
		if !p.Allows(permission) {
			s.Store.audit(r.Context(), "permission.denied", p.UserID, "")
			authError(w, http.StatusForbidden)
			return
		}
		ctx, cancel := context.WithCancel(WithPrincipal(r.Context(), p))
		defer cancel()
		// Streams and long-running diagnostics cannot retain permissions after
		// revocation. Every ordinary request also re-reads owner status/role.
		done := make(chan struct{})
		defer close(done)
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ctx.Done():
					return
				case <-ticker.C:
					current, err := s.Store.Authenticate(ctx, secret, kind)
					if err != nil || !current.Allows(permission) {
						cancel()
						return
					}
				}
			}
		}()
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}

func authError(w http.ResponseWriter, status int) {
	message := http.StatusText(status)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, map[string]string{"error": message})
}

func respond(w http.ResponseWriter, value any, err error) {
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, ErrInvalid):
			status = http.StatusBadRequest
		case errors.Is(err, ErrUnauthorized):
			status = http.StatusUnauthorized
		case errors.Is(err, ErrForbidden):
			status = http.StatusForbidden
		case errors.Is(err, ErrConflict):
			status = http.StatusConflict
		case errors.Is(err, sql.ErrNoRows):
			status = http.StatusNotFound
		}
		authError(w, status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.MarshalWrite(w, value)
}

func decode(r *http.Request, w http.ResponseWriter, out any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	if json.UnmarshalRead(r.Body, out, json.RejectUnknownMembers(true)) != nil {
		authError(w, http.StatusBadRequest)
		return false
	}
	return true
}

func (s *Server) Register(mux *http.ServeMux) {
	if s.Passwords != nil {
		s.registerPasswords(mux, s.Passwords)
	}
	register := func(pattern string, permission Permission, handler http.HandlerFunc) {
		if s.Permissions == nil {
			s.Permissions = make(map[string]Permission)
		}
		s.Permissions[pattern] = permission
		mux.HandleFunc(pattern, handler)
	}
	s.registerProxyCredentials(register)
	s.registerGroups(register)
	s.registerTrafficAccess(register)
	s.registerResources(register)
	s.registerUsage(register)
	s.registerSessions(register)
	s.registerRoles(register)
	s.registerSessionRestore(register)
	s.registerOAuth(mux, register)
	register("GET /api/v2/auth/me", IdentityRead, func(w http.ResponseWriter, r *http.Request) {
		p, _ := FromContext(r.Context())
		respond(w, p, nil)
	})
	register("GET /api/v2/auth/permissions", IdentityRead, func(w http.ResponseWriter, _ *http.Request) {
		respond(w, permission.Catalog(), nil)
	})
	register("GET /api/v2/auth/users", UsersManage, func(w http.ResponseWriter, r *http.Request) {
		users, err := s.Store.Users(r.Context())
		respond(w, users, err)
	})
	register("GET /api/v2/auth/users/{id}", UsersManage, func(w http.ResponseWriter, r *http.Request) {
		u, err := s.Store.User(r.Context(), r.PathValue("id"))
		respond(w, u, err)
	})
	register("POST /api/v2/auth/users", UsersManage, func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Login string `json:"login"`
			Role  string `json:"role"`
		}
		if !decode(r, w, &request) {
			return
		}
		p, _ := FromContext(r.Context())
		u, enrollment, err := s.Store.CreateUser(r.Context(), p.UserID, request.Login, request.Role, false)
		respond(w, struct {
			User       User             `json:"user"`
			Enrollment IssuedCredential `json:"enrollment"`
		}{u, enrollment}, err)
	})
	register("PUT /api/v2/auth/users/{id}", UsersManage, func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Login    string `json:"login"`
			Role     string `json:"role"`
			Disabled bool   `json:"disabled"`
		}
		if !decode(r, w, &request) {
			return
		}
		p, _ := FromContext(r.Context())
		err := s.Store.UpdateUser(r.Context(), p.UserID, r.PathValue("id"), request.Login, request.Role, request.Disabled)
		if s.Proxy != nil {
			if reloadErr := s.Proxy.Reload(); err == nil {
				err = reloadErr
			}
		}
		respond(w, struct{}{}, err)
	})
	register("DELETE /api/v2/auth/users/{id}", UsersManage, func(w http.ResponseWriter, r *http.Request) {
		p, _ := FromContext(r.Context())
		err := s.Store.DeleteUser(r.Context(), p.UserID, r.PathValue("id"))
		if s.Proxy != nil {
			if reloadErr := s.Proxy.Reload(); err == nil {
				err = reloadErr
			}
		}
		respond(w, struct{}{}, err)
	})
	register("POST /api/v2/auth/users/{id}/enrollment", UsersManage, func(w http.ResponseWriter, r *http.Request) {
		p, _ := FromContext(r.Context())
		enrollment, err := s.Store.ResetEnrollment(r.Context(), p.UserID, r.PathValue("id"))
		if s.Proxy != nil {
			if reloadErr := s.Proxy.Reload(); err == nil {
				err = reloadErr
			}
		}
		respond(w, enrollment, err)
	})
	register("GET /api/v2/auth/tokens", TokensOwn, func(w http.ResponseWriter, r *http.Request) {
		p, _ := FromContext(r.Context())
		owner := r.URL.Query().Get("owner")
		if owner == "" {
			owner = p.UserID
		}
		if owner != p.UserID && !p.Allows(TokensManage) {
			authError(w, http.StatusForbidden)
			return
		}
		tokens, err := s.Store.Credentials(r.Context(), owner)
		respond(w, tokens, err)
	})
	register("POST /api/v2/auth/tokens", TokensOwn, func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Owner     string       `json:"owner"`
			Scopes    []Permission `json:"scopes"`
			ExpiresAt int64        `json:"expiresAt"`
		}
		if !decode(r, w, &request) {
			return
		}
		p, _ := FromContext(r.Context())
		if request.Owner == "" {
			request.Owner = p.UserID
		}
		token, err := s.Store.IssueToken(r.Context(), p, request.Owner, request.Scopes, request.ExpiresAt)
		respond(w, token, err)
	})
	register("DELETE /api/v2/auth/tokens/{id}", TokensOwn, func(w http.ResponseWriter, r *http.Request) {
		p, _ := FromContext(r.Context())
		respond(w, struct{}{}, s.Store.Revoke(r.Context(), p, r.PathValue("id")))
	})
	register("POST /api/v2/auth/tokens/{id}/rotate", TokensOwn, func(w http.ResponseWriter, r *http.Request) {
		p, _ := FromContext(r.Context())
		out, err := s.Store.RotateToken(r.Context(), p, r.PathValue("id"))
		respond(w, out, err)
	})
	register("GET /api/v2/auth/events", SecurityRead, func(w http.ResponseWriter, r *http.Request) {
		events, err := s.Store.Events(r.Context())
		respond(w, events, err)
	})
	register("POST /api/v2/auth/password/enrollment", IdentityRead, func(w http.ResponseWriter, r *http.Request) {
		p, _ := FromContext(r.Context())
		if p.CredentialType != "session" {
			authError(w, http.StatusForbidden)
			return
		}
		out, err := s.Store.StartPasswordChange(r.Context(), p)
		if s.Proxy != nil {
			if reloadErr := s.Proxy.Reload(); err == nil {
				err = reloadErr
			}
		}
		respond(w, out, err)
	})
	register("DELETE /api/v2/auth/session", IdentityRead, func(w http.ResponseWriter, r *http.Request) {
		secret, kind := credentials(r)
		if kind != "session" {
			authError(w, http.StatusForbidden)
			return
		}
		err := s.Store.logout(r.Context(), secret)
		if err == nil {
			clearSessionCookie(w, r)
		}
		respond(w, struct{}{}, err)
	})
}
