package auth

import (
	"net/http"
	"net/url"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/httpapi"
)

func sessionCookieName(r *http.Request) string {
	if httpapi.ManagementHTTPS(r) {
		return "__Host-yuhaiin-session"
	}
	return "yuhaiin-session" // HTTP is accepted only from a loopback socket peer.
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, issued IssuedCredential) {
	cookie := &http.Cookie{Name: sessionCookieName(r), Value: issued.Secret, Path: "/", HttpOnly: true, Expires: time.Unix(issued.ExpiresAt, 0), MaxAge: max(1, int(issued.ExpiresAt-time.Now().Unix()))}
	applyCookieSite(cookie, r)
	http.SetCookie(w, cookie)
}

// crossOriginRequest reports whether the page that sent r is served from
// another origin, e.g. the official static UI talking to this controller.
// Origin has already been validated by Server.Wrap at this point.
func crossOriginRequest(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		return true
	}
	scheme := "http"
	if httpapi.ManagementHTTPS(r) {
		scheme = "https"
	}
	return u.Scheme != scheme || u.Host != r.Host
}

// applyCookieSite makes a cookie survive a page reload when the UI is
// served from another origin. Lax cookies are neither stored nor sent on
// cross-site fetches, so a loopback HTTP controller used from the static UI
// needs SameSite=None, which browsers only accept with Secure (they treat
// loopback HTTP as a secure context). Partitioned keys the cookie to the UI's
// top-level site, so it still works when third-party cookies are blocked
// and is never sent while browsing other sites. Set and clear must agree,
// or the clearing cookie lands in a different partition.
func applyCookieSite(cookie *http.Cookie, r *http.Request) {
	cookie.Secure = httpapi.ManagementHTTPS(r)
	cookie.SameSite = http.SameSiteLaxMode
	if cookie.Secure {
		cookie.SameSite = http.SameSiteNoneMode
	}
	if crossOriginRequest(r) {
		cookie.Secure = true
		cookie.SameSite = http.SameSiteNoneMode
		cookie.Partitioned = true
	}
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{Name: sessionCookieName(r), Path: "/", HttpOnly: true, MaxAge: -1, Expires: time.Unix(1, 0)}
	applyCookieSite(cookie, r)
	http.SetCookie(w, cookie)
}

func (s *Server) registerSessionRestore(register func(string, Permission, http.HandlerFunc)) {
	register("GET /api/v2/auth/session", IdentityRead, func(w http.ResponseWriter, r *http.Request) {
		p, err := sessionPrincipal(r)
		if err != nil {
			respond(w, nil, err)
			return
		}
		var expiresAt int64
		err = s.Store.db.QueryRowContext(r.Context(), `SELECT expires_at FROM management_credentials WHERE id=? AND user_id=? AND kind='session'`, p.CredentialID, p.UserID).Scan(&expiresAt)
		respond(w, struct {
			Principal Principal `json:"principal"`
			ExpiresAt int64     `json:"expiresAt"`
		}{p, expiresAt}, err)
	})
}
