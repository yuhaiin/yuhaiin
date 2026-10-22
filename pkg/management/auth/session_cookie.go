package auth

import (
	"net/http"
	"time"
)

func sessionCookieName(r *http.Request) string {
	if r.TLS != nil {
		return "__Host-yuhaiin-session"
	}
	return "yuhaiin-session" // HTTP is accepted only from a loopback socket peer.
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, issued IssuedCredential) {
	cookie := &http.Cookie{Name: sessionCookieName(r), Value: issued.Secret, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode, Expires: time.Unix(issued.ExpiresAt, 0), MaxAge: max(1, int(issued.ExpiresAt-time.Now().Unix()))}
	// The official static UI can connect to another HTTPS controller origin.
	if cookie.Secure {
		cookie.SameSite = http.SameSiteNoneMode
	}
	http.SetCookie(w, cookie)
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{Name: sessionCookieName(r), Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0)}
	if cookie.Secure {
		cookie.SameSite = http.SameSiteNoneMode
	}
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
