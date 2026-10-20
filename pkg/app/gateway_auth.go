package app

import (
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// The official static UI is served from a different origin than the local
// management API. Trust it only when the API connection itself is loopback.
// Never accept arbitrary *.github.io origins or approximate domain matches.
const officialGatewayUIOrigin = "https://yuhaiin.github.io"

// Gateway management inherits configured Basic authentication. Without it,
// allow only loopback clients with a local browser origin or the official
// static UI origin. This preserves the hosted UI while refusing unauthenticated
// management from remote network peers or untrusted web sites.
func guardGatewayManagement(auth *Auth, pattern string, next func(http.ResponseWriter, *http.Request) error) func(http.ResponseWriter, *http.Request) error {
	if auth != nil || !strings.HasPrefix(pattern, "POST /api/v2/rpc/gateway.") {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) error {
		peer, err := netip.ParseAddrPort(r.RemoteAddr)
		allowed := err == nil && peer.Addr().Unmap().IsLoopback()
		if origin := r.Header.Get("Origin"); origin != "" && origin != officialGatewayUIOrigin {
			u, err := url.Parse(origin)
			if err != nil || u == nil {
				allowed = false
			} else {
				ip, err := netip.ParseAddr(u.Hostname())
				localOrigin := strings.EqualFold(u.Hostname(), "localhost") ||
					(err == nil && ip.Unmap().IsLoopback())
				allowed = allowed && (u.Scheme == "http" || u.Scheme == "https") &&
					u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" &&
					localOrigin
			}
		}
		if !allowed {
			http.Error(w, "Gateway management requires authentication for remote clients or origins", http.StatusForbidden)
			return nil
		}
		return next(w, r)
	}
}
