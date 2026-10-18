package app

import (
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// Gateway management inherits configured Basic authentication. Without it,
// allow only local management and local browser origins, so a default host
// binding cannot expose CA rotation/import or arbitrary upstream configuration.
func guardGatewayManagement(auth *Auth, pattern string, next func(http.ResponseWriter, *http.Request) error) func(http.ResponseWriter, *http.Request) error {
	if auth != nil || !strings.HasPrefix(pattern, "POST /api/v2/rpc/gateway.") {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) error {
		peer, err := netip.ParseAddrPort(r.RemoteAddr)
		allowed := err == nil && peer.Addr().IsLoopback()
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || u == nil {
				allowed = false
			} else {
				ip, err := netip.ParseAddr(u.Hostname())
				allowed = allowed && (u.Hostname() == "localhost" || (err == nil && ip.IsLoopback()))
			}
		}
		if !allowed {
			http.Error(w, "Gateway management requires authentication for remote clients or origins", http.StatusForbidden)
			return nil
		}
		return next(w, r)
	}
}
