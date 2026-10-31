package auth

import (
	"context"
	"net/http"
	"net/netip"
)

type auditKey struct{}
type auditInfo struct{ source, method, path, changes, policyRevision, reason string }
type auditMonitorKey struct{}

// Record actual socket peers and route templates. Query strings, credentials,
// bodies, Origin/User-Agent and untrusted forwarding headers are not copied.
func withAuditRequest(r *http.Request, pattern string) context.Context {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	source := ""
	if err == nil {
		source = peer.Addr().Unmap().String()
	}
	return context.WithValue(r.Context(), auditKey{}, auditInfo{source: source, method: r.Method, path: pattern})
}
