package httpapi

import (
	"context"
	"io"
	"net/http"
	"net/netip"
)

// Middleware is initialized after all management routes are registered. It can
// register its own routes and must guard the whole returned handler, including
// auxiliary routes. A non-nil closer is owned by the application's lifecycle.
// Initialization failure aborts startup rather than falling back to local access.
type Middleware func(context.Context, *http.ServeMux, MiddlewareOptions) (http.Handler, io.Closer, error)

type MiddlewareOptions struct {
	DataDirectory string
	AcceptOrigin  func(string, *http.Request) bool
}

// ManagementHTTPS reports the browser-facing transport. A local reverse proxy
// may terminate HTTPS before forwarding over HTTP; only an actual loopback peer
// can supply that scheme. Remote Forwarded headers never confer transport trust.
func ManagementHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil || !peer.Addr().Unmap().IsLoopback() {
		return false
	}
	values := r.Header.Values("X-Forwarded-Proto")
	return len(values) == 1 && values[0] == "https"
}
