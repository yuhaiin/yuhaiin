package httpapi

import (
	"context"
	"github.com/Asutorufa/yuhaiin/pkg/security/configchange"
	"io"
	"net/http"
	"net/netip"

	usage "github.com/Asutorufa/yuhaiin/pkg/contract/usage"
)

// Middleware is initialized after all management routes are registered. It can
// register its own routes and must guard the whole returned handler, including
// auxiliary routes. A non-nil closer is owned by the application's lifecycle.
// Initialization failure aborts startup rather than falling back to local access.
type Middleware func(context.Context, *http.ServeMux, MiddlewareOptions) (http.Handler, io.Closer, error)

type MiddlewareOptions struct {
	ConfigurationChanges configchange.Backend
	DataDirectory        string
	AcceptOrigin         func(string, *http.Request) bool
	UserUsage            UserUsage
}

// UserUsage is optional; identity middleware owns user-scoped authorization.
type UserUsage interface {
	Report(context.Context, usage.Query) (usage.Report, error)
	Audit(context.Context, usage.Query) (usage.AuditPage, error)
	UsageUsers(context.Context, string, int) ([]string, error)
	Options() usage.Options
	SetOptions(context.Context, usage.Options) error
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
