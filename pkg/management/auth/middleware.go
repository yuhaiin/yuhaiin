package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/httpapi"
	"github.com/Asutorufa/yuhaiin/pkg/security/configchange"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

// Middleware installs local users, setup, password sessions and token RBAC.
// Only server executables opt in; native Android does not import this package.
// Runtime shares one private identity store between management and traffic.
type Runtime struct {
	Audit     *AuditForwarder
	Resources *ResourcePolicies
	Access    *AccessPolicies
	store     *Store
	passwords *PasswordService
	Proxy     *ProxyCredentials
	Upstream  *UpstreamCredentials
	db        io.Closer
}

func Middleware(ctx context.Context, mux *http.ServeMux, options httpapi.MiddlewareOptions) (http.Handler, io.Closer, error) {
	runtime, err := OpenRuntime(ctx, options.DataDirectory)
	if err != nil {
		return nil, nil, err
	}
	handler, _, err := runtime.Middleware(ctx, mux, options)
	if err != nil {
		_ = runtime.Close()
		return nil, nil, err
	}
	return handler, runtime, nil
}

func OpenRuntime(ctx context.Context, directory string) (_ *Runtime, err error) {
	if directory == "" {
		return nil, errors.New("management authentication requires a data directory")
	}

	db, err := storagesqlite.OpenManagement(ctx, filepath.Join(directory, "management.db"))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = db.Close()
		}
	}()
	store := NewStore(db.DB())
	passwords, err := NewPasswordService(ctx, store)
	if err != nil {
		return nil, err
	}
	code, err := store.StartInitialization(ctx)
	if err != nil {
		return nil, err
	}
	if code.Secret != "" {
		// Deliberately use local startup output, not the persistent/HTTP log stream.
		if _, err := fmt.Fprintf(os.Stderr, "Management setup required. Open the Web UI and create an administrator.\nInitialization code: %s\nExpires at: %s (15 minutes). Restarting before setup completes replaces this code.\n", code.Secret, time.Unix(code.ExpiresAt, 0).Format(time.RFC3339)); err != nil {
			return nil, fmt.Errorf("write management initialization code: %w", err)
		}
	}
	proxy, err := NewProxyCredentials(ctx, store)
	if err != nil {
		return nil, err
	}
	access, err := NewAccessPolicies(ctx, store)
	if err != nil {
		_ = proxy.Close()
		return nil, err
	}
	resources, err := NewResourcePolicies(ctx, store, proxy, access.Controller)
	if err != nil {
		_ = access.Controller.Close()
		_ = proxy.Close()
		return nil, err
	}
	audit, err := newAuditForwarder(ctx, store, nil)
	if err != nil {
		_ = resources.Close()
		_ = access.Controller.Close()
		_ = proxy.Close()
		return nil, err
	}
	upstream := &UpstreamCredentials{store: store}
	if _, err := upstream.snapshot(ctx); err != nil {
		_ = audit.Close()
		_ = resources.Close()
		_ = access.Controller.Close()
		_ = proxy.Close()
		return nil, err
	}
	return &Runtime{Audit: audit, Resources: resources, Access: access, store: store, passwords: passwords, Proxy: proxy, Upstream: upstream, db: db}, nil
}

func (r *Runtime) Close() error {
	r.Upstream.close()
	var resourceErr, auditErr error
	if r.Audit != nil {
		auditErr = r.Audit.Close()
	}
	if r.Resources != nil {
		resourceErr = r.Resources.Close()
	}
	return errors.Join(auditErr, resourceErr, r.Access.Controller.Close(), r.Proxy.Close(), r.db.Close())
}

func (r *Runtime) Middleware(ctx context.Context, mux *http.ServeMux, options httpapi.MiddlewareOptions) (http.Handler, io.Closer, error) {
	permissions := make(map[string]Permission)
	maps.Copy(permissions, httpapi.ManagementPermissions())
	maps.Copy(permissions, map[string]Permission{
		"GET /metrics":                          MetricsRead,
		"GET /debug/pprof/":                     Diagnostics,
		"GET /debug/pprof/cmdline":              Diagnostics,
		"GET /debug/pprof/profile":              Diagnostics,
		"GET /debug/pprof/symbol":               Diagnostics,
		"GET /debug/pprof/trace":                Diagnostics,
		"GET /debug/profiler/":                  Diagnostics,
		"GET /api/v2/profiler/sessions":         Diagnostics,
		"POST /api/v2/profiler/sessions":        Diagnostics,
		"DELETE /api/v2/profiler/sessions/{id}": Diagnostics,
	})
	server := &Server{Resources: r.Resources, Access: r.Access, Store: r.store, Passwords: r.passwords, Proxy: r.Proxy, Upstream: r.Upstream, Usage: options.UserUsage, Permissions: permissions, AcceptOrigin: options.AcceptOrigin}
	server.Changes = &ConfigurationChanges{server: server, identity: configchange.New(r.store.db), configuration: options.ConfigurationChanges}
	if options.ConfigurationChanges != nil {
		if err := options.ConfigurationChanges.Enable(ctx); err != nil {
			return nil, nil, err
		}
	}
	server.Register(mux)
	return server.Wrap(mux), nil, nil
}
