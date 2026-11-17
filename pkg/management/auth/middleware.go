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
	"slices"
	"time"

	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/httpapi"
	"github.com/Asutorufa/yuhaiin/pkg/management/mcpserver"
	"github.com/Asutorufa/yuhaiin/pkg/management/oauth"
	permission "github.com/Asutorufa/yuhaiin/pkg/management/permission"
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
	// Authorization is the OAuth 2.1 Authorization Server, set by Middleware.
	Authorization *AuthorizationServer
	db            io.Closer
}

type RuntimeOptions struct {
	// InitializationCode overrides random generation for unfinished setup only.
	// Nil generates a random code; a non-nil empty or malformed value is invalid.
	// This secret is never printed or persisted in plaintext.
	InitializationCode *string
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
	return OpenRuntimeWithOptions(ctx, directory, RuntimeOptions{})
}

func OpenRuntimeWithOptions(ctx context.Context, directory string, options RuntimeOptions) (_ *Runtime, err error) {
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
	code, err := store.startInitialization(ctx, options.InitializationCode)
	if err != nil {
		return nil, err
	}
	if code.Secret != "" {
		// Deliberately use local startup output, not the persistent/HTTP log stream.
		if err := writeInitializationNotice(os.Stderr, code, options.InitializationCode != nil); err != nil {
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

// ManagementAPIResource is the existing HTTP management API as an OAuth
// protected resource. Its scopes are every delegable permission except
// mcp:connect and secrets:read: an OAuth client of the API never receives the
// secret-reveal capability. Each route keeps the permission it already
// declares in ManagementPermissions.
func ManagementAPIResource() oauth.Resource {
	scopes := slices.DeleteFunc(permission.DelegableValues(), func(p Permission) bool { return p == MCPConnect || p == SecretsRead })
	return oauth.Resource{ID: "api", Name: "Yuhaiin management API", Path: "/api", Prefixes: []string{"/api/", "/debug/", "/metrics"}, Scopes: scopes, LegacyCredentials: true}
}

// protectedResources registers the OAuth protected resources served by this
// process. Only server executables reach this code: native Android does not
// install the identity middleware and therefore has no Authorization Server,
// MCP endpoint or OAuth tables.
func (r *Runtime) protectedResources(mux *http.ServeMux, permissions map[string]Permission, options httpapi.MiddlewareOptions) (*oauth.Registry, error) {
	registry := &oauth.Registry{}
	if err := registry.Register(ManagementAPIResource()); err != nil {
		return nil, err
	}
	if options.Operations == nil {
		return registry, nil
	}
	mcp, err := mcpserver.New(options.Operations, version.Version)
	if err != nil {
		return nil, err
	}
	if err := registry.Register(mcp.Resource()); err != nil {
		return nil, err
	}
	for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodDelete} {
		pattern := method + " " + mcpserver.Path
		permissions[pattern] = MCPConnect
		mux.Handle(pattern, mcp)
	}
	return registry, nil
}

func writeInitializationNotice(output io.Writer, code InitializationCode, configured bool) error {
	message := "Initialization code: " + code.Secret + "\n"
	restart := "Restarting before setup completes replaces this code."
	if configured {
		message = "Using the configured initialization code (value hidden).\n"
		restart = "Restarting before setup completes renews the configured code for 15 minutes."
	}
	_, err := fmt.Fprintf(output, "Management setup required. Open the Web UI and create an administrator.\n%sExpires at: %s (15 minutes). %s\n", message, time.Unix(code.ExpiresAt, 0).Format(time.RFC3339), restart)
	return err
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
	resources, err := r.protectedResources(mux, permissions, options)
	if err != nil {
		return nil, nil, err
	}
	r.Authorization = newAuthorizationServer(r.store, resources)
	server := &Server{Resources: r.Resources, Access: r.Access, Store: r.store, Passwords: r.passwords, Proxy: r.Proxy, Upstream: r.Upstream, Usage: options.UserUsage, Permissions: permissions, AcceptOrigin: options.AcceptOrigin,
		Authorization: r.Authorization}
	server.Changes = &ConfigurationChanges{server: server, identity: configchange.New(r.store.db), configuration: options.ConfigurationChanges}
	if options.ConfigurationChanges != nil {
		if err := options.ConfigurationChanges.Enable(ctx); err != nil {
			return nil, nil, err
		}
	}
	server.Register(mux)
	// The recovery UI is Core-owned static HTML/JS. Permit reading it without
	// credentials so a broken OTA cannot lock administrators out. Its reset
	// RPC remains authenticated and requires UpdateManage.
	server.public["GET /__ui_recovery"] = true
	server.public["GET /__ui_recovery.js"] = true
	return server.Wrap(mux), nil, nil
}
