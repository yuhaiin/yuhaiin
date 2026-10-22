package managementauth

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
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

// Middleware installs local users, setup, password sessions and token RBAC.
// Only server executables opt in; native Android does not import this package.
func Middleware(ctx context.Context, mux *http.ServeMux, options httpapi.MiddlewareOptions) (_ http.Handler, _ io.Closer, err error) {
	if options.DataDirectory == "" {
		return nil, nil, errors.New("management authentication requires a data directory")
	}

	db, err := storagesqlite.OpenManagement(ctx, filepath.Join(options.DataDirectory, "management.db"))
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			_ = db.Close()
		}
	}()
	store := NewStore(db.DB())
	passwords, err := NewPasswordService(ctx, store)
	if err != nil {
		return nil, nil, err
	}
	code, err := store.StartInitialization(ctx)
	if err != nil {
		return nil, nil, err
	}
	if code.Secret != "" {
		// Deliberately use local startup output, not the persistent/HTTP log stream.
		if _, err := fmt.Fprintf(os.Stderr, "Management setup required. Open the Web UI and create an administrator.\nInitialization code: %s\nExpires at: %s (15 minutes). Restarting before setup completes replaces this code.\n", code.Secret, time.Unix(code.ExpiresAt, 0).Format(time.RFC3339)); err != nil {
			return nil, nil, fmt.Errorf("write management initialization code: %w", err)
		}
	}
	permissions := make(map[string]Permission)
	for pattern, permission := range httpapi.ManagementPermissions() {
		permissions[pattern] = permission
	}
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
	server := &Server{Store: store, Passwords: passwords, Permissions: permissions, AcceptOrigin: options.AcceptOrigin}
	server.Register(mux)
	return server.Wrap(mux), db, nil
}
