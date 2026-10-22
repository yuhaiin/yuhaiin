package app

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/httpapi"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/managementauth"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func (app *AppInstance) protectManagement(ctx context.Context) error {
	if app.Auth != nil {
		log.Warn("legacy management Basic authentication is no longer accepted; complete the web setup using the initialization code in startup output, and remove -u/-p from the service configuration")
	}
	if app.ConfigPath == "" {
		return errors.New("management authentication requires a data directory")
	}
	db, err := storagesqlite.OpenManagement(ctx, filepath.Join(app.ConfigPath, "management.db"))
	if err != nil {
		return err
	}
	app.closers.AddCloser("management_identities", db)
	store := managementauth.NewStore(db.DB())
	passwords, err := managementauth.NewPasswordService(ctx, store)
	if err != nil {
		return err
	}
	code, err := store.StartInitialization(ctx)
	if err != nil {
		return err
	}
	if code.Secret != "" {
		// Deliberately use local startup output, not the persistent/HTTP log stream.
		if _, err := fmt.Fprintf(os.Stderr, "Management setup required. Open the Web UI and create an administrator.\nInitialization code: %s\nExpires at: %s (15 minutes). Restarting before setup completes replaces this code.\n", code.Secret, time.Unix(code.ExpiresAt, 0).Format(time.RFC3339)); err != nil {
			return fmt.Errorf("write management initialization code: %w", err)
		}
	}
	permissions := httpapi.ManagementPermissions()
	maps.Copy(permissions, map[string]managementauth.Permission{
		"GET /metrics":                          managementauth.MetricsRead,
		"GET /debug/pprof/":                     managementauth.Diagnostics,
		"GET /debug/pprof/cmdline":              managementauth.Diagnostics,
		"GET /debug/pprof/profile":              managementauth.Diagnostics,
		"GET /debug/pprof/symbol":               managementauth.Diagnostics,
		"GET /debug/pprof/trace":                managementauth.Diagnostics,
		"GET /debug/profiler/":                  managementauth.Diagnostics,
		"GET /api/v2/profiler/sessions":         managementauth.Diagnostics,
		"POST /api/v2/profiler/sessions":        managementauth.Diagnostics,
		"DELETE /api/v2/profiler/sessions/{id}": managementauth.Diagnostics,
	})
	policy := app.Setting.(*SettingsController).origins
	server := &managementauth.Server{Store: store, Passwords: passwords, Permissions: permissions,
		AcceptOrigin: func(origin string, r *http.Request) bool {
			if policy.accepts(origin, r) {
				return true
			}
			peer, err := netip.ParseAddrPort(r.RemoteAddr)
			return err == nil && !peer.Addr().Unmap().IsLoopback() && r.TLS != nil && sameRequestOrigin(origin, r)
		}}
	server.Register(app.Mux)
	inner := app.Mux
	outer := http.NewServeMux()
	outer.Handle("/", server.Wrap(inner))
	app.Mux = outer
	return nil
}
