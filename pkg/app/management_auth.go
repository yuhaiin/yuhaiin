package app

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/httpapi"
)

func reservedManagementPath(path string) bool {
	return strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/debug/") || path == "/metrics"
}

func (app *AppInstance) protectManagement(ctx context.Context) error {
	var handler http.Handler
	if app.HTTPMiddleware != nil {
		wrapped, closer, err := app.HTTPMiddleware(ctx, app.Mux, httpapi.MiddlewareOptions{DataDirectory: app.ConfigPath, AcceptOrigin: app.acceptManagementOrigin})
		if err != nil {
			return err
		}
		if closer != nil {
			app.closers.AddCloser("http_middleware", closer)
		}
		if wrapped == nil {
			return errors.New("HTTP middleware returned no handler")
		}
		handler = wrapped
	} else {
		handler = app.localManagement()
	}
	outer := http.NewServeMux()
	outer.Handle("/", handler)
	app.Mux = outer
	return nil
}

func (app *AppInstance) acceptManagementOrigin(origin string, r *http.Request) bool {
	policy := app.Setting.(*SettingsController).origins
	if policy.accepts(origin, r) {
		return true
	}
	return httpapi.ManagementHTTPS(r) && sameRequestOrigin(origin, r)
}

// With no identity middleware, management is local-only. This is independent of
// listener bind addresses and never turns an Android LAN listener into remote
// anonymous management. Static UI files remain public.
func (app *AppInstance) localManagement() http.Handler {
	mux := app.Mux
	mux.HandleFunc("GET /api/v2/management", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authentication":"none"}`))
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := mux.Handler(r)
		if pattern == "GET /" && !reservedManagementPath(r.URL.Path) {
			mux.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		peer, err := netip.ParseAddrPort(r.RemoteAddr)
		origin := r.Header.Get("Origin")
		if err != nil || !peer.Addr().Unmap().IsLoopback() || (origin != "" && !app.acceptManagementOrigin(origin, r)) {
			http.Error(w, "Local management requires a loopback peer and a trusted Origin", http.StatusForbidden)
			return
		}
		if origin != "" {
			w.Header().Add("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		mux.ServeHTTP(w, r)
	})
}
