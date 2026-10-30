package app

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	runtimepprof "runtime/pprof"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	backupapp "github.com/Asutorufa/yuhaiin/pkg/app/backup"
	certmanager "github.com/Asutorufa/yuhaiin/pkg/cert/manager"
	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/credential"
	"github.com/Asutorufa/yuhaiin/pkg/httpapi"
	"github.com/Asutorufa/yuhaiin/pkg/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
	"github.com/Asutorufa/yuhaiin/pkg/node"
	routepkg "github.com/Asutorufa/yuhaiin/pkg/route"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
	"github.com/Asutorufa/yuhaiin/pkg/sysproxy"
	updatepkg "github.com/Asutorufa/yuhaiin/pkg/update"
	yf "github.com/yuhaiin/yuhaiin.github.io"
)

type AppInstance struct {
	Certificates  *certmanager.Manager
	Gateway       httpapi.GatewayController
	Node          httpapi.NodeController
	NodeRuntime   *node.NodeRuntime
	Tools         httpapi.ToolsController
	Diagnostics   httpapi.DiagnosticsController
	Subscribe     httpapi.SubscriptionController
	Connections   httpapi.ConnectionMonitor
	UserUsage     httpapi.UserUsage
	Resolver      httpapi.ResolverController
	FakeIP        contractresolver.FakeIPEntries
	ResolverCache httpapi.ResolverCacheController
	ResolverCfg   httpapi.ResolverConfigController
	Lists         httpapi.ListRuntimeController
	Rules         httpapi.RouteRuntimeController
	Backup        httpapi.BackupController
	Setting       httpapi.SettingsController
	Inbound       *inbound.Inbound
	Mux           *http.ServeMux
	*StartOptions
	closers  *closers
	profiler *profilerService
}

type closers struct {
	closers []*moduleCloser
}

func (a *closers) AddCloser(name string, z io.Closer) {
	a.closers = append(a.closers, &moduleCloser{z, name})
}

func (a *closers) Close() error {
	return a.closeExcept("")
}

func (a *closers) CloseExcept(name string) error {
	return a.closeExcept(name)
}

func (a *closers) CloseNamed(name string) error {
	var err error
	for _, closer := range a.closers {
		if closer.name != name {
			continue
		}
		if er := closer.Close(); er != nil {
			err = errors.Join(err, fmt.Errorf("%s close error: %w", closer.name, er))
		}
	}
	return err
}

func (a *closers) closeExcept(name string) error {
	closers := slices.Clone(a.closers)
	slices.Reverse(closers)

	var err error
	for _, v := range closers {
		if v.name == name {
			continue
		}
		if er := v.Close(); er != nil {
			err = errors.Join(err, fmt.Errorf("%s close error: %w", v.name, er))
		}
	}

	return err
}

type moduleCloser struct {
	io.Closer
	name string
}

func (m *moduleCloser) Close() error {
	log.Info("close", "module", m.name)
	defer log.Info("closed", "module", m.name)
	return m.Closer.Close()
}

func (app *AppInstance) RegisterServer(ctx context.Context) error {
	if err := registerV2HTTP(ctx, app); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	RegisterHTTP(app.Mux)
	registerProfilerHTTP(app)
	return app.protectManagement(ctx)
}

func registerV2HTTP(ctx context.Context, app *AppInstance) error {
	var inboundStore httpapi.InboundStore
	var nodeStore *plainstore.NodeStore
	var subscriptionStore *plainstore.SubscriptionStore
	var resolverStore *plainstore.ResolverStore
	resolverConfig := app.ResolverCfg
	var routeSettingsStore *plainstore.RouteSettingsStore
	var routeListStore *plainstore.RouteListStore
	var routeRegistryStore *plainstore.RouteRegistryStore
	var registryCatalogs httpapi.RegistryCatalogController
	var routeRuleStore *plainstore.RouteRuleStore
	var routeEditor *plainstore.RouteEditorStore
	var selectors httpapi.SelectorController
	subscribeController := app.Subscribe
	if sqlStore := app.StateStore; sqlStore != nil {
		db, err := sqlStore.SQLDB(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Error("init v2 sqlite store failed", "err", err)
		} else {
			plainInboundStore := plainstore.NewInboundStore(db)
			inboundRuntimeStore := inbound.NewContractStore(plainInboundStore, app.Inbound)
			if err := inboundRuntimeStore.Sync(ctx); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				log.Error("sync v2 inbound runtime failed", "err", err)
			}
			inboundStore = inboundRuntimeStore
			nodeStore = plainstore.NewNodeStore(db)
			subscriptionStore = plainstore.NewSubscriptionStore(db)
			resolverStore = plainstore.NewResolverStore(db)
			resolverConfig = plainstore.NewResolverConfigRuntimeStore(plainstore.NewResolverConfigStore(db), app.ResolverCfg)
			routeSettingsStore = plainstore.NewRouteSettingsStore(db)
			routeListStore = plainstore.NewRouteListStore(db)
			routeRegistryStore = plainstore.NewRouteRegistryStore(db)
			registryCatalogs = routepkg.NewRegistryCatalogService(routeRegistryStore)
			routeRuleStore = plainstore.NewRouteRuleStore(db)
			routeEditor = plainstore.NewRouteEditorStore(db)
			selectors = plainstore.NewSelectorStore(db)
			if app.NodeRuntime != nil {
				selectors = node.NewSelectorService(app.NodeRuntime)
			}
			if app.NodeRuntime != nil {
				subscribeController = node.NewSubscribe(app.NodeRuntime, subscriptionStore)
			}
		}
	}

	recoveryPoints, _ := app.Backup.(updatepkg.RecoveryPoints)
	httpapi.RegisterV2(func(pattern string, handler func(http.ResponseWriter, *http.Request) error) {
		// The outer management gate covers all routes, including auxiliary
		// registrations, and establishes a Principal before this handler runs.
		handleRPCFunc(app.Mux, nil, nil, pattern, handler)
	}, httpapi.V2Services{
		Certificates:     app.Certificates,
		Gateway:          app.Gateway,
		Settings:         app.Setting,
		Inbounds:         inboundStore,
		Nodes:            nodeStore,
		Node:             app.Node,
		Subscriptions:    subscriptionStore,
		Resolvers:        resolverStore,
		Resolver:         app.Resolver,
		FakeIP:           app.FakeIP,
		ResolverCache:    app.ResolverCache,
		ResolverConfig:   resolverConfig,
		Connections:      app.Connections,
		Tools:            app.Tools,
		Diagnostics:      app.Diagnostics,
		Update:           updatepkg.NewService(updatepkg.Options{Installer: app.Updater, Recovery: recoveryPoints}),
		Backup:           app.Backup,
		Lists:            app.Lists,
		RouteSettings:    routeSettingsStore,
		RouteLists:       routeListStore,
		RouteRegistries:  routeRegistryStore,
		RegistryCatalogs: registryCatalogs,
		Rules:            app.Rules,
		RouteRules:       routeRuleStore,
		RouteEditor:      routeEditor,
		Selectors:        selectors,
		Subscribe:        subscribeController,
	})
	return ctx.Err()
}

func (a *AppInstance) Close() error {
	// Stop certificate work while its governed network path and SQLite owner
	// remain available for bounded challenge cleanup and durable retry receipts.
	var certificateErr error
	if a.Certificates != nil {
		certificateErr = a.Certificates.Close()
	}
	if a.profiler != nil {
		a.profiler.stop()
		activeProfiler.CompareAndSwap(a.profiler, nil)
	}
	sysproxy.Unset()

	err := errors.Join(certificateErr, a.closers.CloseExcept("state_store"))
	if er := compactStateStore(context.Background(), a.StateStore); er != nil {
		err = errors.Join(err, fmt.Errorf("compact state store failed: %w", er))
	}
	if er := a.closers.CloseNamed("state_store"); er != nil {
		err = errors.Join(err, er)
	}
	return err
}

func compactStateStore(ctx context.Context, store SQLStore) error {
	if store == nil {
		return nil
	}
	db, err := store.SQLDB(ctx)
	if err != nil {
		return err
	}

	log.Info("compact state database")
	return storagesqlite.Compact(ctx, db)
}

type StartOptions struct {
	Context context.Context

	StateStore SQLStore

	ProcessDumper netapi.ProcessDumper

	Auth *Auth

	// Optional management HTTP middleware. Without it, only local peers can
	// access management routes; no identity database or auth routes are loaded.
	HTTPMiddleware      httpapi.Middleware
	ProxyAuthentication proxyauth.Provider
	UpstreamCredentials credential.Resolver

	ConfigPath string
	// RecoveryStartupID authorizes one pending offline-restore startup attempt.
	// Ordinary/embedded starts leave it empty and reject pending activation.
	RecoveryStartupID string
	// DelayCertificateStart lets the CLI verify its management listener before
	// renewal can replace the certificate pinned by startup/update supervision.
	DelayCertificateStart bool

	Updater             updatepkg.Installer
	RecoveryMaintenance backupapp.RecoveryMaintainer
}

type SQLStore interface {
	SQLDB(context.Context) (*sql.DB, error)
}

type MigrationStore interface {
	Migrate(context.Context) error
}

type Auth struct {
	Username [32]byte
	Password [32]byte
}

func NewAuth(username, password string) *Auth {
	return &Auth{
		Username: sha256.Sum256([]byte(username)),
		Password: sha256.Sum256([]byte(password)),
	}
}

func (a *Auth) Auth(password, username string) bool {
	rSumUser := sha256.Sum256([]byte(username))
	rSumPass := sha256.Sum256([]byte(password))
	return subtle.ConstantTimeCompare(rSumUser[:], a.Username[:]) == 1 && subtle.ConstantTimeCompare(rSumPass[:], a.Password[:]) == 1
}

func HandleFunc(mux *http.ServeMux, auth *Auth, path string, b func(http.ResponseWriter, *http.Request) error) {
	handleFunc(mux, auth, nil, path, b)
}

func handleFunc(mux *http.ServeMux, auth *Auth, policy *managementOriginPolicy, path string, b func(http.ResponseWriter, *http.Request) error) {
	mux.Handle(path, http.HandlerFunc(func(ow http.ResponseWriter, r *http.Request) {
		w := &wrapResponseWriter{ow, false}

		if policy != nil {
			if !policy.authorize(auth, r) {
				http.Error(w, "Management API requires a trusted Origin and authentication for remote clients", http.StatusForbidden)
				return
			}
			cross(r, w)
		}
		// Browser CORS preflights never include Basic credentials. Handle them
		// before authentication; the actual RPC request is still authenticated.
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if auth != nil {
			username, password, ok := r.BasicAuth()
			if !ok || !auth.Auth(password, username) {
				// ow.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		err := b(w, r)
		if err != nil {
			if !w.writed {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}

			if !errors.Is(err, context.DeadlineExceeded) &&
				!errors.Is(err, os.ErrDeadlineExceeded) &&
				!errors.Is(err, context.Canceled) {
				log.Error("handle failed", "path", path, "err", err)
			}
		} else if !w.writed {
			w.WriteHeader(http.StatusOK)
		}
	}))
}

func cross(r *http.Request, w http.ResponseWriter) {
	// Only validated browser origins reach this point. Echo the exact origin
	// instead of mixing an unrestricted wildcard with credentialed requests.
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Add("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Expose-Headers", "Authorization")
}

type wrapResponseWriter struct {
	http.ResponseWriter
	writed bool
}

func (w *wrapResponseWriter) Write(b []byte) (int, error) {
	if !w.writed {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *wrapResponseWriter) WriteHeader(s int) {
	if !w.writed && (s >= http.StatusOK || s == http.StatusSwitchingProtocols) {
		// Management responses must opt into executable content. Set the default
		// before committing headers, including handlers that flush before writing.
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.writed = true
	}
	w.ResponseWriter.WriteHeader(s)
}

func (w *wrapResponseWriter) Flush() {
	if !w.writed {
		w.WriteHeader(http.StatusOK)
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *wrapResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.writed = true
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

var (
	pprofEnabled    atomic.Bool
	pprofConfigured atomic.Bool
	pprofMu         sync.Mutex
)

func setPprofEnabled(enabled bool) {
	pprofConfigured.Store(true)
	if disabledByEnv, _ := strconv.ParseBool(os.Getenv("DISABLED_PPROF")); disabledByEnv {
		enabled = false
	}

	pprofMu.Lock()
	defer pprofMu.Unlock()
	if pprofEnabled.Load() == enabled {
		return
	}

	pprofEnabled.Store(enabled)
	if enabled {
		// The HTTP CPU profile handler starts and drains its own collector.
		// Starting runtime sampling here leaves an unread buffer and pollutes
		// the first requested profile with samples from before the request.
		// A 100 us block sampling interval still captures network waits without
		// recording almost every short packet-processing synchronization.
		runtime.SetBlockProfileRate(int(100 * time.Microsecond))
		runtime.SetMutexProfileFraction(20)
		return
	}

	if p := activeProfiler.Load(); p != nil {
		p.clear()
	}
	runtimepprof.StopCPUProfile()
	runtime.SetBlockProfileRate(0)
	runtime.SetMutexProfileFraction(0)
	debug.FreeOSMemory()
}

func pprofHandler(handler func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !pprofEnabled.Load() {
			http.NotFound(w, r)
			return
		}
		// Go's leak detector cannot follow gVisor Sleeper's uintptr wake-up
		// references. It marks live workers as _Gleaked, then their next
		// Goready fatals with "bad g->status in ready". Reject this profile
		// before pprof.Index can trigger the detection GC (including debug=2).
		if r.URL.Path == "/debug/pprof/goroutineleak" {
			http.Error(w, "goroutineleak profiling is unavailable: incompatible with gVisor worker wake-ups; use /debug/pprof/goroutine instead", http.StatusNotImplemented)
			return
		}
		handler(w, r)
	}
}

func RegisterHTTP(mux *http.ServeMux) {
	if !pprofConfigured.Load() {
		setPprofEnabled(true)
	}
	mux.HandleFunc("GET /debug/pprof/", pprofHandler(pprof.Index))
	mux.HandleFunc("GET /debug/pprof/cmdline", pprofHandler(pprof.Cmdline))
	mux.HandleFunc("GET /debug/pprof/profile", pprofHandler(pprof.Profile))
	mux.HandleFunc("GET /debug/pprof/symbol", pprofHandler(pprof.Symbol))
	mux.HandleFunc("GET /debug/pprof/trace", pprofHandler(pprof.Trace))

	HandleFunc(mux, nil, "OPTIONS /", func(w http.ResponseWriter, r *http.Request) error { return nil })

	handleFront(mux)
}

func handleFront(mux *http.ServeMux) {
	var ffs fs.FS
	edir := os.Getenv("EXTERNAL_WEB")
	if edir != "" {
		ffs = os.DirFS(edir)
	} else {
		ffs = yf.Content
	}

	cTypeMap := map[string]string{
		".html": "text/html",
		".js":   "text/javascript",
		".css":  "text/css",
		".png":  "image/png",
		".jpg":  "image/jpg",
		".jpeg": "image/jpeg",
		".svg":  "image/svg+xml",
		".ico":  "image/x-icon",
		".gif":  "image/gif",
		".webp": "image/webp",
		".json": "application/json",
		".txt":  "text/plain",
		".mp4":  "video/mp4",
		".mp3":  "audio/mpeg",
		".wav":  "audio/wav",
		".ogg":  "audio/ogg",
		".wasm": "application/wasm",
	}

	mux.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		f, err := ffs.Open(path)
		if err != nil {
			path = filepath.Join(path, "index.html")
			f, err = ffs.Open(path)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
		}
		_ = f.Close()

		ext := filepath.Ext(path)

		ctype := "application/octet-stream"

		if t, ok := cTypeMap[ext]; ok {
			ctype = t
		}

		w.Header().Set("Content-Type", ctype)

		http.ServeFileFS(w, r, ffs, path)
	}))
}
