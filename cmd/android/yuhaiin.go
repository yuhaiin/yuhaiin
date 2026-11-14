package yuhaiin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/app"
	recovery "github.com/Asutorufa/yuhaiin/pkg/app/backup/recovery"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	managementtls "github.com/Asutorufa/yuhaiin/pkg/management/tls"
	"github.com/Asutorufa/yuhaiin/pkg/migrate"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
	"github.com/Asutorufa/yuhaiin/pkg/utils/unit"
)

var savepath string

func SetSavePath(p string) {
	savepath = p
	if old, ok := appStore.(*sqlitePreferenceStore); ok {
		_ = old.close()
	}
	appStore = newSQLitePreferenceStore(paths.PathGenerator.State(p))
	log.Info("android sqlite backend selected", "backend", storagesqlite.BackendName(), "driver", storagesqlite.DriverName())
}

type App struct {
	server    *http.Server
	instance  *app.AppInstance
	startedAt time.Time

	mu      sync.Mutex
	started atomic.Bool

	startCancelMu sync.Mutex
	startCancel   context.CancelFunc

	vpnMu         sync.Mutex
	contracts     atomic.Pointer[inbound.ContractStore]
	platformToken string
	port          int32
	https         bool
}

func (a *App) contractStore() *inbound.ContractStore { return a.contracts.Load() }

func (a *App) instanceSnapshot() *app.AppInstance {
	if !a.started.Load() {
		return nil
	}
	return a.instance
}

// PlatformToken is the per-start secret that authorizes Android platform API
// calls. Only the in-app WebView receives it, as an HttpOnly cookie.
func (a *App) PlatformToken() string {
	if !a.Running() {
		return ""
	}
	return a.platformToken
}

// HTTPPort returns the management port of the running core, or zero.
func (a *App) HTTPPort() int32 {
	if !a.Running() {
		return 0
	}
	return a.port
}

func listenerPortOf(lis net.Listener) int32 {
	if addr, ok := lis.Addr().(*net.TCPAddr); ok {
		return int32(addr.Port)
	}
	return 0
}

func (a *App) setStartCancel(cancel context.CancelFunc) {
	a.startCancelMu.Lock()
	a.startCancel = cancel
	a.startCancelMu.Unlock()
}

func (a *App) clearStartCancel() {
	a.startCancelMu.Lock()
	a.startCancel = nil
	a.startCancelMu.Unlock()
}

func (a *App) cancelStart() {
	a.startCancelMu.Lock()
	cancel := a.startCancel
	a.startCancelMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (a *App) Start(opt *Opts) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.started.Load() {
		return errors.New("yuhaiin is already running")
	}

	configLock, err := lockConfiguration()
	if err != nil {
		return err
	}
	lockTransferred := false
	defer func() {
		if !lockTransferred {
			_ = configLock.Close()
		}
	}()
	if err := recovery.GuardMaintenance(savepath); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	a.setStartCancel(cancel)
	defer func() {
		cancel()
		a.clearStartCancel()
	}()

	if a.server != nil {
		_ = a.server.Close()
	}

	tsLogDir := path.Join(savepath, "tailscale", "logs")
	err = os.MkdirAll(tsLogDir, 0755)
	if err != nil {
		log.Warn("create ts log dir failed:", "err", err)
	}
	os.Setenv("TS_LOGS_DIR", tsLogDir)

	// current make all go system connections from io.github.asutorufa.yuhaiin directly
	// so we don't need to set it here
	// if we use fake ip, the protect will make tailscale can't connect to controlplane
	//
	// SetAndroidProtectFunc = func(sp SocketProtect) {
	// 	netns.SetAndroidProtectFunc(func(fd int) error {
	// 		if !sp.Protect(int32(fd)) {
	// 			// TODO(bradfitz): return an error back up to netns if this fails, once
	// 			// we've had some experience with this and analyzed the logs over a wide
	// 			// range of Android phones. For now we're being paranoid and conservative
	// 			// and do the JNI call to protect best effort, only logging if it fails.
	// 			// The risk of returning an error is that it breaks users on some Android
	// 			// versions even when they're not using exit nodes. I'd rather the
	// 			// relatively few number of exit node users file bug reports if Tailscale
	// 			// doesn't work and then we can look for this log print.
	// 			log.Warn("[unexpected] VpnService.protect(%d) returned false", fd)
	// 		}
	// 		return nil // even on error. see big TODO above.
	// 	})
	// }

	// Socket protection and Network binding are installed with the core, not
	// with the VPN: the VPN is created later, on demand, and the adapters
	// return "no VPN" results while it is down.
	dialer.SetSocketProtector(nil)
	dialer.SocketNetworkBinder = nil
	if opt.TUN != nil && opt.TUN.SocketProtect != nil {
		protect := opt.TUN.SocketProtect
		dialer.SetSocketProtector(&dialer.SocketProtector{
			Method: "VpnService.protect",
			Protect: func(fd int32) error {
				if !protect.Protect(fd) {
					return errors.New("VpnService.protect returned false")
				}
				return nil
			},
		})
	}
	if opt.TUN != nil && opt.TUN.SocketBind != nil {
		bind := opt.TUN.SocketBind
		dialer.SocketNetworkBinder = func(fd int32, iface string) (string, error) {
			handle := bind.Bind(fd, iface)
			if handle < 0 {
				return "", fmt.Errorf("bind protected socket to Android Network failed")
			}
			if handle == 0 {
				return "", nil
			}
			return "android:" + strconv.FormatInt(handle, 10), nil
		}
	}
	applyRuntimeProfile()

	// Initialize SQLite schema before reading Android preferences.
	setting := migrate.NewStateDB(paths.PathGenerator.State(savepath))
	if err := setting.Migrate(ctx); err != nil {
		_ = setting.Close()
		return fmt.Errorf("migrate Android state before startup: %w", err)
	}
	// The core starts without a TUN descriptor. The Android VPN is a TUN
	// inbound on the platform device, created when that inbound is enabled.
	stateDB, err := setting.SQLDB(ctx)
	if err != nil {
		_ = setting.Close()
		return fmt.Errorf("open Android state before startup: %w", err)
	}
	if err := ensureAndroidTUNInbound(ctx, stateDB); err != nil {
		_ = setting.Close()
		return fmt.Errorf("prepare Android TUN inbound before startup: %w", err)
	}

	if err := ctx.Err(); err != nil {
		_ = setting.Close()
		return err
	}

	lis, err := listenAndroidHTTP()
	if err != nil {
		_ = setting.Close()
		return err
	}

	if err := ctx.Err(); err != nil {
		_ = lis.Close()
		_ = setting.Close()
		return err
	}

	app, err := app.Start(&app.StartOptions{
		// Native single-user mode deliberately omits the identity middleware.
		Context:            ctx,
		ConfigPath:         savepath,
		StateStore:         setting,
		AllowLANManagement: GetStore().GetBoolean(AllowLanKey),
		ProcessDumper:      processDumper,
	})
	if err != nil {
		_ = lis.Close()
		return err
	}
	if err := ctx.Err(); err != nil {
		_ = lis.Close()
		_ = app.Close()
		return err
	}

	token, err := newPlatformToken()
	if err != nil {
		_ = lis.Close()
		_ = app.Close()
		return err
	}
	contracts := inbound.NewContractStore(plainstore.NewInboundStore(stateDB), app.Inbound)
	platform := newPlatformAPI(a, token)
	server, serverListener := newAndroidHTTPServer(platform.wrap(app.Mux), lis)

	a.server = server
	a.instance = app
	a.contracts.Store(contracts)
	a.platformToken = token
	a.port = listenerPortOf(lis)
	a.https = server.TLSConfig != nil
	a.startedAt = time.Now()
	activeAppMu.Lock()
	activeApp = a
	activeAppMu.Unlock()

	a.started.Store(true)
	lockTransferred = true

	go func() {
		defer a.started.Store(false)
		defer func() {
			a.contracts.Store(nil)
			activeAppMu.Lock()
			if activeApp == a {
				activeApp = nil
			}
			activeAppMu.Unlock()
		}()
		defer func() { _ = configLock.Close() }()
		defer func() {
			if err := app.Close(); err != nil {
				log.Error("close app error", "err", err)
			}
		}()
		defer serverListener.Close()
		defer func() {
			if opt.CloseFallback != nil {
				_ = opt.CloseFallback.Close()
			}
		}()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go a.notifyFlow(ctx, app, opt)

		if err := server.Serve(serverListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("yuhaiin serve failed", "err", err)
		}
	}()

	return nil
}

var managementTLSDir string

// SetManagementTLSDir sets the private directory that holds the persistent
// self-signed management certificate and key. Android passes an internal,
// non-backed-up app directory. Without it the server stays HTTP-only.
func SetManagementTLSDir(dir string) {
	managementTLSDir = dir
}

// androidHTTPHeaderTimeout bounds request headers and, through net/http, the
// TLS handshake of HTTPS clients. It does not limit streaming responses.
const androidHTTPHeaderTimeout = 30 * time.Second

// newAndroidHTTPServer serves handler on lis. When the management certificate
// is available, the same port also accepts HTTPS (TLS 1.2+, h2 and HTTP/1.1).
// Cleartext requests are served unchanged, so the in-app WebView and API keep
// using http://127.0.0.1:<port>. The bind address, and therefore LAN exposure,
// is decided by listenAndroidHTTP alone.
func newAndroidHTTPServer(handler http.Handler, lis net.Listener) (*http.Server, net.Listener) {
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Debug("http request", "tls", r.TLS != nil, "host", r.Host, "method", r.Method, "path", r.URL.Path)
			handler.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: androidHTTPHeaderTimeout,
	}
	if managementTLSDir == "" {
		log.Info("android management HTTPS disabled: certificate directory is not configured")
		return server, lis
	}
	certificate, fingerprint, created, err := managementtls.LoadOrCreate(managementTLSDir, []string{"localhost", "127.0.0.1", "::1"})
	if err != nil {
		log.Warn("android management HTTPS disabled: certificate unavailable", "err", err)
		return server, lis
	}
	if created {
		log.Info("android management HTTPS generated a self-signed certificate", "sha256", fingerprint)
	} else {
		log.Info("android management HTTPS enabled", "sha256", fingerprint)
	}
	server.TLSConfig = managementtls.ServerConfig(certificate)
	return server, managementtls.NewProtocolListener(lis, server.TLSConfig)
}

func listenAndroidHTTP() (net.Listener, error) {
	allowLAN := GetStore().GetBoolean(AllowLanKey)
	preferredPort := GetStore().GetInt(NewYuhaiinPortKey)
	host := ifOr(allowLAN, "0.0.0.0", "127.0.0.1")
	var listener net.Listener
	var err error
	if preferredPort > 0 && preferredPort <= 65535 {
		listener, err = net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(int(preferredPort))))
		if err == nil {
			log.Info("android http listener using preferred port", "port", preferredPort)
		} else {
			log.Warn("preferred android http port unavailable, using a random port", "port", preferredPort, "err", err)
		}
	}

	if listener == nil {
		listener, err = net.Listen("tcp", net.JoinHostPort(host, "0"))
		if err != nil {
			return nil, err
		}
	}

	_, portstr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	port, err := strconv.ParseUint(portstr, 10, 16)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	GetStore().PutInt(NewYuhaiinPortKey, int32(port))

	return listener, nil
}

func (a *App) notifyFlow(ctx context.Context, app *app.AppInstance, opt *Opts) {
	if !GetStore().GetBoolean(NetworkSpeedKey) ||
		opt.NotifySpped == nil || !opt.NotifySpped.NotifyEnable() {
		return
	}

	ticker := time.NewTicker(time.Second*2 + time.Second/2)
	defer ticker.Stop()

	alreadyEmpty := false
	var lastDownloadBytes, lastUploadBytes uint64
	haveLast := false
	var lastSample time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case sampleTime := <-ticker.C:
			// The notification only needs totals, not the per-connection counter
			// map and decimal strings built by the monitor API.
			var downloadBytes, uploadBytes uint64
			if totals, ok := app.Connections.(interface{ FlowTotals() (uint64, uint64) }); ok {
				downloadBytes, uploadBytes = totals.FlowTotals()
			} else {
				flow, err := app.Connections.Total(ctx)
				if err != nil {
					log.Error("get connections failed", "err", err)
					continue
				}
				downloadBytes, uploadBytes = connectionFlowValue(flow.Download), connectionFlowValue(flow.Upload)
			}
			if !haveLast {
				lastDownloadBytes, lastUploadBytes = downloadBytes, uploadBytes
				haveLast = true
				lastSample = sampleTime
				continue
			}

			seconds := sampleTime.Sub(lastSample).Seconds()
			dr := reduceUnit(uint64(float64(downloadBytes-lastDownloadBytes) / seconds))
			ur := reduceUnit(uint64(float64(uploadBytes-lastUploadBytes) / seconds))
			lastSample = sampleTime
			if dr == emptyRate && ur == emptyRate {
				if alreadyEmpty {
					lastDownloadBytes, lastUploadBytes = downloadBytes, uploadBytes
					continue
				}
				alreadyEmpty = true
			} else if alreadyEmpty {
				alreadyEmpty = false
			}

			download, upload := reduceUnit(downloadBytes), reduceUnit(uploadBytes)
			lastDownloadBytes, lastUploadBytes = downloadBytes, uploadBytes
			opt.NotifySpped.Notify(flowString(download, upload, ur, dr))
		}
	}
}

func connectionFlowValue(v string) uint64 {
	n, _ := strconv.ParseUint(v, 10, 64)
	return n
}

func (a *App) Stop() error {
	// Signal an in-flight Start before waiting for the lifecycle lock. Start owns
	// the lock while it initializes storage and runtime state, so cancellation
	// must not depend on acquiring the same lock first.
	a.cancelStart()

	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.Running() {
		return nil
	}

	if a.server != nil {
		err := a.server.Close()
		if err != nil {
			return err
		}
	}

	for a.Running() {
		runtime.Gosched()
	}

	a.server = nil
	a.instance = nil

	return nil
}

func (a *App) Running() bool { return a.started.Load() }

var emptyRate = fmt.Sprintf("%.2f %v", 0.00, unit.B)

func reduceUnit(v uint64) string {
	x, unit := unit.ReducedUnit(float64(v))
	return fmt.Sprintf("%.2f %v", x, unit)
}

func flowString(download, upload, ur, dr string) string {
	return fmt.Sprintf(
		"↓(%s): %s/S ↑(%s): %s/S",
		download,
		dr,
		upload,
		ur,
	)
}

func applyRuntimeProfile() {
	store := GetStore()

	batteryProfile := store.GetString(AdvBatteryProfileKey)
	if batteryProfile == "" {
		batteryProfile = BatteryProfileBalanced
	}
	configuration.BatteryProfile.Store(batteryProfile)

	processLookupMode := store.GetString(AdvProcessLookupModeKey)
	if processLookupMode == "" {
		processLookupMode = ProcessLookupAlwaysValue
	}
	configuration.ProcessLookupMode.Store(processLookupMode)

	udpIdleProfile := store.GetString(AdvUDPIdleProfileKey)
	if udpIdleProfile == "" {
		udpIdleProfile = batteryProfile
	}

	switch udpIdleProfile {
	case BatteryProfileBatterySaver:
		configuration.UDPIdleTimeout.Store(time.Minute * 5)
		configuration.UDPMappingTimeout.Store(time.Minute * 10)
	case BatteryProfilePerformance:
		configuration.UDPIdleTimeout.Store((time.Minute * 3) / 2)
		configuration.UDPMappingTimeout.Store(time.Minute * 5)
	case BatteryProfileDiagnostic:
		configuration.UDPIdleTimeout.Store((time.Minute * 3) / 2)
		configuration.UDPMappingTimeout.Store(time.Minute * 5)
	default:
		configuration.UDPIdleTimeout.Store(time.Minute * 3)
		configuration.UDPMappingTimeout.Store(time.Minute * 6)
	}
}
