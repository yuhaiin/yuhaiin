package yuhaiin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/app"
	"github.com/Asutorufa/yuhaiin/pkg/chore"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/protos/api"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/tools"
	"github.com/Asutorufa/yuhaiin/pkg/utils/unit"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

var savepath string

func SetSavePath(p string) {
	savepath = p

	ms := filepath.Join(p, "yuhaiin_memory_store.json")
	legacyPreferenceStore = newMemoryStore(ms, true)
	appStore = newSQLitePreferenceStore(tools.PathGenerator.State(p), legacyPreferenceStore)
}

//go:generate go run generate.go

type App struct {
	server *http.Server

	mu      sync.Mutex
	started atomic.Bool
}

func (a *App) Start(opt *Opts) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.started.Load() {
		return errors.New("yuhaiin is already running")
	}

	if a.server != nil {
		_ = a.server.Close()
	}

	tsLogDir := path.Join(savepath, "tailscale", "logs")
	err := os.MkdirAll(tsLogDir, 0755)
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

	dialer.DefaultMarkSymbol = opt.TUN.SocketProtect.Protect
	applyRuntimeProfile()

	lis, err := net.Listen("tcp", net.JoinHostPort(ifOr(GetStore().GetBoolean(AllowLanKey), "0.0.0.0", "127.0.0.1"), "0"))
	if err != nil {
		return err
	}

	setting := newChoreDB()

	app, err := app.Start(&app.StartOptions{
		ConfigPath:     savepath,
		BypassConfig:   setting,
		ResolverConfig: setting,
		InboundConfig:  newInboundDB(setting, opt),
		ChoreConfig:    setting,
		BackupConfig:   setting,
		ProcessDumper:  processDumper,
	})
	if err != nil {
		_ = lis.Close()
		return err
	}

	_, portstr, err := net.SplitHostPort(lis.Addr().String())
	if err != nil {
		_ = app.Close()
		_ = lis.Close()
		return err
	}

	port, err := strconv.ParseUint(portstr, 10, 16)
	if err != nil {
		_ = app.Close()
		_ = lis.Close()
		return err
	}

	GetStore().PutInt(NewYuhaiinPortKey, int32(port))

	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Debug("http request", "host", r.Host, "method", r.Method, "path", r.URL.Path)
		app.Mux.ServeHTTP(w, r)
	})}

	a.server = server

	a.started.Store(true)

	go func() {
		defer a.started.Store(false)
		defer func() {
			if err := app.Close(); err != nil {
				log.Error("close app error", "err", err)
			}
		}()
		defer lis.Close()
		defer opt.CloseFallback.Close()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go a.notifyFlow(ctx, app, opt)

		if err := a.server.Serve(lis); err != nil {
			log.Error("yuhaiin serve failed", "err", err)
		}
	}()

	return nil
}

func (a *App) notifyFlow(ctx context.Context, app *app.AppInstance, opt *Opts) {
	if !GetStore().GetBoolean(NetworkSpeedKey) ||
		opt.NotifySpped == nil || !opt.NotifySpped.NotifyEnable() {
		return
	}

	ticker := time.NewTicker(time.Second*2 + time.Second/2)
	defer ticker.Stop()

	alreadyEmpty := false
	var last *api.TotalFlow
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			flow, err := app.Connections.Total(ctx, &emptypb.Empty{})
			if err != nil {
				log.Error("get connections failed", "err", err)
				continue
			}

			if last == nil {
				last = flow
				continue
			}

			dr := reduceUnit((flow.GetDownload() - last.GetDownload()) / 2)
			ur := reduceUnit((flow.GetUpload() - last.GetUpload()) / 2)
			if dr == emptyRate && ur == emptyRate {
				if alreadyEmpty {
					continue
				}
				alreadyEmpty = true
			} else if alreadyEmpty {
				alreadyEmpty = false
			}

			download, upload := reduceUnit(flow.GetDownload()), reduceUnit(flow.GetUpload())
			last = flow
			opt.NotifySpped.Notify(flowString(download, upload, ur, dr))
		}
	}
}

func (a *App) Stop() error {
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
		processLookupMode = ProcessLookupRulesOnlyValue
	}
	configuration.ProcessLookupMode.Store(processLookupMode)

	configuration.ExtendedStatsEnabled.Store(store.GetBoolean(AdvExtendedStatsKey))

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

func applyInboundRuntimeSettings(store Store, server *config.InboundConfig) {
	if server == nil {
		return
	}

	server.SetHijackDns(store.GetBoolean(DnsHijacking))
	server.SetHijackDnsFakeip(store.GetBoolean(DnsHijacking))

	sniff := server.GetSniff()
	if sniff == nil {
		sniff = &config.Sniff{}
	}
	sniff.SetEnabled(store.GetBoolean(SniffKey))
	server.SetSniff(sniff)
}

type androidInboundDB struct {
	base  chore.DB
	store Store
	opt   *Opts
}

func newInboundDB(base chore.DB, opt *Opts) chore.DB {
	return &androidInboundDB{
		base:  base,
		store: GetStore(),
		opt:   opt,
	}
}

func (a *androidInboundDB) View(f ...func(*config.Setting) error) error {
	return a.base.View(func(s *config.Setting) error {
		working := proto.CloneOf(s)
		a.applyRuntimeOverlay(working.GetServer())

		for _, fn := range f {
			if err := fn(working); err != nil {
				return err
			}
		}

		return nil
	})
}

func (a *androidInboundDB) Batch(f ...func(*config.Setting) error) error {
	return a.base.Batch(func(s *config.Setting) error {
		working := proto.CloneOf(s)
		a.applyRuntimeOverlay(working.GetServer())

		for _, fn := range f {
			if err := fn(working); err != nil {
				return err
			}
		}

		s.GetServer().SetHijackDns(working.GetServer().GetHijackDns())
		s.GetServer().SetHijackDnsFakeip(working.GetServer().GetHijackDnsFakeip())
		s.GetServer().SetSniff(working.GetServer().GetSniff())
		return nil
	})
}

func (a *androidInboundDB) Dir() string { return a.base.Dir() }

func (a *androidInboundDB) applyRuntimeOverlay(server *config.InboundConfig) {
	if server == nil {
		return
	}

	store := a.store
	var listenHost string = "127.0.0.1"
	if store.GetBoolean(AllowLanKey) {
		listenHost = "0.0.0.0"
	}

	inbounds := map[string]*config.Inbound{
		"mix": config.Inbound_builder{
			Name:    new("mix"),
			Enabled: new(store.GetInt(NewHTTPPortKey) != 0),
			Tcpudp: config.Tcpudp_builder{
				Host:    new(net.JoinHostPort(listenHost, fmt.Sprint(store.GetInt(NewHTTPPortKey)))),
				Control: config.TcpUdpControl_tcp_udp_control_all.Enum(),
			}.Build(),
			Mix: &config.Mixed{},
		}.Build(),
		"tun": config.Inbound_builder{
			Name:    new("tun"),
			Enabled: new(true),
			Empty:   &config.Empty{},
			Tun: config.Tun_builder{
				Name:          new(fmt.Sprintf("fd://%d", a.opt.TUN.FD)),
				Mtu:           new(a.opt.TUN.MTU),
				Portal:        new(a.opt.TUN.Portal),
				PortalV6:      new(a.opt.TUN.PortalV6),
				SkipMulticast: new(true),
				Route:         &config.Route{},
				Driver:        config.TunEndpointDriver(config.TunEndpointDriver_value[store.GetString(AdvTunDriverKey)]).Enum(),
			}.Build(),
		}.Build(),
	}

	server.SetInbounds(inbounds)
	applyInboundRuntimeSettings(store, server)
}

func newResolverDB() chore.DB {
	return chore.NewSqliteDB(tools.PathGenerator.State(savepath))
}

func newBypassDB() chore.DB {
	return chore.NewSqliteDB(tools.PathGenerator.State(savepath))
}

func newChoreDB() chore.DB {
	return chore.NewSqliteDB(tools.PathGenerator.State(savepath))
}

func newBackupDB() chore.DB {
	return chore.NewSqliteDB(tools.PathGenerator.State(savepath))
}
