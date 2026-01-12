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
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/protos/api"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/unit"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

var savepath string

func SetSavePath(p string) {
	savepath = p

	ms := filepath.Join(p, "yuhaiin_memory_store.json")
	msc := filepath.Join(p, "yuhaiin_memory_config_store.json")
	migrate(filepath.Join(p, "yuhaiin.badger.db"), ms, msc)
	memoryDB = newMemoryStore(ms, false)
	memoryConfigDB = newMemoryStore(msc, false)
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

	lis, err := net.Listen("tcp", net.JoinHostPort(ifOr(GetStore().GetBoolean(AllowLanKey), "0.0.0.0", "127.0.0.1"), "0"))
	if err != nil {
		return err
	}

	ms := newMemoryStore(filepath.Join(savepath, "yuhaiin_memory_config_store.json"), false)
	app, err := app.Start(&app.StartOptions{
		ConfigPath:     savepath,
		BypassConfig:   newBypassDB(ms),
		ResolverConfig: newResolverDB(ms),
		InboundConfig:  newInboundDB(ms, opt),
		ChoreConfig:    newChoreDB(ms),
		BackupConfig:   newBackupDB(ms),
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

	memoryConfigDB.PutInt(NewYuhaiinPortKey, int32(port))

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

func newInboundDB(ms *memoryStore, opt *Opts) *configDB[*config.InboundConfig] {
	store := GetStore()
	var listenHost string = "127.0.0.1"
	if store.GetBoolean(AllowLanKey) {
		listenHost = "0.0.0.0"
	}

	inbounds := map[string]*config.Inbound{
		"mix": config.Inbound_builder{
			Name:    proto.String("mix"),
			Enabled: proto.Bool(store.GetInt(NewHTTPPortKey) != 0),
			Tcpudp: config.Tcpudp_builder{
				Host:    proto.String(net.JoinHostPort(listenHost, fmt.Sprint(store.GetInt(NewHTTPPortKey)))),
				Control: config.TcpUdpControl_tcp_udp_control_all.Enum(),
			}.Build(),
			Mix: &config.Mixed{},
		}.Build(),
		"tun": config.Inbound_builder{
			Name:    proto.String("tun"),
			Enabled: proto.Bool(true),
			Empty:   &config.Empty{},
			Tun: config.Tun_builder{
				Name:          proto.String(fmt.Sprintf("fd://%d", opt.TUN.FD)),
				Mtu:           proto.Int32(opt.TUN.MTU),
				Portal:        proto.String(opt.TUN.Portal),
				PortalV6:      proto.String(opt.TUN.PortalV6),
				SkipMulticast: proto.Bool(true),
				Route:         &config.Route{},
				Driver:        config.TunEndpointDriver(config.TunEndpointDriver_value[store.GetString(AdvTunDriverKey)]).Enum(),
			}.Build(),
		}.Build(),
	}

	return newConfigDB(
		ms,
		"inbound_db",
		func(s *config.Setting) *config.InboundConfig {
			if s.GetServer() == nil {
				s.SetServer(config.InboundConfig_builder{
					HijackDns:       proto.Bool(true),
					HijackDnsFakeip: proto.Bool(true),
					Sniff: config.Sniff_builder{
						Enabled: proto.Bool(true),
					}.Build(),
				}.Build())
			}

			s.GetServer().SetInbounds(inbounds)

			return s.GetServer()
		},
		func(s *config.InboundConfig) *config.Setting {
			s.SetInbounds(inbounds)
			return config.Setting_builder{Server: s}.Build()
		},
	)
}

func newResolverDB(ms *memoryStore) *configDB[*config.DnsConfig] {
	return newConfigDB(
		ms,
		"resolver_db",
		func(s *config.Setting) *config.DnsConfig { return s.GetDns() },
		func(s *config.DnsConfig) *config.Setting { return config.Setting_builder{Dns: s}.Build() },
	)
}

func newBypassDB(ms *memoryStore) *configDB[*config.BypassConfig] {
	return newConfigDB(
		ms,
		"bypass_db",
		func(s *config.Setting) *config.BypassConfig { return s.GetBypass() },
		func(s *config.BypassConfig) *config.Setting { return config.Setting_builder{Bypass: s}.Build() },
	)
}

func newChoreDB(ms *memoryStore) *configDB[*config.Setting] {
	return newConfigDB(
		ms,
		"chore_db",
		func(s *config.Setting) *config.Setting { return s },
		func(s *config.Setting) *config.Setting { return s },
	)
}

func newBackupDB(ms *memoryStore) *configDB[*config.Setting] {
	return newConfigDB(
		ms,
		"backup_db",
		func(s *config.Setting) *config.Setting { return s },
		func(s *config.Setting) *config.Setting { return s },
	)
}
