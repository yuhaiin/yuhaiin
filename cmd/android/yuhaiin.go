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
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/internal/app"
	"github.com/Asutorufa/yuhaiin/internal/appapi"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	bypass "github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	service "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/unit"
	"google.golang.org/protobuf/types/known/emptypb"
	"tailscale.com/net/netmon"
)

var SetAndroidProtectFunc func(SocketProtect)

//go:generate go run generate.go

type App struct {
	app *appapi.Components
	lis *http.Server

	mu      sync.Mutex
	started atomic.Bool
}

func newResolverDB() *configDB[*dns.DnsConfig] {
	return newConfigDB(
		"resolver_db",
		func(s *pc.Setting) *dns.DnsConfig { return s.GetDns() },
		func(s *dns.DnsConfig) *pc.Setting { return pc.Setting_builder{Dns: s}.Build() },
	)
}

func newBypassDB() *configDB[*bypass.Config] {
	return newConfigDB(
		"bypass_db",
		func(s *pc.Setting) *bypass.Config { return s.GetBypass() },
		func(s *bypass.Config) *pc.Setting { return pc.Setting_builder{Bypass: s}.Build() },
	)
}

func (a *App) Start(opt *Opts) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.started.Load() {
		return errors.New("yuhaiin is already running")
	}

	netmon.RegisterInterfaceGetter(func() ([]netmon.Interface, error) { return getInterfaces(opt.Interfaces) })

	if SetAndroidProtectFunc != nil {
		SetAndroidProtectFunc(opt.TUN.SocketProtect)
	}

	tsLogDir := path.Join(opt.Savepath, "tailscale", "logs")
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

	errChan := make(chan error)

	go func() {
		defer a.started.Store(false)

		dialer.DefaultMarkSymbol = opt.TUN.SocketProtect.Protect

		fakedb := fakeDB(opt, app.PathGenerator.Config(opt.Savepath))

		app, err := app.Start(
			appapi.Start{
				ConfigPath:     opt.Savepath,
				BypassConfig:   newBypassDB(),
				ResolverConfig: newResolverDB(),
				InboundConfig:  fakedb,
				ChoreConfig:    fakedb,
				Host: net.JoinHostPort(ifOr(GetStore("Default").GetBoolean(AllowLanKey), "0.0.0.0", "127.0.0.1"),
					fmt.Sprint(GetStore("Default").GetInt(NewYuhaiinPortKey))),
				ProcessDumper: NewUidDumper(opt.TUN.UidDumper),
			})
		if err != nil {
			errChan <- err
			return
		}
		defer app.Close()

		a.app = app

		lis := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Debug("http request", "host", r.Host, "method", r.Method, "path", r.URL.Path)
			app.Mux.ServeHTTP(w, r)
		})}
		defer lis.Close()

		a.lis = lis
		a.started.Store(true)

		close(errChan)
		defer opt.CloseFallback.Close()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go a.notifyFlow(ctx, app, opt)

		if err := a.lis.Serve(app.HttpListener); err != nil {
			log.Error("yuhaiin serve failed", "err", err)
		}
	}()

	return <-errChan
}

func (a *App) notifyFlow(ctx context.Context, app *appapi.Components, opt *Opts) {
	if !GetStore("Default").GetBoolean(NetworkSpeedKey) ||
		opt.NotifySpped == nil || !opt.NotifySpped.NotifyEnable() {
		return
	}

	ticker := time.NewTicker(time.Second*2 + time.Second/2)
	defer ticker.Stop()

	alreadyEmpty := false
	var last *service.TotalFlow
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

	if a.lis != nil {
		err := a.lis.Close()
		if err != nil {
			return err
		}
	}

	for a.Running() {
		runtime.Gosched()
	}

	a.app = nil
	a.lis = nil

	return nil
}

func (a *App) Running() bool { return a.started.Load() }

func (a *App) SaveNewBypass(link string) error {
	if !a.Running() || a.app == nil || a.app.RuleController == nil {
		return fmt.Errorf("proxy service is not start")
	}

	a.app.Setting.(*fakeSettings).updateRemoteUrl(link)
	_, err := a.app.RuleController.Reload(context.TODO(), &emptypb.Empty{})
	return err
}

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
