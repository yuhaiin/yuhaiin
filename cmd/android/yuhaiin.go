package yuhaiin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/internal/app"
	"github.com/Asutorufa/yuhaiin/internal/appapi"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	service "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/unit"
	"google.golang.org/protobuf/types/known/emptypb"
)

//go:generate go run generate.go

type App struct {
	app *appapi.Components
	lis *http.Server

	mu      sync.Mutex
	started atomic.Bool
}

func (a *App) Start(opt *Opts) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.started.Load() {
		return errors.New("yuhaiin is already running")
	}

	errChan := make(chan error)

	go func() {
		defer a.started.Store(false)

		dialer.DefaultMarkSymbol = opt.TUN.SocketProtect.Protect

		app, err := app.Start(
			appapi.Start{
				ConfigPath: opt.Savepath,
				Setting:    fakeSetting(opt, app.PathGenerator.Config(opt.Savepath)),
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

			dr := reduceUnit((flow.Download - last.Download) / 2)
			ur := reduceUnit((flow.Upload - last.Upload) / 2)
			if dr == emptyRate && ur == emptyRate {
				if alreadyEmpty {
					continue
				}
				alreadyEmpty = true
			} else if alreadyEmpty {
				alreadyEmpty = false
			}

			download, upload := reduceUnit(flow.Download), reduceUnit(flow.Upload)
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
	if !a.Running() || a.app == nil || a.app.Rc == nil {
		return fmt.Errorf("proxy service is not start")
	}

	a.app.Setting.(*fakeSettings).updateRemoteUrl(link)
	_, err := a.app.Rc.Reload(context.TODO(), &emptypb.Empty{})
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
