package yuhaiin

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/internal/app"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
)

// GOPROXY=https://goproxy.cn,direct ANDROID_HOME=/mnt/data/ide/idea-Android-sdk/Sdk/ ANDROID_NDK_HOME=/mnt/dataHDD/android-ndk/android-ndk-r23b gomobile bind -target=android/amd64,android/arm64 -ldflags='-s -w' -trimpath -v -o yuhaiin.aar ./

type App struct {
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

		dialer.DefaultMarkSymbol = opt.TUN.SocketProtect.Protect

		err := app.Start(
			app.StartOpt{
				ConfigPath:    opt.Savepath,
				Setting:       fakeSetting(opt, app.PathGenerator.Config(opt.Savepath)),
				Host:          opt.Host,
				ProcessDumper: NewUidDumper(opt.TUN.UidDumper),
			})
		if err != nil {
			errChan <- err
			return
		}
		defer app.Close()

		lis := &http.Server{Handler: app.Mux}
		defer lis.Close()

		a.lis = lis
		a.started.Store(true)
		defer a.started.Store(false)

		close(errChan)
		defer opt.CloseFallback.Close()

		a.lis.Serve(app.HttpListener)
	}()

	return <-errChan
}

func (a *App) Stop() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.started.Load() {
		return nil
	}

	if a.lis != nil {
		err := a.lis.Close()
		if err != nil {
			return err
		}
	}

	for a.started.Load() {
	}

	return nil
}

func (a *App) Running() bool { return a.started.Load() }

func (a *App) SaveNewBypass(link, dir string) error {
	var hc func(*http.Request) (*http.Response, error)
	if a.started.Load() && app.Node == nil {
		hc = http.DefaultClient.Do
	} else {
		hc = app.Node.Do
	}

	req, err := http.NewRequest(http.MethodGet, link, nil)
	if err != nil {
		log.Error("create get bypass file request failed", "err", err)
		return err
	}

	r, err := hc(req)
	if err != nil {
		log.Error("get new bypass by proxy failed", "err", err)
		return err
	}
	defer r.Body.Close()

	data, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "yuhaiin.conf"), data, os.ModePerm)
}
