package yuhaiin

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	yuhaiin "github.com/Asutorufa/yuhaiin/internal"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/node"
)

// GOPROXY=https://goproxy.cn,direct ANDROID_HOME=/mnt/data/ide/idea-Android-sdk/Sdk/ ANDROID_NDK_HOME=/mnt/dataHDD/android-ndk/android-ndk-r23b gomobile bind -target=android/amd64,android/arm64 -ldflags='-s -w' -trimpath -v -o yuhaiin.aar ./

type App struct {
	nodes *node.Nodes
	lis   *http.Server

	lock    sync.Mutex
	started atomic.Bool
}

func (a *App) Start(opt *Opts) error {
	a.lock.Lock()
	defer a.lock.Unlock()

	if a.started.Load() {
		return errors.New("yuhaiin is already running")
	}

	errChan := make(chan error)

	go func() {

		dialer.DefaultMarkSymbol = opt.TUN.SocketProtect.Protect

		resp, err := yuhaiin.Start(
			yuhaiin.StartOpt{
				ConfigPath:    opt.Savepath,
				Setting:       fakeSetting(opt, yuhaiin.PathGenerator.Config(opt.Savepath)),
				Host:          opt.Host,
				ProcessDumper: NewUidDumper(opt.TUN.UidDumper),
			})
		if err != nil {
			errChan <- err
			return
		}
		defer resp.Close()

		a.nodes = resp.Node
		lis := &http.Server{
			Handler: resp.Mux,
		}
		defer lis.Close()

		a.lis = lis
		a.started.Store(true)
		defer a.started.Store(false)

		close(errChan)

		a.lis.Serve(resp.HttpListener)
	}()

	return <-errChan
}

func (a *App) Stop() error {
	a.lock.Lock()
	defer a.lock.Unlock()

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
	if a.started.Load() && a.nodes == nil {
		hc = http.DefaultClient.Do
	} else {
		hc = a.nodes.Do
	}

	req, err := http.NewRequest(http.MethodGet, link, nil)
	if err != nil {
		log.Errorln(err)
		return err
	}

	r, err := hc(req)
	if err != nil {
		log.Errorln("get new bypass by proxy failed:", err)
		return err
	}
	defer r.Body.Close()

	data, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "yuhaiin.conf"), data, os.ModePerm)
}
