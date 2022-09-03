package yuhaiin

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	yuhaiin "github.com/Asutorufa/yuhaiin/internal"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/node"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

// GOPROXY=https://goproxy.cn,direct ANDROID_HOME=/mnt/data/ide/idea-Android-sdk/Sdk/ ANDROID_NDK_HOME=/mnt/dataHDD/android-ndk/android-ndk-r23b gomobile bind -target=android/amd64,android/arm64 -ldflags='-s -w' -trimpath -v -o yuhaiin.aar ./

type App struct {
	nodes *node.Nodes
	lis   *http.Server

	lock   sync.Mutex
	closed chan struct{}
}

func (a *App) Start(opt *Opts) error {
	a.lock.Lock()
	defer a.lock.Unlock()
	select {
	case <-a.closed:
	default:
		if a.closed != nil {
			return errors.New("yuhaiin is already running")
		}
	}

	errChan := make(chan error)
	defer close(errChan)

	go func() {
		pc := yuhaiin.PathConfig(opt.Savepath)
		fakeSetting := fakeSetting(opt, pc.Config)

		resp, err := yuhaiin.Start(yuhaiin.StartOpt{
			PathConfig: pc,
			Setting:    fakeSetting,
			Host:       opt.Host,
			Rules: map[protoconfig.BypassMode]string{
				protoconfig.Bypass_block:  opt.Bypass.Block,
				protoconfig.Bypass_proxy:  opt.Bypass.Proxy,
				protoconfig.Bypass_direct: opt.Bypass.Direct,
			},
			UidDumper: NewUidDumper(opt.TUN.UidDumper),
		})
		if err != nil {
			errChan <- err
			return
		}
		a.nodes = resp.Node
		a.lis = &http.Server{Handler: resp.Mux}
		a.closed = make(chan struct{})
		defer func() {
			a.nodes = nil
			resp.Close()
			a.lis.Close()
			a.lis = nil
			close(a.closed)
		}()

		errChan <- nil

		a.lis.Serve(resp.HttpListener)
	}()
	return <-errChan
}

func (a *App) Stop() error {
	a.lock.Lock()
	defer a.lock.Unlock()

	if a.closed == nil {
		return nil
	}
	var err error
	if a.lis != nil {
		err = a.lis.Close()
	}
	<-a.closed
	return err
}

func (a *App) Running() bool {
	select {
	case <-a.closed:
		return false
	default:
		if a.closed == nil {
			return false
		}
		return true
	}
}

func (a *App) SaveNewBypass(link, dir string) error {
	var hc func(*http.Request) (*http.Response, error)
	if a.nodes == nil {
		hc = http.DefaultClient.Do
	} else {
		hc = a.nodes.Do
	}

	req, err := http.NewRequest(http.MethodGet, link, nil)
	if err != nil {
		log.Errorln(err)
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
