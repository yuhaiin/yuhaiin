package macos

import (
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/app"
	"github.com/Asutorufa/yuhaiin/pkg/chore"
	"github.com/Asutorufa/yuhaiin/pkg/protos/tools"
)

type Closer interface {
	Close() error
}

type Opts struct {
	CloseFallback Closer
	TUN           *TUN   `json:"tun"`
	Savepath      string `json:"savepath"`
}

type TUN struct {
	Portal   string `json:"portal"`
	PortalV6 string `json:"portal_v6"`
	FD       int32  `json:"fd"`
	MTU      int32  `json:"mtu"`
}

var App atomic.Pointer[app.AppInstance]

func Start(opt *Opts) error {
	setting := chore.NewJsonDB(tools.PathGenerator.Config(opt.Savepath))

	app, err := app.Start(&app.StartOptions{
		ConfigPath:     opt.Savepath,
		BypassConfig:   setting,
		ResolverConfig: setting,
		InboundConfig:  fakeDB(opt, tools.PathGenerator.Config(opt.Savepath)),
		ChoreConfig:    setting,
	})
	if err != nil {
		return err
	}

	App.Store(app)
	return nil
}

func Stop() error {
	if app := App.Load(); app != nil {
		App.Store(nil)
		return app.Close()
	}
	return nil
}
