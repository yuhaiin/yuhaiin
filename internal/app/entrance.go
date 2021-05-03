package app

import (
	"fmt"
	"log"
	"net"

	"github.com/Asutorufa/yuhaiin/internal/config"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
)

type Entrance struct {
	config      *config.Config
	localListen *Listener
	shunt       *Shunt
	dir         string
	connManager *connManager
	p           proxy.Proxy
}

func NewEntrance(dir string, p proxy.Proxy) (e *Entrance, err error) {
	e = &Entrance{dir: dir, p: p}

	e.config, err = config.NewConfig(dir)
	if err != nil {
		return nil, fmt.Errorf("get config failed: %v", err)
	}

	s := e.config.GetSetting()

	e.shunt, err = NewShunt(s.Bypass.BypassFile, getDNS(s.DNS).LookupIP)
	if err != nil {
		return nil, fmt.Errorf("create shunt failed: %v", err)
	}

	e.connManager = newConnManager(e.getBypass())
	e.addObserver()
	return e, nil
}

func (e *Entrance) Start() (err error) {
	// initialize Local Servers Controller
	e.localListen, err = NewListener(e.config.GetSetting().GetProxy(), e.connManager)
	if err != nil {
		return fmt.Errorf("create local listener failed: %v", err)
	}
	return nil
}

func (e *Entrance) SetConFig(c *config.Setting) (err error) {
	err = e.config.Apply(c)
	if err != nil {
		return fmt.Errorf("apply config failed: %v", err)
	}
	return nil
}

func (e *Entrance) addObserver() {
	e.config.AddObserver(func(current, old *config.Setting) {
		if current.Bypass.BypassFile != old.Bypass.BypassFile {
			err := e.shunt.SetFile(current.Bypass.BypassFile)
			if err != nil {
				log.Printf("shunt set file failed: %v", err)
			}
		}
	})

	e.config.AddObserver(func(current, old *config.Setting) {
		if diffDNS(current.DNS, old.DNS) {
			e.shunt.SetLookup(getDNS(current.DNS).LookupIP)
		}
	})

	e.config.AddObserver(func(current, old *config.Setting) {
		if diffDNS(current.LocalDNS, old.LocalDNS) ||
			current.Bypass.Enabled != old.Bypass.Enabled {
			e.connManager.SetProxy(e.getBypass())
		}
	})

	e.config.AddObserver(func(current, _ *config.Setting) {
		e.localListen.SetServer(e.config.GetSetting().GetProxy())
	})
}

func diffDNS(old, new *config.DNS) bool {
	if old.Host != new.Host {
		return true
	}
	if old.DOH != new.DOH {
		return true
	}
	if old.Subnet != new.Subnet {
		return true
	}
	return false
}

func (e *Entrance) RefreshMapping() error {
	return e.shunt.RefreshMapping()
}

func getDNS(dc *config.DNS) dns.DNS {
	if dc.DOH {
		return dns.NewDoH(dc.Host, toSubnet(dc.Subnet), nil)
	}
	return dns.NewDNS(dc.Host, toSubnet(dc.Subnet), nil)
}

func toSubnet(s string) *net.IPNet {
	_, subnet, err := net.ParseCIDR(s)
	if err != nil {
		if net.ParseIP(s).To4() != nil {
			_, subnet, _ = net.ParseCIDR(s + "/32")
		}

		if net.ParseIP(s).To16() != nil {
			_, subnet, _ = net.ParseCIDR(s + "/128")
		}
	}
	return subnet
}

func (e *Entrance) GetConfig() (*config.Setting, error) {
	return e.config.GetSetting(), nil
}

func (e *Entrance) getBypass() proxy.Proxy {
	if !e.config.GetSetting().Bypass.Enabled {
		return NewBypassManager(nil, getDNS(e.config.GetSetting().GetLocalDNS()), e.p)
	} else {
		return NewBypassManager(e.shunt, getDNS(e.config.GetSetting().GetLocalDNS()), e.p)
	}
}

func (e *Entrance) GetDownload() uint64 {
	return e.connManager.GetDownload()
}

func (e *Entrance) GetUpload() uint64 {
	return e.connManager.GetUpload()
}
