package app

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/internal/config"
	"github.com/Asutorufa/yuhaiin/pkg/log/logasfmt"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
)

type MODE int

const (
	OTHERS MODE = 0
	BLOCK  MODE = 1
	DIRECT MODE = 2
	// PROXY  MODE = 3
	MAX MODE = 3
)

func (m MODE) String() string {
	switch m {
	case BLOCK:
		return "BLOCK"
	case DIRECT:
		return "DIRECT"
	default:
		return "PROXY"
	}
}

var Mode = map[string]MODE{
	"direct": DIRECT,
	// "proxy":  PROXY,
	"block": BLOCK,
}

//BypassManager .
type BypassManager struct {
	mapper func(string) MODE
	proxy  proxy.Proxy
	dialer proxy.Proxy
}

//NewBypassManager .
func NewBypassManager(conf *config.Config, p proxy.Proxy) *BypassManager {
	if p == nil {
		p = &proxy.DefaultProxy{}
	}

	m := &BypassManager{proxy: p}

	shunt, err := NewShunt(conf, WithProxy(m))
	if err != nil {
		log.Printf("create shunt failed: %v, disable bypass.\n", err)
	}

	conf.AddObserverAndExec(func(current, old *config.Setting) bool {
		return diffDNS(current.Dns.Local, old.Dns.Local)
	}, func(current *config.Setting) {
		m.dialer = direct.NewDirect(&net.Dialer{
			Timeout:  11 * time.Second,
			Resolver: getDNS(current.Dns.Local, nil).Resolver(),
		})
	})

	conf.AddObserverAndExec(func(current, old *config.Setting) bool {
		return current.Bypass.Enabled != old.Bypass.Enabled
	}, func(current *config.Setting) {
		if !current.Bypass.Enabled {
			m.mapper = func(s string) MODE {
				return OTHERS
			}
		} else {
			m.mapper = shunt.Get
		}
	})

	return m
}

//Conn get net.Conn by host
func (m *BypassManager) Conn(host string) (conn net.Conn, err error) {
	return m.marry(host).Conn(host)
}

func (m *BypassManager) PacketConn(host string) (conn net.PacketConn, err error) {
	return m.marry(host).PacketConn(host)
}

func (m *BypassManager) marry(host string) (p proxy.Proxy) {
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		return newErrProxy(fmt.Errorf("split host [%s] failed: %v", host, err))
	}

	mark := m.mapper(hostname)

	logasfmt.Printf("[%s] -> %v\n", host, mark)

	switch mark {
	case BLOCK:
		p = newErrProxy(fmt.Errorf("BLOCK: %v", host))
	case DIRECT:
		p = m.dialer
	default:
		p = m.proxy
	}

	return
}

type errProxy struct {
	err error
}

func newErrProxy(err error) proxy.Proxy {
	return &errProxy{err: err}
}

func (e *errProxy) Conn(string) (net.Conn, error) {
	return nil, e.err
}

func (e *errProxy) PacketConn(string) (net.PacketConn, error) {
	return nil, e.err
}
