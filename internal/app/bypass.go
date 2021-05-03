package app

import (
	"fmt"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/internal/app/component"
	"github.com/Asutorufa/yuhaiin/internal/config"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
)

//BypassManager .
type BypassManager struct {
	mapper component.Mapper
	proxy  proxy.Proxy
	dialer *net.Dialer
	bypass bool
}

//NewBypassManager .
func NewBypassManager(conf *config.Config, p proxy.Proxy) *BypassManager {
	if p == nil {
		p = &proxy.DefaultProxy{}
	}

	shunt, err := NewShunt(conf)
	if err != nil {
		fmt.Println("create shunt failed, disable bypass.")
	}

	m := &BypassManager{proxy: p, mapper: shunt}

	_ = conf.Exec(
		func(s *config.Setting) error {
			m.dialer = &net.Dialer{
				Timeout:  11 * time.Second,
				Resolver: getDNS(s.LocalDNS).Resolver(),
			}
			m.bypass = s.Bypass.Enabled
			return nil
		})

	conf.AddObserver(func(current, old *config.Setting) {
		if diffDNS(old.LocalDNS, current.LocalDNS) {
			m.dialer = &net.Dialer{
				Timeout:  11 * time.Second,
				Resolver: getDNS(current.LocalDNS).Resolver(),
			}
		}
	})

	conf.AddObserver(func(current, old *config.Setting) {
		if current.Bypass.Enabled != old.Bypass.Enabled {
			m.bypass = current.Bypass.Enabled
		}
	})

	return m
}

//Conn get net.Conn by host
func (m *BypassManager) Conn(host string) (conn net.Conn, err error) {
	resp, err := m.marry(host)
	if err != nil {
		return nil, fmt.Errorf("map failed: %v", err)
	}

	return resp.Conn(host)

}

func (m *BypassManager) PacketConn(host string) (conn net.PacketConn, err error) {
	resp, err := m.marry(host)
	if err != nil {
		return nil, fmt.Errorf("map failed: %v", err)
	}
	return resp.PacketConn(host)
}

func (m *BypassManager) marry(host string) (p proxy.Proxy, err error) {
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		return nil, fmt.Errorf("split host [%s] failed: %v", host, err)
	}

	mark := component.OTHERS
	if m.mapper != nil && m.bypass {
		c := m.mapper.Get(hostname)
		mark = c.Mark
	}

	fmt.Printf("[%s] ->  mode: %s\n", host, component.ModeMapping[mark])

	switch mark {
	case component.BLOCK:
		err = fmt.Errorf("block: %v", host)
	case component.DIRECT:
		p = &direct{dialer: m.dialer}
	case component.OTHERS:
		fallthrough
	default:
		p = m.proxy
	}

	return
}

type direct struct {
	dialer *net.Dialer
}

func (d *direct) Conn(s string) (net.Conn, error) {
	return d.dialer.Dial("tcp", s)
}

func (d *direct) PacketConn(string) (net.PacketConn, error) {
	return net.ListenPacket("udp", "")
}
