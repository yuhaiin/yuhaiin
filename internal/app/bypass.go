package app

import (
	"fmt"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils"

	"github.com/Asutorufa/yuhaiin/internal/app/component"
)

//BypassManager .
type BypassManager struct {
	lookup      func(string) ([]net.IP, error)
	mapper      component.Mapper
	proxy       utils.Proxy
	dialer      net.Dialer
	connManager *connManager
}

//NewBypassManager .
func NewBypassManager(mapper component.Mapper, lookup func(string) ([]net.IP, error)) (*BypassManager, error) {
	if mapper == nil {
		fmt.Println("checked mapper is nil, disable bypass.")
	}
	if lookup == nil {
		lookup = net.LookupIP
	}

	m := &BypassManager{
		dialer:      net.Dialer{Timeout: 11 * time.Second},
		lookup:      lookup,
		proxy:       &utils.DefaultProxy{},
		mapper:      mapper,
		connManager: newConnManager(),
	}
	return m, nil
}

//Conn get net.Conn by host
func (m *BypassManager) Conn(host string) (conn net.Conn, err error) {
	resp, err := m.marry(host)
	if err != nil {
		return nil, fmt.Errorf("map failed: %v", err)
	}

	if resp.Mark == component.BLOCK {
		return nil, fmt.Errorf("block: %v", err)
	}

	if resp.Mark == component.OTHERS {
		conn, err = m.proxy.Conn(host)
	}

	if resp.Mark == component.DIRECT {
		if resp.IP == component.IP {
			conn, err = m.dialer.Dial("tcp", host)
		}

		if resp.IP == component.DOMAIN {
			var ip []net.IP
			ip, err = m.lookup(resp.Hostname)
			if err != nil {
				return nil, fmt.Errorf("dns resolve failed: %v", err)
			}

			for i := range ip {
				conn, err = m.dialer.Dial("tcp", net.JoinHostPort(ip[i].String(), resp.Port))
				if err == nil {
					break
				}
			}
		}
	}

	return m.connManager.newConn(host, conn), err
}

func (m *BypassManager) PacketConn(host string) (conn net.PacketConn, err error) {
	resp, err := m.marry(host)
	if err != nil {
		return nil, fmt.Errorf("map failed: %v", err)
	}

	if resp.Mark == component.BLOCK {
		return nil, fmt.Errorf("block: %v", host)
	}

	if resp.Mark == component.OTHERS {
		return m.proxy.PacketConn(host)
	}

	return net.ListenPacket("udp", "")
}

//SetProxy .
func (m *BypassManager) SetProxy(p utils.Proxy) {
	if p == nil {
		m.proxy = &utils.DefaultProxy{}
	} else {
		fmt.Printf("set Proxy: %p\n", p)
		fmt.Printf("conn: %p\n", p.Conn)
		m.proxy = p
	}
}

func (m *BypassManager) marry(host string) (c component.MapperResp, err error) {
	c.Hostname, c.Port, err = net.SplitHostPort(host)
	if err != nil {
		return c, fmt.Errorf("split host [%s] failed: %v", host, err)
	}

	if m.mapper == nil {
		c.Mark = component.OTHERS
		if net.ParseIP(c.Hostname) != nil {
			c.IP = component.IP
		} else {
			c.IP = component.DOMAIN
		}
	} else {
		c = m.mapper.Get(c.Hostname)
	}

	fmt.Printf("[%s] ->  mode: %s\n", host, component.ModeMapping[c.Mark])

	return
}

func (m *BypassManager) GetDownload() uint64 {
	return m.connManager.GetDownload()
}

func (m *BypassManager) GetUpload() uint64 {
	return m.connManager.GetUpload()
}
