package app

import (
	"fmt"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/internal/app/component"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

//BypassManager .
type BypassManager struct {
	dns         dns.DNS
	mapper      component.Mapper
	proxy       utils.Proxy
	dialer      net.Dialer
	connManager *connManager
}

//NewBypassManager .
func NewBypassManager(mapper component.Mapper, dns dns.DNS) (*BypassManager, error) {
	if mapper == nil {
		fmt.Println("checked mapper is nil, disable bypass.")
	}
	if dns == nil {
		fmt.Println("checked dns is nil")
	}

	m := &BypassManager{
		dialer:      net.Dialer{Timeout: 11 * time.Second},
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

	switch resp.Mark {
	case component.BLOCK:
		return nil, fmt.Errorf("block: %v", host)
	case component.DIRECT:
		if resp.IP == component.IP || m.dns == nil {
			conn, err = m.dialer.Dial("tcp", host)
			break
		}

		var ip []net.IP
		ip, err = m.dns.LookupIP(resp.Hostname)
		if err != nil {
			return nil, fmt.Errorf("dns resolve failed: %v", err)
		}

		for i := range ip {
			conn, err = m.dialer.Dial("tcp", net.JoinHostPort(ip[i].String(), resp.Port))
			if err == nil {
				break
			}
		}

	case component.OTHERS:
		fallthrough
	default:
		conn, err = m.proxy.Conn(host)
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
		conn, err = m.proxy.PacketConn(host)
	} else {
		conn, err = net.ListenPacket("udp", "")
	}

	return m.connManager.newPacketConn(host, conn), err
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
	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		return c, fmt.Errorf("split host [%s] failed: %v", host, err)
	}

	if m.mapper == nil {
		c.Mark = component.OTHERS
		if net.ParseIP(hostname) != nil {
			c.IP = component.IP
		} else {
			c.IP = component.DOMAIN
		}
	} else {
		c = m.mapper.Get(hostname)
	}

	c.Hostname = hostname
	c.Port = port
	fmt.Printf("[%s] ->  mode: %s\n", host, component.ModeMapping[c.Mark])
	return
}

func (m *BypassManager) GetDownload() uint64 {
	return m.connManager.GetDownload()
}

func (m *BypassManager) GetUpload() uint64 {
	return m.connManager.GetUpload()
}
