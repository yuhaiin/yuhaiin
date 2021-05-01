package app

import (
	"fmt"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/internal/app/component"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
)

//BypassManager .
type BypassManager struct {
	dns    dns.DNS
	mapper component.Mapper
	proxy  proxy.Proxy
	dialer net.Dialer
}

//NewBypassManager .
func NewBypassManager(mapper component.Mapper, dns dns.DNS, p proxy.Proxy) *BypassManager {
	if mapper == nil {
		fmt.Println("checked mapper is nil, disable bypass.")
	}
	if dns == nil {
		fmt.Println("checked dns is nil")
	}
	if p == nil {
		p = &proxy.DefaultProxy{}
	}

	m := &BypassManager{
		dialer: net.Dialer{Timeout: 11 * time.Second, Resolver: dns.Resolver()},
		proxy:  p,
		mapper: mapper,
		dns:    dns,
	}
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
	if m.mapper != nil {
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
	dialer net.Dialer
}

func (d *direct) Conn(s string) (net.Conn, error) {
	return d.dialer.Dial("tcp", s)
}

func (d *direct) PacketConn(string) (net.PacketConn, error) {
	return net.ListenPacket("udp", "")
}
