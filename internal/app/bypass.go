package app

import (
	"errors"
	"fmt"
	"net"
	"time"
)

//BypassManager .
type BypassManager struct {
	bypass bool

	lookup func(string) ([]net.IP, error)
	mapper func(string) (mark int, isIP bool)

	proxy       func(string) (net.Conn, error)
	proxyPacket func(string) (net.PacketConn, error)

	dialer      net.Dialer
	connManager *connManager
}

//NewBypassManager .
func NewBypassManager(bypass bool, mapper func(s string) (int, bool),
	lookup func(string) ([]net.IP, error)) (*BypassManager, error) {
	if mapper == nil {
		return nil, fmt.Errorf("mapper is nil")
	}

	if lookup == nil {
		lookup = net.LookupIP
	}

	m := &BypassManager{
		dialer: net.Dialer{Timeout: 11 * time.Second},
		lookup: lookup,
		proxy: func(host string) (conn net.Conn, err error) {
			return net.DialTimeout("tcp", host, 15*time.Second)
		},
		proxyPacket: func(s string) (net.PacketConn, error) {
			return net.ListenPacket("udp", "")
		},
		mapper:      mapper,
		connManager: newConnManager(),
		bypass:      bypass,
	}

	return m, nil
}

// https://myexternalip.com/raw
func (m *BypassManager) Forward(host string) (conn net.Conn, err error) {
	resp, err := m.marry(host)
	if err != nil {
		return nil, fmt.Errorf("map failed: %v", err)
	}
	switch {
	case resp.mark == direct && resp.isIP:
		conn, err = m.dialer.Dial("tcp", host)
	case resp.mark == direct && !resp.isIP:
		var ip []net.IP
		ip, err = m.lookup(resp.hostname)
		if err != nil {
			return nil, fmt.Errorf("dns resolve failed: %v", err)
		}
		for i := range ip {
			conn, err = m.dialer.Dial("tcp", net.JoinHostPort(ip[i].String(), resp.port))
			if err == nil {
				break
			}
		}
	default:
		conn, err = m.proxy(host)
	}

	return m.connManager.newConn(host, conn), err
}

func (m *BypassManager) ForwardPacket(host string) (conn net.PacketConn, err error) {
	resp, err := m.marry(host)
	if err != nil {
		return nil, fmt.Errorf("map failed: %v", err)
	}

	if resp.mark == direct {
		return net.ListenPacket("udp", "")
	}

	return m.proxyPacket(host)
}

//SetProxy .
func (m *BypassManager) SetProxy(conn func(string) (net.Conn, error),
	packetConn func(string) (net.PacketConn, error)) {
	if conn == nil {
		m.proxy = func(host string) (conn net.Conn, err error) {
			return net.DialTimeout("tcp", host, 15*time.Second)
		}
	} else {
		m.proxy = conn
	}

	if packetConn == nil {
		m.proxyPacket = func(s string) (net.PacketConn, error) {
			return net.ListenPacket("udp", "")
		}
	} else {
		m.proxyPacket = packetConn
	}
}

type getResp struct {
	hostname string
	port     string
	mark     int
	isIP     bool
}

func (m *BypassManager) marry(host string) (resp getResp, err error) {
	resp.hostname, resp.port, err = net.SplitHostPort(host)
	if err != nil {
		return getResp{}, fmt.Errorf("split host [%s] failed: %v", host, err)
	}

	if !m.bypass {
		resp.mark = proxy
		resp.isIP = net.ParseIP(resp.hostname) != nil
	} else {
		resp.mark, resp.isIP = m.mapper(resp.hostname)
	}

	switch resp.mark {
	case others:
		fmt.Printf("[%s] ->  mode: default(proxy)\n", host)
	case block:
		return getResp{}, errors.New("block " + resp.hostname)
	default:
		fmt.Printf("[%s] ->  mode: %s\n", host, modeMapping[resp.mark])
	}

	return
}

func (m *BypassManager) GetDownload() uint64 {
	return m.connManager.GetDownload()
}

func (m *BypassManager) GetUpload() uint64 {
	return m.connManager.GetUpload()
}
